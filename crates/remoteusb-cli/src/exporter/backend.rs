//! Private inventory and on-demand native USB/IP imports.

use std::collections::BTreeSet;
use std::io::{self, Write};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use remoteusb_transport::QueueCapacity;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio::time::Instant;

use super::platform::{DeviceHost, Lease as _};
use crate::usbip::{self, BusId, DeviceRecord, OpCode, OpHeader};
use crate::{invalid_data, inventory};

const MAX_DEVICES: u32 = 1024;

#[derive(Clone)]
struct Policy {
    allowed: Option<Arc<BTreeSet<BusId>>>,
    reserved: Arc<Mutex<BTreeSet<BusId>>>,
}

impl Policy {
    fn permits(&self, busid: BusId) -> bool {
        self.allowed.as_ref().is_none_or(|ids| ids.contains(&busid))
    }

    fn reserve(&self, busid: BusId) -> io::Result<Reservation> {
        if !self.permits(busid) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "device is not allowed",
            ));
        }
        if !self
            .reserved
            .lock()
            .map_err(|_| io::Error::other("device reservation lock poisoned"))?
            .insert(busid)
        {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "device is already reserved",
            ));
        }
        Ok(Reservation {
            busid,
            reserved: Arc::clone(&self.reserved),
            release: true,
        })
    }

    fn filter(&self, devices: &mut Vec<inventory::Device>) -> io::Result<()> {
        let reserved = self
            .reserved
            .lock()
            .map_err(|_| io::Error::other("device reservation lock poisoned"))?;
        devices.retain_mut(|device| {
            device.busy |= reserved.contains(&device.busid);
            self.permits(device.busid)
        });
        Ok(())
    }
}

struct Reservation {
    busid: BusId,
    reserved: Arc<Mutex<BTreeSet<BusId>>>,
    release: bool,
}

impl Reservation {
    fn preserve(mut self) {
        self.release = false;
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        // A poisoned policy cannot admit another session, so preserving the
        // reservation in that case is safer than reopening an uncertain device.
        if self.release
            && let Ok(mut reserved) = self.reserved.lock()
        {
            reserved.remove(&self.busid);
        }
    }
}

async fn stopped(receiver: &mut watch::Receiver<bool>) {
    while !*receiver.borrow_and_update() {
        if receiver.changed().await.is_err() {
            return;
        }
    }
}

async fn setup<T>(
    operation: impl Future<Output = io::Result<T>>,
    deadline: Instant,
    stop: &mut watch::Receiver<bool>,
) -> io::Result<T> {
    tokio::select! {
        biased;
        () = stopped(stop) => Err(io::Error::new(io::ErrorKind::Interrupted, "managed exporter is stopping")),
        result = tokio::time::timeout_at(deadline, operation) => result
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "managed USB/IP setup timed out"))?,
    }
}

/// Observe EOF without consuming pipelined USB data. If data is already queued,
/// normal forwarding observes its eventual EOF after the bounded bind finishes.
async fn disconnected(socket: &TcpStream) {
    let mut byte = [0; 1];
    if matches!(socket.peek(&mut byte).await, Ok(0) | Err(_)) {
        return;
    }
    std::future::pending::<()>().await;
}

/// Never cancel a driver mutation. Shutdown/EOF close the socket immediately;
/// a deadline retains it solely to offer negative proof after reconciliation.
async fn settle_mutation<T, E>(
    operation: impl Future<Output = Result<T, E>>,
    socket: &mut Option<TcpStream>,
    deadline: Instant,
    stop: &mut watch::Receiver<bool>,
) -> (Result<T, E>, bool) {
    tokio::pin!(operation);
    let timed_out = if let Some(connection) = socket.as_ref() {
        tokio::select! {
            biased;
            () = stopped(stop) => false,
            () = disconnected(connection) => false,
            () = tokio::time::sleep_until(deadline) => true,
            result = &mut operation => return (result, false),
        }
    } else {
        false
    };
    if !timed_out {
        drop(socket.take());
    }
    (finish_mutation(operation, socket, stop).await, true)
}

async fn finish_mutation<T>(
    operation: impl Future<Output = T>,
    socket: &mut Option<TcpStream>,
    stop: &mut watch::Receiver<bool>,
) -> T {
    tokio::pin!(operation);
    tokio::select! {
        biased;
        () = stopped(stop) => {
            drop(socket.take());
            operation.await
        },
        result = &mut operation => result,
    }
}

pub(super) async fn run<H: DeviceHost>(
    host: H,
    listener: TcpListener,
    backend: SocketAddr,
    allowed: Option<BTreeSet<BusId>>,
    shutdown: impl Future<Output = ()>,
    max_connections: QueueCapacity,
    setup_timeout: Duration,
) -> io::Result<()> {
    if setup_timeout.is_zero() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "managed backend requires a positive setup timeout",
        ));
    }
    if !listener.local_addr()?.ip().is_loopback()
        || !backend.ip().is_loopback()
        || backend.port() == 0
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "managed backend endpoints must be loopback with a nonzero backend port",
        ));
    }
    let policy = Policy {
        allowed: allowed.map(Arc::new),
        reserved: Arc::default(),
    };
    let (stop, stopped) = watch::channel(false);
    let mut sessions = JoinSet::new();
    let mut failure = None;
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            biased;
            () = &mut shutdown => break,
            result = sessions.join_next(), if !sessions.is_empty() => {
                if let Some(error) = session_failure(result) {
                    failure = Some(error);
                    break;
                }
            },
            connection = listener.accept(), if sessions.len() < max_connections.get() => {
                match connection {
                    Ok((socket, _)) => {
                        let host = host.clone();
                        let policy = policy.clone();
                        let stop = stopped.clone();
                        sessions.spawn(handle(host, socket, backend, policy, stop, setup_timeout));
                    },
                    Err(error) => { failure = Some(error); break; },
                }
            },
        }
    }
    drop(listener);
    stop.send_replace(true);
    // Never abort these tasks: they own in-flight mutations and driver leases.
    while let Some(result) = sessions.join_next().await {
        if let Some(error) = session_failure(Some(result)) {
            if failure.is_none() {
                failure = Some(error);
            } else {
                let _ = writeln!(
                    io::stderr(),
                    "additional managed exporter cleanup failure: {error}"
                );
            }
        }
    }
    failure.map_or(Ok(()), Err)
}

fn session_failure(
    result: Option<Result<io::Result<()>, tokio::task::JoinError>>,
) -> Option<io::Error> {
    match result {
        Some(Ok(Err(error))) => Some(error),
        Some(Err(error)) => Some(io::Error::other(error)),
        _ => None,
    }
}

/// A separate bounded write still permits negative proof after setup expired.
async fn reject(socket: &mut TcpStream, header: OpHeader, deadline: Instant) {
    let deadline = deadline.max(Instant::now() + Duration::from_secs(1));
    let _ = tokio::time::timeout_at(deadline, socket.write_all(&header.encode())).await;
}

async fn handle<H: DeviceHost>(
    host: H,
    mut socket: TcpStream,
    backend: SocketAddr,
    policy: Policy,
    mut stop: watch::Receiver<bool>,
    setup_timeout: Duration,
) -> io::Result<()> {
    let deadline = Instant::now() + setup_timeout;
    let mut header = [0; usbip::HEADER_BYTES];
    if setup(socket.read_exact(&mut header), deadline, &mut stop)
        .await
        .is_err()
    {
        return Ok(());
    }
    let request = OpHeader::parse(header);
    if request == Some(OpHeader::IMPORT_REQUEST) {
        // Import owns its cleanup result separately from session/network errors.
        return import(&host, socket, backend, policy, stop, deadline).await;
    }
    let result = if header == inventory::REQUEST {
        setup(
            async {
                let mut devices = host.inventory().await?;
                policy.filter(&mut devices)?;
                inventory::send(&mut socket, &devices).await
            },
            deadline,
            &mut stop,
        )
        .await
    } else if request == Some(OpHeader::DEVLIST_REQUEST) {
        setup(
            async {
                let reply = device_list(backend, &policy).await?;
                socket.write_all(&reply).await
            },
            deadline,
            &mut stop,
        )
        .await
    } else {
        if request.is_some_and(|request| request.code == OpCode::ReqImport) {
            reject(&mut socket, OpHeader::IMPORT_REJECTED, deadline).await;
        }
        Err(invalid_data("unsupported managed USB/IP request"))
    };
    if let Err(error) = result {
        let _ = writeln!(io::stderr(), "managed USB/IP request failed: {error}");
    }
    Ok(())
}

async fn import<H: DeviceHost>(
    host: &H,
    mut socket: TcpStream,
    backend: SocketAddr,
    policy: Policy,
    mut stop: watch::Receiver<bool>,
    deadline: Instant,
) -> io::Result<()> {
    let mut field = [0; usbip::BUSID_BYTES];
    let reserved = setup(
        async {
            socket.read_exact(&mut field).await?;
            policy.reserve(BusId::decode(&field)?)
        },
        deadline,
        &mut stop,
    )
    .await;
    let reservation = match reserved {
        Ok(reservation) => reservation,
        Err(error) => {
            if !*stop.borrow() {
                reject(&mut socket, OpHeader::IMPORT_REJECTED, deadline).await;
            }
            let _ = writeln!(io::stderr(), "managed USB/IP import rejected: {error}");
            return Ok(());
        }
    };
    // Do not initiate new driver work after setup already expired or shutdown
    // was observed. Once bind is initiated, it must always be reconciled.
    if *stop.borrow() {
        return Ok(());
    }
    if Instant::now() >= deadline {
        reject(&mut socket, OpHeader::IMPORT_REJECTED, deadline).await;
        return Ok(());
    }
    let busid = reservation.busid;
    let mut socket = Some(socket);
    let (bound, cancelled) =
        settle_mutation(host.bind(busid), &mut socket, deadline, &mut stop).await;
    let lease = match bound {
        Ok(lease) => lease,
        Err(error) => {
            if !*stop.borrow()
                && let Some(socket) = &mut socket
            {
                reject(socket, OpHeader::IMPORT_REJECTED, deadline).await;
            }
            if error.cleanup_failed {
                reservation.preserve();
                return Err(io::Error::other(format!(
                    "device binding cleanup failed: {}",
                    error.error
                )));
            }
            let _ = writeln!(
                io::stderr(),
                "managed USB/IP binding rejected: {}",
                error.error
            );
            return Ok(());
        }
    };
    let outcome = if cancelled {
        Attachment::Reject(OpHeader::IMPORT_REJECTED, None)
    } else if let Some(socket) = &mut socket {
        attach(socket, backend, busid, deadline, &mut stop).await
    } else {
        Attachment::Ended(Err(io::Error::other(
            "managed import lost its owned socket",
        )))
    };
    // All native sockets are closed by attach. Successful/partial attachments
    // also close the client before restore; rejected management sockets remain
    // only to send negative proof after the driver mutation is reconciled.
    if matches!(&outcome, Attachment::Ended(_)) {
        drop(socket.take());
    }
    let restored = finish_mutation(lease.restore(), &mut socket, &mut stop).await;
    if let Attachment::Reject(header, error) = outcome {
        if let Some(socket) = &mut socket
            && !*stop.borrow()
        {
            reject(socket, header, deadline).await;
        }
        if let Some(error) = error {
            let _ = writeln!(io::stderr(), "managed USB/IP import rejected: {error}");
        }
    } else if let Attachment::Ended(Err(error)) = outcome {
        let _ = writeln!(io::stderr(), "managed USB/IP import ended: {error}");
    }
    drop(socket);
    if restored.is_err() {
        reservation.preserve();
    } else {
        drop(reservation);
    }
    restored
        .map_err(|error| io::Error::other(format!("device sharing restoration failed: {error}")))
}

/// A native `OP_REP_IMPORT`: the success header and device record to forward
/// verbatim, or the backend's own rejection header.
type ImportReply = Result<[u8; usbip::IMPORT_REPLY_BYTES], OpHeader>;

async fn native_import(backend: SocketAddr, busid: BusId) -> io::Result<(TcpStream, ImportReply)> {
    let mut upstream = TcpStream::connect(backend).await?;
    upstream
        .write_all(&OpHeader::IMPORT_REQUEST.encode())
        .await?;
    upstream.write_all(busid.field()).await?;
    let reply = decode_import(&mut upstream, busid).await?;
    Ok((upstream, reply))
}

async fn decode_import(
    reader: &mut (impl AsyncRead + Unpin),
    busid: BusId,
) -> io::Result<ImportReply> {
    let mut header = [0; usbip::HEADER_BYTES];
    reader.read_exact(&mut header).await?;
    let reply = OpHeader::parse(header)
        .filter(|reply| reply.code == OpCode::RepImport)
        .ok_or_else(|| invalid_data("invalid native USB/IP import reply"))?;
    if reply.status != usbip::ST_OK {
        // Forward the real backend's rejection without inventing descriptors.
        return Ok(Err(reply));
    }
    let mut bytes = [0; usbip::IMPORT_REPLY_BYTES];
    let (prefix, record) = bytes
        .split_last_chunk_mut::<{ usbip::DEVICE_BYTES }>()
        .expect("an import reply is one header and one device record");
    prefix.copy_from_slice(&header);
    reader.read_exact(record).await?;
    if DeviceRecord::new(record).busid()? != busid {
        return Err(invalid_data("native USB/IP imported a different BUSID"));
    }
    Ok(Ok(bytes))
}

enum Attachment {
    Reject(OpHeader, Option<io::Error>),
    Ended(io::Result<()>),
}

async fn attach(
    socket: &mut TcpStream,
    backend: SocketAddr,
    busid: BusId,
    deadline: Instant,
    stop: &mut watch::Receiver<bool>,
) -> Attachment {
    let native = tokio::select! {
        biased;
        () = disconnected(socket) => return Attachment::Ended(Ok(())),
        result = setup(native_import(backend, busid), deadline, stop) => result,
    };
    let (mut upstream, reply) = match native {
        Ok(native) => native,
        Err(error) => return Attachment::Reject(OpHeader::IMPORT_REJECTED, Some(error)),
    };
    let reply = match reply {
        Ok(reply) => reply,
        Err(rejection) => return Attachment::Reject(rejection, None),
    };
    // Do not append a rejection after any success bytes have been offered.
    if let Err(error) = setup(socket.write_all(&reply), deadline, stop).await {
        return Attachment::Ended(Err(error));
    }
    Attachment::Ended(forward(socket, &mut upstream, stop).await)
}

async fn forward(
    socket: &mut TcpStream,
    upstream: &mut TcpStream,
    stop: &mut watch::Receiver<bool>,
) -> io::Result<()> {
    let (mut downstream_read, mut downstream_write) = socket.split();
    let (mut upstream_read, mut upstream_write) = upstream.split();
    // A half-close ends the attachment, rather than waiting indefinitely for
    // the other direction. Each copy uses a bounded buffer and backpressure,
    // and returns at EOF without shutting down its writer.
    tokio::select! {
        biased;
        () = stopped(stop) => Ok(()),
        result = tokio::io::copy(&mut downstream_read, &mut upstream_write) => result.map(|_| ()),
        result = tokio::io::copy(&mut upstream_read, &mut downstream_write) => result.map(|_| ()),
    }
}

async fn device_list(backend: SocketAddr, policy: &Policy) -> io::Result<Vec<u8>> {
    let mut upstream = TcpStream::connect(backend).await?;
    upstream
        .write_all(&OpHeader::DEVLIST_REQUEST.encode())
        .await?;
    decode_device_list(&mut upstream, policy).await
}

async fn decode_device_list(
    reader: &mut (impl AsyncRead + Unpin),
    policy: &Policy,
) -> io::Result<Vec<u8>> {
    let mut header = [0; usbip::HEADER_BYTES];
    reader.read_exact(&mut header).await?;
    let status = OpHeader::parse(header)
        .filter(|reply| reply.code == OpCode::RepDevlist)
        .ok_or_else(|| invalid_data("invalid native USB/IP device-list reply"))?
        .status;
    if status != usbip::ST_OK {
        return Ok(header.to_vec());
    }
    let count = reader.read_u32().await?;
    if count > MAX_DEVICES {
        return Err(invalid_data("USB/IP device list exceeds 1024 devices"));
    }
    let mut reply = header.to_vec();
    reply.extend_from_slice(&[0; 4]);
    let mut selected = 0_u32;
    for _ in 0..count {
        let mut device = [0; usbip::DEVICE_BYTES];
        reader.read_exact(&mut device).await?;
        let record = DeviceRecord::new(&device);
        let permitted = policy.permits(record.busid()?);
        let length = record.interface_bytes();
        let mut interfaces = [0; usbip::MAX_INTERFACE_BYTES];
        reader.read_exact(&mut interfaces[..length]).await?;
        if permitted {
            reply.extend_from_slice(&device);
            reply.extend_from_slice(&interfaces[..length]);
            selected += 1;
        }
    }
    // The device count follows the header.
    reply[usbip::HEADER_BYTES..usbip::HEADER_BYTES + 4].copy_from_slice(&selected.to_be_bytes());
    Ok(reply)
}

#[cfg(test)]
mod tests;
