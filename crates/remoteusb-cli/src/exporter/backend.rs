//! Private inventory and on-demand native USB/IP imports.

use std::collections::BTreeSet;
use std::io::{self, Write};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio::time::Instant;

use super::platform;
use crate::inventory;

const IMPORT: [u8; 8] = [1, 0x11, 0x80, 3, 0, 0, 0, 0];
const DEVLIST: [u8; 8] = [1, 0x11, 0x80, 5, 0, 0, 0, 0];
const IMPORT_REJECTED: [u8; 8] = [1, 0x11, 0, 3, 0, 0, 0, 1];
const MAX_DEVICES: u32 = 1024;
const DEVICE_BYTES: usize = 312;

#[derive(Clone)]
struct Policy {
    allowed: Option<Arc<BTreeSet<String>>>,
    reserved: Arc<Mutex<BTreeSet<String>>>,
}

impl Policy {
    fn permits(&self, busid: &str) -> bool {
        self.allowed.as_ref().is_none_or(|ids| ids.contains(busid))
    }

    fn reserve(&self, busid: &str) -> io::Result<Reservation> {
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
            .insert(busid.to_owned())
        {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "device is already reserved",
            ));
        }
        Ok(Reservation {
            busid: busid.to_owned(),
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
            self.permits(&device.busid)
        });
        Ok(())
    }
}

struct Reservation {
    busid: String,
    reserved: Arc<Mutex<BTreeSet<String>>>,
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

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn busid(bytes: &[u8; 32]) -> io::Result<&str> {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| invalid("unterminated USB/IP BUSID"))?;
    if bytes[end..].iter().any(|byte| *byte != 0) {
        return Err(invalid("nonzero USB/IP BUSID padding"));
    }
    let id = std::str::from_utf8(&bytes[..end]).map_err(|_| invalid("invalid USB/IP BUSID"))?;
    inventory::validate_busid(id)?;
    Ok(id)
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

pub(super) async fn run(
    listener: TcpListener,
    backend: SocketAddr,
    allowed: Option<BTreeSet<String>>,
    shutdown: impl Future<Output = ()>,
    max_connections: usize,
    setup_timeout: Duration,
) -> io::Result<()> {
    if max_connections == 0 || setup_timeout.is_zero() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "managed backend requires positive limits",
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
    if let Some(ids) = &allowed {
        for id in ids {
            inventory::validate_busid(id)?;
        }
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
            connection = listener.accept(), if sessions.len() < max_connections => {
                match connection {
                    Ok((socket, _)) => {
                        let policy = policy.clone();
                        let stop = stopped.clone();
                        sessions.spawn(handle(socket, backend, policy, stop, setup_timeout));
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

async fn reject(socket: &mut TcpStream, deadline: Instant) {
    // A separate bounded write still permits negative proof after setup expired.
    let deadline = deadline.max(Instant::now() + Duration::from_secs(1));
    let _ = tokio::time::timeout_at(deadline, socket.write_all(&IMPORT_REJECTED)).await;
}

async fn handle(
    mut socket: TcpStream,
    backend: SocketAddr,
    policy: Policy,
    mut stop: watch::Receiver<bool>,
    setup_timeout: Duration,
) -> io::Result<()> {
    let deadline = Instant::now() + setup_timeout;
    let mut header = [0; 8];
    if setup(socket.read_exact(&mut header), deadline, &mut stop)
        .await
        .is_err()
    {
        return Ok(());
    }
    if header == IMPORT {
        // Import owns its cleanup result separately from session/network errors.
        return import(socket, backend, policy, stop, deadline).await;
    }
    let result = if header == inventory::REQUEST {
        setup(
            async {
                let mut devices = platform::inventory().await?;
                policy.filter(&mut devices)?;
                inventory::send(&mut socket, &devices).await
            },
            deadline,
            &mut stop,
        )
        .await
    } else if header == DEVLIST {
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
        if header[..4] == IMPORT[..4] {
            reject(&mut socket, deadline).await;
        }
        Err(invalid("unsupported managed USB/IP request"))
    };
    if let Err(error) = result {
        let _ = writeln!(io::stderr(), "managed USB/IP request failed: {error}");
    }
    Ok(())
}

async fn import(
    mut socket: TcpStream,
    backend: SocketAddr,
    policy: Policy,
    mut stop: watch::Receiver<bool>,
    deadline: Instant,
) -> io::Result<()> {
    let mut id = [0; 32];
    let reserved = setup(
        async {
            socket.read_exact(&mut id).await?;
            policy.reserve(busid(&id)?)
        },
        deadline,
        &mut stop,
    )
    .await;
    let reservation = match reserved {
        Ok(reservation) => reservation,
        Err(error) => {
            if !*stop.borrow() {
                reject(&mut socket, deadline).await;
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
        reject(&mut socket, deadline).await;
        return Ok(());
    }
    let mut socket = Some(socket);
    let (bound, cancelled) = settle_mutation(
        platform::bind(&reservation.busid),
        &mut socket,
        deadline,
        &mut stop,
    )
    .await;
    let lease = match bound {
        Ok(lease) => lease,
        Err(error) => {
            if !*stop.borrow()
                && let Some(socket) = &mut socket
            {
                reject(socket, deadline).await;
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
        Attachment::Reject(IMPORT_REJECTED, None)
    } else if let Some(socket) = &mut socket {
        attach(socket, backend, &id, deadline, &mut stop).await
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
            let deadline = deadline.max(Instant::now() + Duration::from_secs(1));
            let _ = tokio::time::timeout_at(deadline, socket.write_all(&header)).await;
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

struct ImportReply {
    upstream: TcpStream,
    bytes: [u8; 8 + DEVICE_BYTES],
    length: usize,
}

async fn native_import(backend: SocketAddr, id: &[u8; 32]) -> io::Result<ImportReply> {
    let mut upstream = TcpStream::connect(backend).await?;
    upstream.write_all(&IMPORT).await?;
    upstream.write_all(id).await?;
    let (bytes, length) = decode_import(&mut upstream, id).await?;
    Ok(ImportReply {
        upstream,
        bytes,
        length,
    })
}

async fn decode_import(
    reader: &mut (impl AsyncRead + Unpin),
    id: &[u8; 32],
) -> io::Result<([u8; 8 + DEVICE_BYTES], usize)> {
    let mut bytes = [0; 8 + DEVICE_BYTES];
    reader.read_exact(&mut bytes[..8]).await?;
    if bytes[..4] != [1, 0x11, 0, 3] {
        return Err(invalid("invalid native USB/IP import reply"));
    }
    let length = if bytes[4..8] == [0; 4] {
        reader.read_exact(&mut bytes[8..]).await?;
        let returned: &[u8; 32] = bytes[264..296].try_into().expect("32-byte native BUSID");
        if busid(returned)? != busid(id)? {
            return Err(invalid("native USB/IP imported a different BUSID"));
        }
        bytes.len()
    } else {
        // Forward the real backend's rejection without inventing descriptors.
        8
    };
    Ok((bytes, length))
}

enum Attachment {
    Reject([u8; 8], Option<io::Error>),
    Ended(io::Result<()>),
}

async fn attach(
    socket: &mut TcpStream,
    backend: SocketAddr,
    id: &[u8; 32],
    deadline: Instant,
    stop: &mut watch::Receiver<bool>,
) -> Attachment {
    let native = tokio::select! {
        biased;
        () = disconnected(socket) => return Attachment::Ended(Ok(())),
        result = setup(native_import(backend, id), deadline, stop) => result,
    };
    let mut reply = match native {
        Ok(reply) => reply,
        Err(error) => return Attachment::Reject(IMPORT_REJECTED, Some(error)),
    };
    if reply.length == 8 {
        return Attachment::Reject(reply.bytes[..8].try_into().expect("eight-byte reply"), None);
    }
    // Do not append a rejection after any success bytes have been offered.
    if let Err(error) = setup(socket.write_all(&reply.bytes), deadline, stop).await {
        return Attachment::Ended(Err(error));
    }
    Attachment::Ended(forward(socket, &mut reply.upstream, stop).await)
}

async fn forward(
    socket: &mut TcpStream,
    upstream: &mut TcpStream,
    stop: &mut watch::Receiver<bool>,
) -> io::Result<()> {
    let (mut downstream_read, mut downstream_write) = socket.split();
    let (mut upstream_read, mut upstream_write) = upstream.split();
    // A half-close ends the attachment, rather than waiting indefinitely for
    // the other direction. Each copy uses bounded storage and backpressure.
    tokio::select! {
        biased;
        () = stopped(stop) => Ok(()),
        result = relay(&mut downstream_read, &mut upstream_write) => result,
        result = relay(&mut upstream_read, &mut downstream_write) => result,
    }
}

async fn relay(
    reader: &mut (impl AsyncRead + Unpin),
    writer: &mut (impl AsyncWrite + Unpin),
) -> io::Result<()> {
    let mut buffer = [0; 4096];
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            return Ok(());
        }
        writer.write_all(&buffer[..read]).await?;
    }
}

async fn device_list(backend: SocketAddr, policy: &Policy) -> io::Result<Vec<u8>> {
    let mut upstream = TcpStream::connect(backend).await?;
    upstream.write_all(&DEVLIST).await?;
    decode_device_list(&mut upstream, policy).await
}

async fn decode_device_list(
    reader: &mut (impl AsyncRead + Unpin),
    policy: &Policy,
) -> io::Result<Vec<u8>> {
    let mut header = [0; 8];
    reader.read_exact(&mut header).await?;
    if header[..4] != [1, 0x11, 0, 5] {
        return Err(invalid("invalid native USB/IP device-list reply"));
    }
    if header[4..8] != [0; 4] {
        return Ok(header.to_vec());
    }
    let count = reader.read_u32().await?;
    if count > MAX_DEVICES {
        return Err(invalid("USB/IP device list exceeds 1024 devices"));
    }
    let mut reply = header.to_vec();
    reply.extend_from_slice(&[0; 4]);
    let mut selected = 0_u32;
    for _ in 0..count {
        let mut device = [0; DEVICE_BYTES];
        reader.read_exact(&mut device).await?;
        let id: &[u8; 32] = device[256..288].try_into().expect("32-byte native BUSID");
        let permitted = policy.permits(busid(id)?);
        let length = usize::from(device[311]) * 4;
        let mut interfaces = [0; 255 * 4];
        reader.read_exact(&mut interfaces[..length]).await?;
        if permitted {
            reply.extend_from_slice(&device);
            reply.extend_from_slice(&interfaces[..length]);
            selected += 1;
        }
    }
    reply[8..12].copy_from_slice(&selected.to_be_bytes());
    Ok(reply)
}

#[cfg(test)]
mod tests;
