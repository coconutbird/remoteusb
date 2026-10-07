use std::io;
use std::io::Write;
use std::net::SocketAddr;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{oneshot, watch};
use tokio::task::JoinHandle;

use crate::usbip::{self, OpHeader};

#[derive(Default)]
struct ReplyProof {
    offered: AtomicBool,
    rejected: AtomicBool,
}

const PROXY_TIMEOUT: Duration = Duration::from_secs(5);

/// Owns a private driver endpoint until its independent supervisor releases it.
/// Only the first accepted connection can ever reach the receiver's transport.
pub(super) struct Proxy {
    address: SocketAddr,
    stop: Option<oneshot::Sender<()>>,
    release: Option<oneshot::Sender<()>>,
    closed: watch::Receiver<bool>,
    task: JoinHandle<io::Result<()>>,
    reply_forwarded: Arc<ReplyProof>,
}

impl Proxy {
    pub(super) async fn start(upstream: SocketAddr) -> io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let (stop, stopped) = oneshot::channel();
        let (release, released) = oneshot::channel();
        let (closed, closure) = watch::channel(false);
        let reply_forwarded = Arc::new(ReplyProof::default());
        let observed_reply = Arc::clone(&reply_forwarded);
        let task = tokio::spawn(async move {
            let result = forward_once(&listener, upstream, stopped, &observed_reply).await;
            // All driver/upstream sockets have dropped before this notification.
            closed.send_replace(true);
            reject_until_released(&listener, released).await;
            result
        });
        Ok(Self {
            address,
            stop: Some(stop),
            release: Some(release),
            closed: closure,
            task,
            reply_forwarded,
        })
    }

    pub(super) fn address(&self) -> SocketAddr {
        self.address
    }

    pub(super) fn may_have_attached(&self) -> bool {
        self.reply_forwarded.offered.load(Ordering::Acquire)
            && !self.reply_forwarded.rejected.load(Ordering::Acquire)
    }

    pub(super) fn request_close(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }

    pub(super) async fn ended(&mut self) {
        while !*self.closed.borrow_and_update() {
            if self.closed.changed().await.is_err() {
                return;
            }
        }
    }

    pub(super) async fn close(&mut self) -> io::Result<()> {
        self.request_close();
        tokio::time::timeout(PROXY_TIMEOUT, self.ended())
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "owned driver connection closure timed out; endpoint remains reserved",
                )
            })?;
        if self.task.is_finished() {
            return Err(io::Error::other(
                "private endpoint reservation task unexpectedly ended; state indeterminate",
            ));
        }
        Ok(())
    }

    pub(super) async fn release(mut self) -> io::Result<()> {
        self.close().await?;
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
        tokio::time::timeout(PROXY_TIMEOUT, &mut self.task)
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "private endpoint reservation release timed out",
                )
            })?
            .map_err(io::Error::other)?
    }
}

async fn forward_once(
    listener: &TcpListener,
    upstream: SocketAddr,
    mut stopped: oneshot::Receiver<()>,
    reply_forwarded: &ReplyProof,
) -> io::Result<()> {
    let (mut driver, _) = tokio::select! {
        connection = listener.accept() => connection?,
        _ = &mut stopped => return Ok(()),
    };
    let mut transport = tokio::select! {
        connection = tokio::time::timeout(PROXY_TIMEOUT, TcpStream::connect(upstream)) => {
            connection.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "private proxy upstream connection timed out"))??
        },
        _ = &mut stopped => return Ok(()),
    };
    let (mut driver_read, mut driver_write) = driver.split();
    let (mut transport_read, mut transport_write) = transport.split();
    let outbound = tokio::io::copy(&mut driver_read, &mut transport_write);
    let inbound = forward_reply(&mut transport_read, &mut driver_write, reply_forwarded);
    tokio::pin!(outbound, inbound);
    loop {
        tokio::select! {
            result = &mut outbound => return result.map(|_| ()),
            result = &mut inbound => return result,
            _ = &mut stopped => return Ok(()),
            connection = listener.accept() => { drop(connection?.0); },
        }
    }
}

async fn forward_reply(
    reader: &mut (impl AsyncRead + Unpin),
    writer: &mut (impl AsyncWrite + Unpin),
    observed: &ReplyProof,
) -> io::Result<()> {
    let mut buffer = [0; 8192];
    let mut header = [0; usbip::HEADER_BYTES];
    let mut header_used = 0;
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            return Ok(());
        }
        if header_used < header.len() {
            if header_used == 0 {
                // Mark BEFORE offering bytes: partial writes remain conservative.
                observed.offered.store(true, Ordering::Release);
            }
            let count = read.min(header.len() - header_used);
            header[header_used..header_used + count].copy_from_slice(&buffer[..count]);
            header_used += count;
            if header_used == header.len()
                && OpHeader::parse(header).is_some_and(OpHeader::proves_rejected_import)
            {
                // A valid negative OP_REP_IMPORT proves rejection before device
                // creation. Mark before forwarding its decisive status bytes.
                observed.rejected.store(true, Ordering::Release);
            }
        }
        writer.write_all(&buffer[..read]).await?;
    }
}

async fn reject_until_released(listener: &TcpListener, mut released: oneshot::Receiver<()>) {
    loop {
        tokio::select! {
            _ = &mut released => return,
            connection = listener.accept() => match connection {
                Ok((connection, _)) => drop(connection),
                Err(error) => {
                    let _ = writeln!(io::stderr(), "USB/IP private endpoint accept failed; reservation retained: {error}");
                    tokio::time::sleep(Duration::from_millis(200)).await;
                },
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Proxy;
    use crate::usbip::{OpCode, OpHeader};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    #[tokio::test]
    async fn one_owned_socket_forwards_and_eof_closes_both_sides() {
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut proxy = Proxy::start(upstream.local_addr().unwrap()).await.unwrap();
        let mut driver = TcpStream::connect(proxy.address()).await.unwrap();
        let (mut receiver, _) = upstream.accept().await.unwrap();
        driver.write_all(b"owned connection").await.unwrap();
        let mut bytes = [0; 16];
        receiver.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"owned connection");
        assert!(!proxy.may_have_attached());
        receiver.write_all(b"reply").await.unwrap();
        let mut reply = [0; 5];
        driver.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"reply");
        assert!(proxy.may_have_attached());
        let mut concurrent = TcpStream::connect(proxy.address()).await.unwrap();
        assert_eq!(concurrent.read(&mut bytes).await.unwrap(), 0);
        assert!(
            tokio::time::timeout(Duration::from_millis(5), upstream.accept())
                .await
                .is_err()
        );
        proxy.close().await.unwrap();
        assert_eq!(driver.read(&mut bytes).await.unwrap(), 0);
        assert_eq!(receiver.read(&mut bytes).await.unwrap(), 0);
        assert!(TcpListener::bind(proxy.address()).await.is_err());
        let mut retry = TcpStream::connect(proxy.address()).await.unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), retry.read(&mut bytes))
                .await
                .unwrap()
                .unwrap(),
            0
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(5), upstream.accept())
                .await
                .is_err()
        );
        proxy.release().await.unwrap();
    }

    #[tokio::test]
    async fn upstream_eof_ends_owned_connection_without_allowing_reconnect() {
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut proxy = Proxy::start(upstream.local_addr().unwrap()).await.unwrap();
        let mut driver = TcpStream::connect(proxy.address()).await.unwrap();
        let (receiver, _) = upstream.accept().await.unwrap();
        drop(receiver);
        let mut byte = [0];
        assert_eq!(driver.read(&mut byte).await.unwrap(), 0);
        drop(driver);
        tokio::time::timeout(Duration::from_secs(1), proxy.ended())
            .await
            .unwrap();
        assert!(!proxy.may_have_attached());
        let mut retry = TcpStream::connect(proxy.address()).await.unwrap();
        assert_eq!(retry.read(&mut byte).await.unwrap(), 0);
        assert!(
            tokio::time::timeout(Duration::from_millis(5), upstream.accept())
                .await
                .is_err()
        );
        proxy.release().await.unwrap();
    }

    #[tokio::test]
    async fn fragmented_negative_import_preserves_rejection_proof() {
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut proxy = Proxy::start(upstream.local_addr().unwrap()).await.unwrap();
        let mut driver = TcpStream::connect(proxy.address()).await.unwrap();
        let (mut receiver, _) = upstream.accept().await.unwrap();
        let rejection = OpHeader::new(OpCode::RepImport, 4).encode();
        receiver.write_all(&rejection[..3]).await.unwrap();
        let mut first = [0; 3];
        driver.read_exact(&mut first).await.unwrap();
        assert!(proxy.may_have_attached());
        receiver.write_all(&rejection[3..]).await.unwrap();
        let mut rest = [0; 5];
        driver.read_exact(&mut rest).await.unwrap();
        assert!(!proxy.may_have_attached());
        proxy.close().await.unwrap();
        proxy.release().await.unwrap();
    }
}
