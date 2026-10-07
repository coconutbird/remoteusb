//! The shared bounded forwarding engine. Endpoint roles differ only in how a
//! stream begins: exporters accept authenticated Groupnet streams and open the
//! loopback backend; receivers accept loopback sockets and open Groupnet streams.

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use groupnet::network::tunnel::TunneledStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio::time::Instant;
use tokio_util::compat::{Compat, FuturesAsyncReadCompatExt};

use crate::config::PeerConfig;
use crate::fabric::{Fabric, Link, closed, within};

/// Exchanged inside pinned TLS before any USB/IP byte. Version 3 follows
/// Groupnet's byte-credit tunnel format; earlier peers cannot interoperate.
pub const PREAMBLE: &[u8; 12] = b"REMOTEUSB\0\0\x03";

/// An authenticated end-to-end stream adapted to Tokio I/O.
type Secure = Compat<TunneledStream>;

/// How one endpoint role admits streams and completes its side of setup.
/// Roles are owned values; their setup futures run on spawned forwarding tasks.
pub(crate) trait Role: 'static {
    /// Accepted work owned by its forwarding task until setup completes.
    type Incoming: Send + 'static;

    /// Whether this role initiates streams and must first wait for a route.
    /// Exporters receive streams over an existing admitted session and must fence
    /// that generation at once: waiting for route recovery would adopt a
    /// replacement session's generation for a stream from the withdrawn one.
    const INITIATES: bool;

    /// Logs role-specific readiness once the fabric is up.
    fn announce(&self) -> io::Result<()> {
        Ok(())
    }

    /// Waits for the next candidate. `None` skips a rejected candidate.
    async fn accept(&self, link: &Link) -> io::Result<Option<Self::Incoming>>;

    /// Completes authentication-preamble and endpoint setup into a forwarding pair.
    fn open(
        link: &Link,
        incoming: Self::Incoming,
    ) -> impl Future<Output = io::Result<(Secure, TcpStream)>> + Send;
}

/// Forwards authenticated Groupnet streams to a concrete loopback backend.
pub(crate) struct Exporter {
    pub(crate) backend: SocketAddr,
}

/// An accepted Groupnet stream and the backend it will be joined to.
pub(crate) struct Inbound {
    stream: TunneledStream,
    backend: SocketAddr,
}

impl Role for Exporter {
    type Incoming = Inbound;
    const INITIATES: bool = false;

    async fn accept(&self, link: &Link) -> io::Result<Option<Inbound>> {
        let (peer, stream) = link.accept().await?;
        if &peer != link.peer() {
            eprintln!("USB/IP stream: unauthorized node ID");
            return Ok(None);
        }
        Ok(Some(Inbound {
            stream,
            backend: self.backend,
        }))
    }

    async fn open(_: &Link, inbound: Inbound) -> io::Result<(Secure, TcpStream)> {
        let mut secure = inbound.stream.compat();
        respond(&mut secure).await?;
        let socket = TcpStream::connect(inbound.backend).await?;
        socket.set_nodelay(true)?;
        Ok((secure, socket))
    }
}

/// Exposes a loopback listener; each local socket owns one Groupnet stream.
pub(crate) struct Receiver {
    listener: TcpListener,
}

impl Receiver {
    pub(crate) fn new(listener: TcpListener) -> Self {
        Self { listener }
    }
}

impl Role for Receiver {
    type Incoming = TcpStream;
    const INITIATES: bool = true;

    fn announce(&self) -> io::Result<()> {
        eprintln!("local USB/IP listener: {}", self.listener.local_addr()?);
        Ok(())
    }

    async fn accept(&self, _: &Link) -> io::Result<Option<TcpStream>> {
        self.listener.accept().await.map(|(socket, _)| Some(socket))
    }

    async fn open(link: &Link, socket: TcpStream) -> io::Result<(Secure, TcpStream)> {
        socket.set_nodelay(true)?;
        let mut secure = link.connect().await?.compat();
        initiate(&mut secure).await?;
        Ok((secure, socket))
    }
}

/// Receiver side of the protocol exchange, completed before any USB/IP byte.
async fn initiate(stream: &mut Secure) -> io::Result<()> {
    stream.write_all(PREAMBLE).await?;
    stream.flush().await?;
    expect_preamble(stream).await
}

/// Exporter side: the reply is sent only after the receiver proves the protocol.
async fn respond(stream: &mut Secure) -> io::Result<()> {
    expect_preamble(stream).await?;
    stream.write_all(PREAMBLE).await?;
    stream.flush().await
}

async fn expect_preamble(stream: &mut Secure) -> io::Result<()> {
    let mut received = [0; PREAMBLE.len()];
    stream.read_exact(&mut received).await?;
    if &received != PREAMBLE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "incompatible remoteusb protocol; update both endpoints",
        ));
    }
    Ok(())
}

/// Optional count of local forwarding tasks, reset to zero on every exit.
#[derive(Default)]
pub(crate) struct TaskStatus(Option<watch::Sender<usize>>);

impl TaskStatus {
    pub(crate) fn new(sender: watch::Sender<usize>) -> Self {
        let status = Self(Some(sender));
        status.update(0);
        status
    }

    fn update(&self, count: usize) {
        if let Some(status) = &self.0 {
            status.send_replace(count);
        }
    }
}

impl Drop for TaskStatus {
    fn drop(&mut self) {
        self.update(0);
    }
}

/// One stream: shared setup deadline, session-generation fence, then
/// bidirectional forwarding without an idle timeout.
async fn forward<R: Role>(link: Link, incoming: R::Incoming, setup: Duration) -> io::Result<()> {
    let deadline = Instant::now() + setup;
    if R::INITIATES {
        within(deadline, link.route_ready()).await?;
    }
    let fence = link.session_fence()?;
    tokio::select! {
        biased;
        () = fence => Err(closed()),
        result = async {
            let (mut secure, mut socket) = within(deadline, R::open(&link, incoming)).await?;
            link.log_stream();
            copy_bidirectional(&mut secure, &mut socket).await.map(drop)
        } => result,
    }
}

fn finished(result: Result<io::Result<()>, tokio::task::JoinError>) -> io::Result<()> {
    match result {
        Ok(Err(error)) => eprintln!("USB/IP stream: {error}"),
        Ok(Ok(())) => {}
        Err(error) => return Err(io::Error::other(error)),
    }
    Ok(())
}

/// Runs one role until shutdown or terminal fabric closure. Admission includes
/// streams still in setup; at capacity, candidates wait in their queues.
/// Individual stream failures are logged without payloads and never stop the
/// endpoint. Shutdown aborts and drains streams, which unplugs attached devices.
pub(crate) async fn serve<R: Role>(
    config: &PeerConfig,
    role: R,
    shutdown: impl Future<Output = ()>,
    status: TaskStatus,
) -> io::Result<()> {
    tokio::pin!(shutdown);
    let fabric = tokio::select! {
        biased;
        () = &mut shutdown => return Ok(()),
        result = Fabric::start(config) => result?,
    };
    if let Err(error) = role.announce() {
        fabric.close().await;
        return Err(error);
    }
    eprintln!(
        "Groupnet endpoint {} ready: peer {}",
        config.local_id, config.peer_id
    );
    let mut tasks = JoinSet::new();
    let result = loop {
        tokio::select! {
            biased;
            () = &mut shutdown => break Ok(()),
            () = fabric.closed() => break Err(closed()),
            Some(result) = tasks.join_next(), if !tasks.is_empty() => {
                status.update(tasks.len());
                if let Err(error) = finished(result) { break Err(error); }
            }
            accepted = role.accept(fabric.link()), if tasks.len() < config.limits.max_connections.get() => {
                match accepted {
                    Ok(Some(incoming)) => {
                        tasks.spawn(forward::<R>(fabric.link().clone(), incoming, config.limits.connect_timeout));
                        status.update(tasks.len());
                    }
                    Ok(None) => {}
                    Err(error) => break Err(error),
                }
            }
        }
    };
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    status.update(0);
    fabric.close().await;
    result
}
