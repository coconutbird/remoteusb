//! USB/IP byte forwarding over pinned, mutually authenticated Groupnet ordered streams.
//!
//! Keyed rendezvous admits only the configured node IDs. Independently provisioned
//! CA roots and exact peer leaf pins authenticate the end-to-end stream; a fixed
//! remoteusb protocol exchange completes before an exporter opens its backend.
//! Each local TCP connection owns one stream, without payload inspection or reconnect.

use std::fs::File;
use std::io::{self, BufReader};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use groupnet::connectivity::{NetworkKey, PathPolicy, TcpPunchConfig, TcpRendezvous};
use groupnet::core::NodeId;
use groupnet::network::TunnelConfig;
use groupnet::network::tunnel::{PeerIdentity, TlsIdentity, TunnelLimits, TunneledStream};
use groupnet::runtime::{Node, Ordered};
use groupnet::transport::tcp::TcpMsgTransport;
use rustls::pki_types::CertificateDer;
use tokio::io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;
use tokio::time::{sleep, timeout};
use tokio_util::compat::FuturesAsyncReadCompatExt;

const PREAMBLE: &[u8; 12] = b"REMOTEUSB\0\0\x01";
const POLL: Duration = Duration::from_millis(25);

/// Bounds concurrent sessions and connection establishment, never idle USB devices.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum connection tasks and node-wide/per-peer sessions, including setup.
    pub max_connections: usize,
    /// Deadline for fabric admission and each stream's complete setup exchange.
    pub connect_timeout: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_connections: 64,
            connect_timeout: Duration::from_secs(10),
        }
    }
}

/// One endpoint's independently provisioned identity, admission and routing settings.
#[derive(Clone, Debug)]
pub struct PeerConfig {
    /// This endpoint's routing alias (1–64 UTF-8 bytes).
    pub local_id: String,
    /// The only authorized remote routing alias, distinct from `local_id`.
    pub peer_id: String,
    /// Concrete keyed TCP rendezvous address.
    pub rendezvous: SocketAddr,
    /// PEM trust-root certificates.
    pub ca: PathBuf,
    /// PEM local leaf certificate followed by any intermediate certificates.
    pub cert: PathBuf,
    /// PEM local private key.
    pub key: PathBuf,
    /// PEM authorized remote leaf certificate (exact certificate pin).
    pub peer_cert: PathBuf,
    /// File containing the shared 32-byte network key as 64 hexadecimal digits.
    pub network_key: PathBuf,
    /// Reusable TCP candidate binds; the first is the registration/source bind.
    /// At most four binds are supported; unspecified addresses and ephemeral ports
    /// are permitted. The first bind must match the rendezvous address family.
    pub candidate_binds: Vec<SocketAddr>,
    /// Diagnostic/privacy policy disabling direct traversal in favor of relay.
    pub relay_only: bool,
    /// Bounded setup and concurrent session policy.
    pub limits: Limits,
}

impl PeerConfig {
    fn validate(&self) -> io::Result<()> {
        validate_ids(&[self.local_id.as_str(), self.peer_id.as_str()])?;
        if self.limits.max_connections == 0
            || self.limits.max_connections > tokio::sync::Semaphore::MAX_PERMITS
            || self.limits.connect_timeout.is_zero()
            || tokio::time::Instant::now()
                .checked_add(self.limits.connect_timeout)
                .is_none()
        {
            return Err(invalid_input(
                "invalid connection capacity or setup timeout",
            ));
        }
        if self.rendezvous.port() == 0
            || self.rendezvous.ip().is_unspecified()
            || invalid_ip(self.rendezvous.ip())
            || self.candidate_binds.is_empty()
            || self.candidate_binds.len() > 4
            || self.candidate_binds[0].is_ipv4() != self.rendezvous.is_ipv4()
            || self
                .candidate_binds
                .iter()
                .any(|bind| invalid_ip(bind.ip()))
        {
            return Err(invalid_input(
                "invalid rendezvous or candidate bind addresses",
            ));
        }
        Ok(())
    }

    fn tunnels(&self) -> io::Result<TunnelConfig> {
        let identity = TlsIdentity::from_der(
            certificates(&self.ca)?
                .into_iter()
                .map(|der| der.to_vec())
                .collect(),
            certificates(&self.cert)?
                .into_iter()
                .map(|der| der.to_vec())
                .collect(),
            rustls_pemfile::private_key(&mut BufReader::new(File::open(&self.key)?))?
                .ok_or_else(|| invalid_input("PEM file contains no private key"))?
                .secret_der()
                .to_vec(),
        )?;
        let peer = certificates(&self.peer_cert)?;
        let limits = TunnelLimits {
            max_peers: 1,
            max_sessions: self.limits.max_connections,
            sessions_per_peer: self.limits.max_connections,
            accept_queue: self.limits.max_connections,
            setup_timeout: self.limits.connect_timeout,
            ..TunnelLimits::default()
        };
        limits.validate()?;
        Ok(TunnelConfig::new(
            identity,
            [PeerIdentity::new(
                NodeId::new(self.peer_id.as_str()),
                peer[0].as_ref(),
            )?],
        )
        .with_limits(limits))
    }
}

fn certificates(path: &Path) -> io::Result<Vec<CertificateDer<'static>>> {
    let certificates = rustls_pemfile::certs(&mut BufReader::new(File::open(path)?))
        .collect::<io::Result<Vec<_>>>()?;
    if certificates.is_empty() {
        return Err(invalid_input("PEM file contains no certificates"));
    }
    Ok(certificates)
}

fn validate_ids(ids: &[&str]) -> io::Result<()> {
    if ids.is_empty()
        || ids.len() > 255
        || ids
            .iter()
            .enumerate()
            .any(|(index, id)| id.is_empty() || id.len() > 64 || ids[..index].contains(id))
    {
        return Err(invalid_input(
            "node IDs must be distinct and contain 1–64 UTF-8 bytes",
        ));
    }
    Ok(())
}

fn network_key(path: &Path) -> io::Result<NetworkKey> {
    let text = std::fs::read_to_string(path)?;
    let digits: Vec<_> = text
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();
    if digits.len() != 64 {
        return Err(invalid_input(
            "network key must contain exactly 64 hexadecimal digits",
        ));
    }
    let mut key = [0; 32];
    for (destination, pair) in key.iter_mut().zip(digits.as_chunks::<2>().0) {
        let high = char::from(pair[0]).to_digit(16);
        let low = char::from(pair[1]).to_digit(16);
        let (Some(high), Some(low)) = (high, low) else {
            return Err(invalid_input("network key contains non-hexadecimal digits"));
        };
        *destination = u8::try_from(high * 16 + low).map_err(invalid_input)?;
    }
    Ok(NetworkKey::from_bytes(key))
}

fn invalid_ip(ip: IpAddr) -> bool {
    ip.is_multicast() || matches!(ip, IpAddr::V4(address) if address.is_broadcast())
}

fn invalid_input(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, error.to_string())
}

fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::NotConnected, "Groupnet fabric closed")
}

async fn establish<T>(
    duration: Duration,
    operation: impl Future<Output = io::Result<T>>,
) -> io::Result<T> {
    timeout(duration, operation).await.map_err(|_| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "connection establishment timed out",
        )
    })?
}

struct Fabric {
    node: Node,
    tcp: TcpMsgTransport,
    peer: NodeId,
}

impl Fabric {
    async fn start(config: &PeerConfig) -> io::Result<Self> {
        // Load and validate every credential before binding or connecting sockets.
        let tunnels = config.tunnels()?;
        let peer = NodeId::new(config.peer_id.as_str());
        let mut punch = TcpPunchConfig::new(
            NodeId::new(config.local_id.as_str()),
            config.rendezvous,
            network_key(&config.network_key)?,
            vec![peer.clone()],
        );
        punch.bind = config.candidate_binds[0];
        punch.candidate_binds = config.candidate_binds[1..].to_vec();
        punch.max_peers = 1;
        punch.policy = if config.relay_only {
            PathPolicy::RelayOnly
        } else {
            PathPolicy::DirectPreferred
        };
        let tcp = establish(
            config.limits.connect_timeout,
            TcpMsgTransport::bind_connectivity(punch),
        )
        .await?;
        let result = establish(
            config.limits.connect_timeout,
            Node::builder(NodeId::new(config.local_id.as_str()))
                .link(tcp.clone().into_bound_link(1))
                .gossip_interval_ms(50)
                .tunnels(tunnels)
                .start(),
        )
        .await;
        match result {
            Ok(node) => {
                let addresses = match tcp.local_addrs() {
                    Ok(addresses) => addresses,
                    Err(error) => {
                        node.close().await;
                        tcp.close().await;
                        return Err(error);
                    }
                };
                eprintln!(
                    "Groupnet node {}: rendezvous {}, candidate listeners {addresses:?}",
                    config.local_id, config.rendezvous
                );
                Ok(Self { node, tcp, peer })
            }
            Err(error) => {
                tcp.close().await;
                Err(error)
            }
        }
    }

    async fn closed(&self) {
        loop {
            tokio::select! {
                () = self.node.router().cancelled() => return,
                () = sleep(POLL) => {
                    if self.tcp.local_addrs().is_err() {
                        return;
                    }
                }
            }
        }
    }

    async fn close(&self) {
        self.node.close().await;
        self.tcp.close().await;
    }
}

async fn preamble(
    stream: &mut tokio_util::compat::Compat<TunneledStream>,
    client: bool,
) -> io::Result<()> {
    if client {
        stream.write_all(PREAMBLE).await?;
        stream.flush().await?;
    }
    let mut received = [0; PREAMBLE.len()];
    stream.read_exact(&mut received).await?;
    if &received != PREAMBLE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "incompatible remoteusb protocol",
        ));
    }
    if !client {
        stream.write_all(PREAMBLE).await?;
        stream.flush().await?;
    }
    Ok(())
}

fn finished(result: Result<io::Result<()>, tokio::task::JoinError>) -> io::Result<()> {
    match result {
        Ok(Err(error)) => eprintln!("USB/IP stream: {error}"),
        Ok(Ok(())) => {}
        Err(error) => return Err(io::Error::other(error)),
    }
    Ok(())
}

async fn drain(tasks: &mut JoinSet<io::Result<()>>) {
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
}

/// Forwards authorized Groupnet ordered streams to a loopback USB/IP backend.
///
/// TLS CA authentication, exact peer pin, authorized node ID and the remoteusb
/// preamble/reply complete before opening the backend. Admission includes setup
/// and queued streams. Individual session failures do not stop the daemon.
/// Shutdown aborts/drains streams and closes the node and connectivity endpoint;
/// this disconnects devices, and is not a graceful filesystem unmount.
///
/// # Errors
/// Returns invalid credentials/settings, a non-loopback backend, fabric admission
/// or terminal closure errors, or a panicked forwarding task. No idle timeout or
/// automatic stream reconnect is applied.
pub async fn run_server(
    config: PeerConfig,
    backend: SocketAddr,
    shutdown: impl Future<Output = ()>,
) -> io::Result<()> {
    config.validate()?;
    if !backend.ip().is_loopback() || backend.port() == 0 {
        return Err(invalid_input(
            "USB/IP backend must be a concrete loopback address",
        ));
    }
    tokio::pin!(shutdown);
    let fabric = tokio::select! {
        biased;
        () = &mut shutdown => return Ok(()),
        result = Fabric::start(&config) => result?,
    };
    let endpoint = match fabric.node.endpoint(Ordered::new()) {
        Ok(endpoint) => endpoint,
        Err(error) => {
            fabric.close().await;
            return Err(error);
        }
    };
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
                if let Err(error) = finished(result) { break Err(error); }
            }
            accepted = endpoint.accept(), if tasks.len() < config.limits.max_connections => {
                match accepted {
                    Ok((peer, stream)) => {
                        if peer != fabric.peer {
                            eprintln!("USB/IP stream: unauthorized node ID");
                            continue;
                        }
                        let tcp = fabric.tcp.clone();
                        let duration = config.limits.connect_timeout;
                        tasks.spawn(async move {
                            let mut secure = stream.compat();
                            let mut socket = establish(duration, async {
                                preamble(&mut secure, false).await?;
                                let socket = TcpStream::connect(backend).await?;
                                socket.set_nodelay(true)?;
                                Ok(socket)
                            }).await?;
                            eprintln!("USB/IP stream {peer}: path {:?}", tcp.path_to(&peer));
                            copy_bidirectional(&mut secure, &mut socket).await?;
                            Ok(())
                        });
                    }
                    Err(error) => break Err(error),
                }
            }
        }
    };
    drain(&mut tasks).await;
    fabric.close().await;
    result
}

/// Exposes a loopback TCP listener through one independent ordered stream per socket.
///
/// The fabric remains alive concurrently with forwarding. A bounded setup deadline
/// covers route discovery, pinned TLS and the remoteusb exchange, but never idle
/// USB/IP traffic. At capacity, sockets remain in the OS backlog. Failed sessions
/// are not retried. Shutdown drains tasks and disconnects attached devices.
///
/// # Errors
/// Returns invalid credentials/settings, a non-loopback listener, listener failure,
/// terminal fabric closure or a panicked task. Individual setup failures are logged
/// without payloads/secrets and leave the daemon available for a new local session.
pub async fn run_client(
    listener: TcpListener,
    config: PeerConfig,
    shutdown: impl Future<Output = ()>,
) -> io::Result<()> {
    config.validate()?;
    if !listener.local_addr()?.ip().is_loopback() {
        return Err(invalid_input(
            "local USB/IP listener must be a loopback address",
        ));
    }
    tokio::pin!(shutdown);
    let fabric = tokio::select! {
        biased;
        () = &mut shutdown => return Ok(()),
        result = Fabric::start(&config) => result?,
    };
    eprintln!("local USB/IP listener: {}", listener.local_addr()?);
    let peer = match fabric.node.peer(fabric.peer.clone(), Ordered::new()) {
        Ok(peer) => peer,
        Err(error) => {
            fabric.close().await;
            return Err(error);
        }
    };
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
                if let Err(error) = finished(result) { break Err(error); }
            }
            accepted = listener.accept(), if tasks.len() < config.limits.max_connections => {
                let (mut socket, _) = match accepted {
                    Ok(accepted) => accepted,
                    Err(error) => break Err(error),
                };
                let peer = peer.clone();
                let tcp = fabric.tcp.clone();
                let duration = config.limits.connect_timeout;
                tasks.spawn(async move {
                    socket.set_nodelay(true)?;
                    let mut secure = establish(duration, async {
                        wait_route(peer.node(), &tcp, peer.id()).await?;
                        let mut stream = peer.connect().await?.compat();
                        preamble(&mut stream, true).await?;
                        Ok(stream)
                    }).await?;
                    eprintln!("USB/IP stream {}: path {:?}", peer.id(), tcp.path_to(peer.id()));
                    copy_bidirectional(&mut socket, &mut secure).await?;
                    Ok(())
                });
            }
        }
    };
    drain(&mut tasks).await;
    fabric.close().await;
    result
}

async fn wait_route(node: &Node, tcp: &TcpMsgTransport, peer: &NodeId) -> io::Result<()> {
    loop {
        tcp.local_addrs()?;
        if node.router().is_closed() {
            return Err(closed());
        }
        if tcp.path_to(peer).is_some() && node.router().route_to(peer).is_some() {
            return Ok(());
        }
        sleep(POLL).await;
    }
}

/// Hosts keyed TCP rendezvous, traversal coordination and encrypted-stream relay.
///
/// The relay carries Groupnet ciphertext, not plaintext USB/IP. Only the explicit
/// nonempty node allowlist and shared key are admitted; there is no open mode.
/// The assigned address is logged, including an ephemeral port when requested.
///
/// # Errors
/// Returns an invalid key, invalid/duplicate IDs, invalid listen address, bind
/// failure or terminal rendezvous closure. Shutdown drains rendezvous tasks.
pub async fn run_rendezvous(
    listen: SocketAddr,
    key: &Path,
    peers: Vec<String>,
    shutdown: impl Future<Output = ()>,
) -> io::Result<()> {
    validate_ids(&peers.iter().map(String::as_str).collect::<Vec<_>>())?;
    if invalid_ip(listen.ip()) {
        return Err(invalid_input(
            "rendezvous listen address must be unicast or unspecified",
        ));
    }
    let rendezvous = TcpRendezvous::bind(
        listen,
        network_key(key)?,
        peers.into_iter().map(NodeId::new).collect(),
    )
    .await?;
    eprintln!("Groupnet rendezvous listener: {}", rendezvous.local_addr()?);
    tokio::pin!(shutdown);
    let result = loop {
        tokio::select! {
            biased;
            () = &mut shutdown => break Ok(()),
            () = sleep(POLL) => {
                if let Err(error) = rendezvous.local_addr() { break Err(error); }
            }
        }
    };
    rendezvous.close().await;
    result
}
