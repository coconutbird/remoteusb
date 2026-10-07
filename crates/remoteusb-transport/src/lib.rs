//! USB/IP byte forwarding over pinned, mutually authenticated Groupnet ordered streams.
//!
//! Direct TCP admission allowlists the configured node ID; its routing metadata is
//! unauthenticated and carries no secret. Optional keyed rendezvous also restricts
//! node IDs. In both modes CA roots and exact leaf pins authenticate Groupnet's
//! end-to-end TLS stream; the protocol exchange precedes opening the backend.
//! Direct admission does not prove ownership of a node ID: a spoofed allowlisted
//! claim can occupy the single bounded transport peer slot, but cannot authorize
//! a USB/IP stream without the independently provisioned TLS credentials.
//! Each local TCP connection owns one stream, without payload inspection or reconnect.
//! Direct streams are fenced to the native admitted TCP session generation:
//! withdrawal/replacement cancels setup and forwarding, never replaying a stream.
//! Membership gossip is not used: the native network router retains only bounded
//! routing/packet state, and its bounded unused coordination inbox is never
//! decoded into application or replicated membership metadata.

use std::fs::File;
use std::io::{self, BufReader};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use groupnet::connectivity::{NetworkKey, PathPolicy, TcpPunchConfig, TcpRendezvous};
use groupnet::core::NodeId;
use groupnet::network::tunnel::{PeerIdentity, TlsIdentity, TunnelLimits, TunneledStream};
use groupnet::network::{Network, NetworkConfig, RouterConfig, TunnelConfig};
use groupnet::transport::admission::{AcceptedPeer, Admission, JoinRequest};
use groupnet::transport::bulk::BulkTransport;
use groupnet::transport::link::LinkFuture;
use groupnet::transport::tcp::{TcpAdmissionConfig, TcpMsgConfig, TcpMsgTransport};
use rustls::pki_types::CertificateDer;
use tokio::io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::{Instant, sleep, timeout_at};
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

/// Native Groupnet connection establishment; TLS authorization is identical in both modes.
#[derive(Clone, Debug)]
pub enum Connection {
    /// A bounded admitted TCP listener with an optional explicit bootstrap address.
    /// `None` accepts the allowlisted peer without a configured outbound bootstrap.
    Direct {
        /// Listener bind; unspecified IPs and ephemeral ports are permitted.
        bind: SocketAddr,
        /// Concrete bootstrap target in the bind's address family, or accept-only.
        peer: Option<SocketAddr>,
    },
    /// Keyed rendezvous, direct traversal and optional encrypted-stream relay.
    Rendezvous {
        /// Concrete keyed TCP rendezvous address.
        address: SocketAddr,
        /// Shared network admission key, not the TLS private key.
        key: PathBuf,
        /// One to four reusable TCP candidate/source binds.
        /// The first bind must match the rendezvous address family.
        binds: Vec<SocketAddr>,
        /// Disable direct traversal and require encrypted-stream relay.
        relay_only: bool,
    },
}

/// One endpoint's independently provisioned identity, admission and routing settings.
#[derive(Clone, Debug)]
pub struct PeerConfig {
    /// This endpoint's routing alias (1–64 UTF-8 bytes).
    pub local_id: String,
    /// The only authorized remote routing alias, distinct from `local_id`.
    pub peer_id: String,
    /// Native direct admission or optional keyed rendezvous.
    pub connection: Connection,
    /// PEM trust-root certificates.
    pub ca: PathBuf,
    /// PEM local leaf certificate followed by any intermediate certificates.
    pub cert: PathBuf,
    /// PEM local private key.
    pub key: PathBuf,
    /// PEM authorized remote leaf certificate (exact certificate pin).
    pub peer_cert: PathBuf,
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
        match &self.connection {
            Connection::Direct { bind, peer } => {
                if invalid_ip(bind.ip())
                    || peer.is_some_and(|peer| {
                        peer.port() == 0
                            || peer.ip().is_unspecified()
                            || invalid_ip(peer.ip())
                            || peer.is_ipv4() != bind.is_ipv4()
                    })
                {
                    return Err(invalid_input("invalid direct bind or peer address"));
                }
            }
            Connection::Rendezvous { address, binds, .. } => {
                if address.port() == 0
                    || address.ip().is_unspecified()
                    || invalid_ip(address.ip())
                    || binds.is_empty()
                    || binds.len() > 4
                    || binds[0].is_ipv4() != address.is_ipv4()
                    || binds.iter().any(|bind| invalid_ip(bind.ip()))
                {
                    return Err(invalid_input(
                        "invalid rendezvous or candidate bind addresses",
                    ));
                }
            }
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
    establish_until(Instant::now() + duration, operation).await
}

async fn establish_until<T>(
    deadline: Instant,
    operation: impl Future<Output = io::Result<T>>,
) -> io::Result<T> {
    timeout_at(deadline, operation).await.map_err(|_| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "connection establishment timed out",
        )
    })?
}

/// This gates routing claims only. TLS CA authentication and the exact leaf pin
/// remain mandatory before the protocol exchange or any backend connection.
#[derive(Debug)]
struct PeerAdmission(NodeId);

impl Admission for PeerAdmission {
    fn admit<'a>(&'a self, request: JoinRequest<'a>) -> LinkFuture<'a, io::Result<AcceptedPeer>> {
        Box::pin(async move {
            if request.claimed != &self.0 || !request.credential.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "unconfigured direct peer",
                ));
            }
            Ok(AcceptedPeer::new(self.0.clone()))
        })
    }
}

struct Fabric {
    network: Network,
    tcp: TcpMsgTransport,
    peer: NodeId,
    bootstrap: Option<JoinHandle<()>>,
}

impl Fabric {
    async fn start(config: &PeerConfig) -> io::Result<Self> {
        // Load and validate every credential before binding or connecting sockets.
        let tunnels = config.tunnels()?;
        let peer = NodeId::new(config.peer_id.as_str());
        let tcp = establish(config.limits.connect_timeout, async {
            match &config.connection {
                Connection::Direct { bind, .. } => {
                    TcpMsgTransport::bind_admitted(
                        NodeId::new(config.local_id.as_str()),
                        *bind,
                        TcpMsgConfig {
                            max_outbound: 1,
                            // Match native connectivity's pre-allocation frame bound.
                            max_frame_bytes: groupnet::connectivity::MAX_TCP_MESSAGE,
                            ..TcpMsgConfig::default()
                        },
                        Arc::new(PeerAdmission(peer.clone())),
                        Vec::new(),
                        TcpAdmissionConfig {
                            max_pending: config.limits.max_connections,
                            max_peers: 1,
                            handshake_timeout: config.limits.connect_timeout,
                        },
                    )
                    .await
                }
                Connection::Rendezvous {
                    address,
                    key,
                    binds,
                    relay_only,
                } => {
                    let mut punch = TcpPunchConfig::new(
                        NodeId::new(config.local_id.as_str()),
                        *address,
                        network_key(key)?,
                        vec![peer.clone()],
                    );
                    punch.bind = binds[0];
                    punch.candidate_binds = binds[1..].to_vec();
                    punch.max_peers = 1;
                    punch.policy = if *relay_only {
                        PathPolicy::RelayOnly
                    } else {
                        PathPolicy::DirectPreferred
                    };
                    TcpMsgTransport::bind_connectivity(punch).await
                }
            }
        })
        .await?;
        let result = establish(
            config.limits.connect_timeout,
            NetworkConfig::default()
                .with_router(RouterConfig {
                    forwarding: false,
                    max_routes: 1,
                    max_transports: 1,
                    // Unused coordination messages are bounded and never decoded
                    // by a membership engine or retained as replicated metadata.
                    message_queue: 1,
                    ..RouterConfig::default()
                })
                .with_link(tcp.clone().into_bound_link(1))
                .with_tunnels(tunnels)
                .bind(NodeId::new(config.local_id.as_str())),
        )
        .await;
        match result {
            Ok(network) => {
                let addresses = match tcp.local_addrs() {
                    Ok(addresses) => addresses,
                    Err(error) => {
                        network.close().await;
                        tcp.close().await;
                        return Err(error);
                    }
                };
                eprintln!(
                    "Groupnet node {}: {:?}, listeners {addresses:?}",
                    config.local_id, config.connection
                );
                let bootstrap = if let Connection::Direct {
                    peer: Some(address),
                    ..
                } = &config.connection
                {
                    let address = *address;
                    let tcp = tcp.clone();
                    let peer = peer.clone();
                    Some(tokio::spawn(async move {
                        loop {
                            // Native introduction/gossip metadata is untrusted.
                            // Bootstrap retries restore the explicitly chosen target.
                            if tcp.path_to(&peer).is_none() {
                                tcp.register_peer(peer.clone(), address);
                                if tcp.connect_peer(&peer).is_err() {
                                    return;
                                }
                            }
                            sleep(Duration::from_secs(1)).await;
                        }
                    }))
                } else {
                    None
                };
                Ok(Self {
                    network,
                    tcp,
                    peer,
                    bootstrap,
                })
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
                () = self.network.router().cancelled() => return,
                () = sleep(POLL) => {
                    if self.tcp.local_addrs().is_err() {
                        return;
                    }
                }
            }
        }
    }

    async fn close(mut self) {
        if let Some(bootstrap) = self.bootstrap.take() {
            bootstrap.abort();
            let _ = bootstrap.await;
        }
        self.network.close().await;
        self.tcp.close().await;
    }
}

impl Drop for Fabric {
    fn drop(&mut self) {
        if let Some(bootstrap) = &self.bootstrap {
            bootstrap.abort();
        }
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

/// Adjacent TCP admission and end-to-end TLS admission have independent
/// generations. A direct forwarding task must not outlive its socket generation,
/// even if Groupnet's reliable tunnel would otherwise await a heartbeat timeout.
fn session_lost(
    tcp: &TcpMsgTransport,
    peer: &NodeId,
    direct: bool,
) -> io::Result<impl Future<Output = ()> + use<>> {
    let observed = if direct {
        let registry = tcp.sessions().ok_or_else(closed)?;
        let neighbors = registry.subscribe();
        let generation = neighbors
            .borrow()
            .iter()
            .find(|session| &session.node == peer)
            .map(|session| session.id)
            .ok_or_else(closed)?;
        Some((neighbors, generation))
    } else {
        None
    };
    let peer = peer.clone();
    Ok(async move {
        let Some((mut neighbors, generation)) = observed else {
            return std::future::pending().await;
        };
        loop {
            let admitted = neighbors
                .borrow_and_update()
                .iter()
                .any(|session| session.node == peer && session.id == generation);
            if !admitted || neighbors.changed().await.is_err() {
                return;
            }
        }
    })
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
/// Shutdown aborts/drains streams and closes the network and connectivity endpoint;
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
            accepted = fabric.network.accept(), if tasks.len() < config.limits.max_connections => {
                match accepted {
                    Ok((peer, stream)) => {
                        if peer != fabric.peer {
                            eprintln!("USB/IP stream: unauthorized node ID");
                            continue;
                        }
                        let tcp = fabric.tcp.clone();
                        let duration = config.limits.connect_timeout;
                        let direct = matches!(&config.connection, Connection::Direct { .. });
                        tasks.spawn(async move {
                            let disconnected = session_lost(&tcp, &peer, direct)?;
                            tokio::select! {
                                biased;
                                () = disconnected => Err(closed()),
                                result = async {
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
                                } => result,
                            }
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
    client(listener, config, shutdown, TaskStatus(None)).await
}

/// Monitored forwarding with the same persistent lifetime as [`run_client`].
///
/// Reports accepted local forwarding tasks, including route/TLS/protocol setup.
/// Updates on accept/completion and resets to zero on every exit, including future
/// cancellation. A watch receiver can coalesce transitions; zero alone is not an
/// attachment acknowledgement and must not terminate discovery/setup.
///
/// # Errors
/// Returns the same errors as [`run_client`]. Dropping status receivers does not
/// stop forwarding.
pub async fn run_client_with_status(
    listener: TcpListener,
    config: PeerConfig,
    shutdown: impl Future<Output = ()>,
    status: watch::Sender<usize>,
) -> io::Result<()> {
    let status = TaskStatus(Some(status));
    status.update(0);
    client(listener, config, shutdown, status).await
}

struct TaskStatus(Option<watch::Sender<usize>>);

impl TaskStatus {
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

async fn client(
    listener: TcpListener,
    config: PeerConfig,
    shutdown: impl Future<Output = ()>,
    status: TaskStatus,
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
            accepted = listener.accept(), if tasks.len() < config.limits.max_connections => {
                let (mut socket, _) = match accepted {
                    Ok(accepted) => accepted,
                    Err(error) => break Err(error),
                };
                let peer = fabric.peer.clone();
                let network = fabric.network.clone();
                let tcp = fabric.tcp.clone();
                let duration = config.limits.connect_timeout;
                let direct = matches!(&config.connection, Connection::Direct { .. });
                tasks.spawn(async move {
                    socket.set_nodelay(true)?;
                    let deadline = Instant::now() + duration;
                    establish_until(deadline, wait_route(&network, &tcp, &peer)).await?;
                    let disconnected = session_lost(&tcp, &peer, direct)?;
                    tokio::select! {
                        biased;
                        () = disconnected => Err(closed()),
                        result = async {
                            let mut secure = establish_until(deadline, async {
                                let mut stream = network.connect(&peer).await?.compat();
                                preamble(&mut stream, true).await?;
                                Ok(stream)
                            }).await?;
                            eprintln!("USB/IP stream {peer}: path {:?}", tcp.path_to(&peer));
                            copy_bidirectional(&mut socket, &mut secure).await?;
                            Ok(())
                        } => result,
                    }
                });
                status.update(tasks.len());
            }
        }
    };
    drain(&mut tasks).await;
    status.update(0);
    fabric.close().await;
    result
}

async fn wait_route(network: &Network, tcp: &TcpMsgTransport, peer: &NodeId) -> io::Result<()> {
    loop {
        tcp.local_addrs()?;
        if network.router().is_closed() {
            return Err(closed());
        }
        if tcp.path_to(peer).is_some() && network.router().route_to(peer).is_some() {
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
