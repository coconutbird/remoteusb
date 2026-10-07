//! Hardware-independent regressions over actual admitted TCP and keyed rendezvous.

use std::error::Error;
use std::fs;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use groupnet::connectivity::{NetworkKey, PathPolicy, PeerPath, TcpPunchConfig, TcpRendezvous};
use groupnet::core::{GroupId, NodeId, wire};
use groupnet::network::tunnel::{PeerIdentity, TlsIdentity};
use groupnet::network::{NetworkConfig, TunnelConfig};
use groupnet::runtime::{Node, Ordered};
use groupnet::transport::Transport;
use groupnet::transport::admission::{AcceptedPeer, Admission, JoinRequest};
use groupnet::transport::bulk::BulkTransport;
use groupnet::transport::link::LinkFuture;
use groupnet::transport::tcp::{TcpAdmissionConfig, TcpMsgConfig, TcpMsgTransport};
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use remoteusb_transport::wire::{PREAMBLE as MARKER, tunnel_limits};
use remoteusb_transport::{
    Connection, Limits, PeerConfig, run_client, run_client_with_status, run_rendezvous, run_server,
};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{oneshot, watch};
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};
use tokio_util::compat::FuturesAsyncReadCompatExt;

type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;
const WAIT: Duration = Duration::from_secs(10);
const QUIET: Duration = Duration::from_millis(150);
const KEY: [u8; 32] = [0x42; 32];

struct Identity {
    cert: PathBuf,
    key: PathBuf,
    der: Vec<u8>,
    key_der: Vec<u8>,
}

struct Certificates {
    directory: TempDir,
    ca: PathBuf,
    ca_der: Vec<u8>,
    exporter: Identity,
    receiver: Identity,
    rogue: Identity,
    network_key: PathBuf,
}

impl Certificates {
    fn new() -> TestResult<Self> {
        let directory = tempfile::tempdir()?;
        let key = KeyPair::generate()?;
        let mut params = CertificateParams::new(Vec::<String>::new())?;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];
        let certificate = params.self_signed(&key)?;
        let ca_der = certificate.der().to_vec();
        let ca = directory.path().join("ca.pem");
        fs::write(&ca, certificate.pem())?;
        let issuer = Issuer::new(params, key);
        let issue = |name: &str| -> TestResult<Identity> {
            let key = KeyPair::generate()?;
            let mut params = CertificateParams::new(vec!["groupnet.peer".to_owned()])?;
            params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
            params.extended_key_usages = vec![
                ExtendedKeyUsagePurpose::ServerAuth,
                ExtendedKeyUsagePurpose::ClientAuth,
            ];
            let certificate = params.signed_by(&key, &issuer)?;
            let cert = directory.path().join(format!("{name}.pem"));
            let key_path = directory.path().join(format!("{name}.key"));
            fs::write(&cert, certificate.pem())?;
            fs::write(&key_path, key.serialize_pem())?;
            Ok(Identity {
                cert,
                key: key_path,
                der: certificate.der().to_vec(),
                key_der: key.serialize_der(),
            })
        };
        let exporter = issue("exporter")?;
        let receiver = issue("receiver")?;
        let rogue = issue("rogue")?;
        let network_key = directory.path().join("network.key");
        fs::write(&network_key, format!("{}\n", "42".repeat(32)))?;
        Ok(Self {
            directory,
            ca,
            ca_der,
            exporter,
            receiver,
            rogue,
            network_key,
        })
    }

    fn config(&self, rendezvous: SocketAddr, exporter: bool, relay_only: bool) -> PeerConfig {
        let (local_id, peer_id, identity, peer) = if exporter {
            ("exporter", "receiver", &self.exporter, &self.receiver)
        } else {
            ("receiver", "exporter", &self.receiver, &self.exporter)
        };
        PeerConfig {
            local_id: local_id.to_owned(),
            peer_id: peer_id.to_owned(),
            connection: Connection::Rendezvous {
                address: rendezvous,
                key: self.network_key.clone(),
                binds: vec!["127.0.0.1:0".parse().expect("literal address")],
                relay_only,
            },
            ca: self.ca.clone(),
            cert: identity.cert.clone(),
            key: identity.key.clone(),
            peer_cert: peer.cert.clone(),
            limits: Limits::default(),
        }
    }

    fn direct(&self, bind: SocketAddr, peer: Option<SocketAddr>, exporter: bool) -> PeerConfig {
        let mut config = self.config(bind, exporter, false);
        config.connection = Connection::Direct { bind, peer };
        config
    }

    fn tunnels(&self, identity: &Identity, pin: &Identity) -> io::Result<TunnelConfig> {
        Ok(TunnelConfig::new(
            TlsIdentity::from_der(
                vec![self.ca_der.clone()],
                vec![identity.der.clone()],
                identity.key_der.clone(),
            )?,
            [PeerIdentity::new(NodeId::new("exporter"), &pin.der)?],
        )
        .with_limits(tunnel_limits(&Limits::default())))
    }
}

struct Running {
    address: SocketAddr,
    shutdown: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<io::Result<()>>>,
}

impl Running {
    async fn stop(mut self) -> TestResult {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(task) = self.task.take() {
            within(task).await???;
        }
        Ok(())
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        if let Some(task) = self.task.as_ref() {
            task.abort();
        }
    }
}

async fn within<T>(operation: impl Future<Output = T>) -> TestResult<T> {
    Ok(timeout(WAIT, operation).await?)
}

async fn listener() -> io::Result<TcpListener> {
    TcpListener::bind("127.0.0.1:0").await
}

async fn rendezvous() -> io::Result<TcpRendezvous> {
    TcpRendezvous::bind(
        "127.0.0.1:0".parse().map_err(io::Error::other)?,
        NetworkKey::from_bytes(KEY),
        vec![NodeId::new("exporter"), NodeId::new("receiver")],
    )
    .await
}

async fn start_server(config: PeerConfig) -> TestResult<(Running, TcpListener)> {
    let backend = listener().await?;
    let address = backend.local_addr()?;
    let (shutdown, receiver) = oneshot::channel();
    let task = tokio::spawn(run_server(config, address, async move {
        let _ = receiver.await;
    }));
    Ok((
        Running {
            address,
            shutdown: Some(shutdown),
            task: Some(task),
        },
        backend,
    ))
}

async fn start_client(config: PeerConfig) -> TestResult<Running> {
    let listener = listener().await?;
    let address = listener.local_addr()?;
    let (shutdown, receiver) = oneshot::channel();
    let task = tokio::spawn(run_client(listener, config, async move {
        let _ = receiver.await;
    }));
    Ok(Running {
        address,
        shutdown: Some(shutdown),
        task: Some(task),
    })
}

async fn raw_peer(
    address: SocketAddr,
    tunnels: TunnelConfig,
    relay_only: bool,
) -> TestResult<(Node, TcpMsgTransport)> {
    let mut config = TcpPunchConfig::new(
        NodeId::new("receiver"),
        address,
        NetworkKey::from_bytes(KEY),
        vec![NodeId::new("exporter")],
    );
    config.bind = "127.0.0.1:0".parse()?;
    config.candidate_binds.push("127.0.0.1:0".parse()?);
    config.policy = if relay_only {
        PathPolicy::RelayOnly
    } else {
        PathPolicy::DirectPreferred
    };
    let tcp = TcpMsgTransport::bind_connectivity(config).await?;
    let node = Node::builder(NodeId::new("receiver"))
        .link(tcp.clone().into_bound_link(1))
        .tunnels(tunnels)
        .gossip_interval_ms(50)
        .start()
        .await?;
    within(async {
        while node.router().route_to(&NodeId::new("exporter")).is_none()
            || tcp.path_to(&NodeId::new("exporter"))
                != Some(if relay_only {
                    PeerPath::Relay
                } else {
                    PeerPath::Direct
                })
        {
            sleep(Duration::from_millis(25)).await;
        }
    })
    .await?;
    Ok((node, tcp))
}

#[derive(Debug)]
struct ExporterAdmission;

impl Admission for ExporterAdmission {
    fn admit<'a>(&'a self, request: JoinRequest<'a>) -> LinkFuture<'a, io::Result<AcceptedPeer>> {
        Box::pin(async move {
            if request.claimed != &NodeId::new("exporter") || !request.credential.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "unexpected peer",
                ));
            }
            Ok(AcceptedPeer::new(request.claimed.clone()))
        })
    }
}

async fn unused_address() -> TestResult<SocketAddr> {
    Ok(listener().await?.local_addr()?)
}

async fn direct_peer(
    address: SocketAddr,
    id: &str,
    tunnels: TunnelConfig,
) -> TestResult<(Node, TcpMsgTransport)> {
    // An unspecified client bind advertises no dial-back address. The server
    // must discover the peer through the full-duplex admitted session alone.
    let tcp = TcpMsgTransport::bind_admitted(
        NodeId::new(id),
        "0.0.0.0:0",
        TcpMsgConfig::default(),
        Arc::new(ExporterAdmission),
        Vec::new(),
        TcpAdmissionConfig {
            max_peers: 1,
            ..TcpAdmissionConfig::default()
        },
    )
    .await?;
    tcp.register_peer(NodeId::new("exporter"), address);
    let node = Node::builder(NodeId::new(id))
        .link(tcp.clone().into_bound_link(1))
        .tunnels(tunnels)
        .gossip_interval_ms(50)
        .start()
        .await?;
    tcp.connect_peer(&NodeId::new("exporter"))?;
    Ok((node, tcp))
}

async fn direct_route(node: &Node, tcp: &TcpMsgTransport) -> TestResult {
    within(async {
        let id = NodeId::new("exporter");
        while tcp.path_to(&id).is_none() || node.router().route_to(&id).is_none() {
            tcp.connect_peer(&id)?;
            sleep(Duration::from_millis(25)).await;
        }
        Ok::<_, io::Error>(())
    })
    .await??;
    Ok(())
}

async fn start_monitored(config: PeerConfig) -> TestResult<(Running, watch::Receiver<usize>)> {
    let listener = listener().await?;
    let address = listener.local_addr()?;
    let (shutdown, receiver) = oneshot::channel();
    let (status, count) = watch::channel(0);
    let task = tokio::spawn(run_client_with_status(
        listener,
        config,
        async move {
            let _ = receiver.await;
        },
        status,
    ));
    Ok((
        Running {
            address,
            shutdown: Some(shutdown),
            task: Some(task),
        },
        count,
    ))
}

async fn count_is(count: &mut watch::Receiver<usize>, expected: usize) -> TestResult {
    within(count.wait_for(|count| *count == expected)).await??;
    Ok(())
}

async fn no_backend_connection(backend: &TcpListener) {
    assert!(timeout(QUIET, backend.accept()).await.is_err());
}

async fn exchange(mut socket: TcpStream, backend: &TcpListener, payload: &[u8]) -> TestResult {
    socket.write_all(payload).await?;
    socket.shutdown().await?;
    let (mut remote, _) = within(backend.accept()).await??;
    let mut received = Vec::new();
    within(remote.read_to_end(&mut received)).await??;
    assert_eq!(received, payload);
    // Reply only after EOF: an upload half-close must not discard the read half.
    remote.write_all(payload).await?;
    remote.shutdown().await?;
    let mut response = Vec::new();
    within(socket.read_to_end(&mut response)).await??;
    assert_eq!(response, payload);
    Ok(())
}

#[tokio::test]
async fn unauthenticated_gossip_flood_is_not_replicated_and_does_not_block_pinned_streams()
-> TestResult {
    let certificates = Certificates::new()?;
    let address = unused_address().await?;
    let (server, backend) = start_server(certificates.direct(address, None, true)).await?;
    let exporter = NodeId::new("exporter");
    let receiver = NodeId::new("receiver");
    let tcp = TcpMsgTransport::bind_admitted(
        receiver.clone(),
        "0.0.0.0:0",
        TcpMsgConfig::default(),
        Arc::new(ExporterAdmission),
        Vec::new(),
        TcpAdmissionConfig {
            max_peers: 1,
            ..TcpAdmissionConfig::default()
        },
    )
    .await?;
    tcp.register_peer(exporter.clone(), address);
    let network = NetworkConfig::default()
        .with_link(tcp.clone().into_bound_link(1))
        .with_tunnels(certificates.tunnels(&certificates.receiver, &certificates.exporter)?)
        .bind(receiver.clone())
        .await?;
    within(async {
        while tcp.path_to(&exporter).is_none() || network.router().route_to(&exporter).is_none() {
            tcp.connect_peer(&exporter)?;
            sleep(Duration::from_millis(25)).await;
        }
        Ok::<_, io::Error>(())
    })
    .await??;
    // Admission so far is only an empty-credential routing claim. No TLS stream
    // has been opened. These valid small frames used to accumulate unbounded
    // replicated metadata in the runtime's implicit routing membership group.
    for number in 0..2048 {
        let frame = wire::Frame {
            kind: wire::Kind::Digest,
            group: GroupId::new("__groupnet_routing__"),
            target: None,
            digest: Vec::new(),
            wants: Vec::new(),
            members: Vec::new(),
            metadata: vec![wire::MetaDelta {
                key: format!("untrusted-{number}"),
                version: 1,
                writer: receiver.clone(),
                value: "untrusted-value".to_owned(),
            }],
            lead: None,
        };
        network
            .router()
            .send(&exporter, &wire::encode(&frame))
            .await?;
        if number % 16 == 0 {
            sleep(Duration::from_millis(1)).await;
        }
    }
    // A membership-bearing server would emit/replicate coordination frames.
    // Native route advertisements are internal and not part of this inbox.
    assert!(timeout(QUIET, network.router().recv()).await.is_err());
    no_backend_connection(&backend).await;
    let mut stream = within(network.connect(&exporter)).await??.compat();
    stream.write_all(MARKER).await?;
    stream.flush().await?;
    let mut marker = [0; MARKER.len()];
    within(stream.read_exact(&mut marker)).await??;
    assert_eq!(&marker, MARKER);
    let payload: Vec<_> = (0..=255).cycle().take(4096).collect();
    stream.write_all(&payload).await?;
    stream.shutdown().await?;
    let (mut remote, _) = within(backend.accept()).await??;
    let mut request = Vec::new();
    within(remote.read_to_end(&mut request)).await??;
    assert_eq!(request, payload);
    remote.write_all(&payload).await?;
    remote.shutdown().await?;
    let mut response = Vec::new();
    within(stream.read_to_end(&mut response)).await??;
    assert_eq!(response, payload);
    network.close().await;
    tcp.close().await;
    server.stop().await?;
    Ok(())
}

#[tokio::test]
async fn admitted_direct_binary_halfclose_and_monitored_lifecycle() -> TestResult {
    let certificates = Certificates::new()?;
    let address = unused_address().await?;
    let (server, backend) = start_server(certificates.direct(address, None, true)).await?;
    let (client, mut count) =
        start_monitored(certificates.direct("0.0.0.0:0".parse()?, Some(address), false)).await?;
    count_is(&mut count, 0).await?;
    let payload: Vec<_> = (0..=255).cycle().take(32 * 1024).collect();
    exchange(
        TcpStream::connect(client.address).await?,
        &backend,
        &payload,
    )
    .await?;
    count_is(&mut count, 0).await?;

    let mut first = TcpStream::connect(client.address).await?;
    first.write_all(b"one").await?;
    let (mut remote, _) = within(backend.accept()).await??;
    let mut data = [0; 3];
    within(remote.read_exact(&mut data)).await??;
    assert_eq!(&data, b"one");
    count_is(&mut count, 1).await?;
    let second = TcpStream::connect(client.address).await?;
    let (_second_remote, _) = within(backend.accept()).await??;
    count_is(&mut count, 2).await?;
    first.shutdown().await?;
    within(remote.read_to_end(&mut Vec::new())).await??;
    remote.shutdown().await?;
    within(first.read_to_end(&mut Vec::new())).await??;
    count_is(&mut count, 1).await?;
    // Half-closing first removed only that task; idle second is counted until cleanup.
    client.stop().await?;
    assert_eq!(*count.borrow(), 0);
    drop(second);
    server.stop().await?;
    Ok(())
}

#[tokio::test]
async fn direct_admission_rejects_unlisted_and_duplicate_peers_then_readmits() -> TestResult {
    let certificates = Certificates::new()?;
    let address = unused_address().await?;
    let (server, backend) = start_server(certificates.direct(address, None, true)).await?;
    let (node, tcp) = direct_peer(
        address,
        "receiver",
        certificates.tunnels(&certificates.receiver, &certificates.exporter)?,
    )
    .await?;
    direct_route(&node, &tcp).await?;
    let peer = node.peer(NodeId::new("exporter"), Ordered::new())?;
    let mut active = within(peer.connect()).await??.compat();
    active.write_all(MARKER).await?;
    active.flush().await?;
    let mut marker = [0; MARKER.len()];
    within(active.read_exact(&mut marker)).await??;
    assert_eq!(&marker, MARKER);
    let (mut remote, _) = within(backend.accept()).await??;

    for id in ["unlisted", "receiver"] {
        let (denied_node, denied_tcp) = direct_peer(
            address,
            id,
            certificates.tunnels(&certificates.receiver, &certificates.exporter)?,
        )
        .await?;
        // Repeat actual admission attempts while the legitimate session is live.
        for _ in 0..5 {
            denied_tcp.connect_peer(&NodeId::new("exporter"))?;
            sleep(QUIET).await;
            assert_eq!(denied_tcp.known_peers(), [] as [NodeId; 0]);
            assert!(
                denied_node
                    .router()
                    .route_to(&NodeId::new("exporter"))
                    .is_none()
            );
        }
        no_backend_connection(&backend).await;
        denied_node.close().await;
        denied_tcp.close().await;
    }
    // Duplicate attempts cannot evict the current generation.
    active.write_all(b"live").await?;
    active.flush().await?;
    let mut data = [0; 4];
    within(remote.read_exact(&mut data)).await??;
    assert_eq!(&data, b"live");
    node.close().await;
    tcp.close().await;
    drop(active);
    drop(remote);
    let (node, tcp) = direct_peer(
        address,
        "receiver",
        certificates.tunnels(&certificates.receiver, &certificates.exporter)?,
    )
    .await?;
    direct_route(&node, &tcp).await?;
    let peer = node.peer(NodeId::new("exporter"), Ordered::new())?;
    let mut stream = within(peer.connect()).await??.compat();
    stream.write_all(MARKER).await?;
    stream.flush().await?;
    within(stream.read_exact(&mut marker)).await??;
    assert_eq!(&marker, MARKER);
    let _ = within(backend.accept()).await??;
    node.close().await;
    tcp.close().await;
    server.stop().await?;
    Ok(())
}

#[tokio::test]
async fn direct_bootstrap_recovers_late_server_and_server_restart_without_replaying_streams()
-> TestResult {
    let certificates = Certificates::new()?;
    let address = unused_address().await?;
    let (client, mut count) =
        start_monitored(certificates.direct("127.0.0.1:0".parse()?, Some(address), false)).await?;
    let mut local = TcpStream::connect(client.address).await?;
    local.write_all(b"late server").await?;
    count_is(&mut count, 1).await?;
    sleep(QUIET).await;
    let (server, backend) = start_server(certificates.direct(address, None, true)).await?;
    let (mut remote, _) = within(backend.accept()).await??;
    let mut data = [0; 11];
    within(remote.read_exact(&mut data)).await??;
    assert_eq!(&data, b"late server");
    server.stop().await?;
    count_is(&mut count, 0).await?;
    let mut byte = [0];
    assert!(matches!(
        within(local.read(&mut byte)).await?,
        Ok(0) | Err(_)
    ));
    drop(remote);
    drop(backend);
    let (server, backend) = start_server(certificates.direct(address, None, true)).await?;
    no_backend_connection(&backend).await;
    exchange(
        TcpStream::connect(client.address).await?,
        &backend,
        b"new stream",
    )
    .await?;
    count_is(&mut count, 0).await?;
    client.stop().await?;
    server.stop().await?;
    Ok(())
}

#[tokio::test]
async fn monitored_setup_timeout_cancellation_and_validation_reset_counts() -> TestResult {
    let certificates = Certificates::new()?;
    let address = unused_address().await?;
    let mut config = certificates.direct("127.0.0.1:0".parse()?, Some(address), false);
    config.limits.connect_timeout = Duration::from_millis(300);
    let (mut client, mut count) = start_monitored(config.clone()).await?;
    let _pending = TcpStream::connect(client.address).await?;
    count_is(&mut count, 1).await?;
    count_is(&mut count, 0).await?;
    let _pending = TcpStream::connect(client.address).await?;
    count_is(&mut count, 1).await?;
    let task = client.task.take().ok_or("missing task")?;
    task.abort();
    assert!(
        within(task)
            .await?
            .expect_err("aborted client succeeded")
            .is_cancelled()
    );
    assert_eq!(*count.borrow(), 0);

    let (status, count) = watch::channel(99);
    let mut broken = config.clone();
    broken.ca = certificates.directory.path().join("missing-ca.pem");
    assert!(
        run_client_with_status(listener().await?, broken, std::future::pending(), status)
            .await
            .is_err()
    );
    assert_eq!(*count.borrow(), 0);

    let (status, count) = watch::channel(99);
    config.limits.max_connections = 0;
    assert!(
        run_client_with_status(listener().await?, config, std::future::pending(), status)
            .await
            .is_err()
    );
    assert_eq!(*count.borrow(), 0);
    Ok(())
}

#[tokio::test]
async fn invalid_direct_endpoints_fail_before_binding() -> TestResult {
    let certificates = Certificates::new()?;
    for (bind, peer) in [
        ("224.0.0.1:0", None),
        ("127.0.0.1:0", Some("0.0.0.0:7443")),
        ("127.0.0.1:0", Some("127.0.0.1:0")),
        ("127.0.0.1:0", Some("224.0.0.1:7443")),
        ("127.0.0.1:0", Some("[::1]:7443")),
    ] {
        let config = certificates.direct(bind.parse()?, peer.map(str::parse).transpose()?, false);
        let error = run_client(listener().await?, config, std::future::pending())
            .await
            .expect_err("invalid direct endpoint accepted");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }
    Ok(())
}

#[tokio::test]
async fn relay_forwards_binary_and_preserves_both_half_closes() -> TestResult {
    let certificates = Certificates::new()?;
    let relay = rendezvous().await?;
    let (server, backend) =
        start_server(certificates.config(relay.local_addr()?, true, true)).await?;
    let client = start_client(certificates.config(relay.local_addr()?, false, true)).await?;
    let payload: Vec<_> = (0..=255).cycle().take(32 * 1024).collect();
    exchange(
        TcpStream::connect(client.address).await?,
        &backend,
        &payload,
    )
    .await?;
    client.stop().await?;
    server.stop().await?;
    relay.close().await;
    Ok(())
}

#[tokio::test]
async fn direct_ordered_stream_forwards_binary_after_protocol_exchange() -> TestResult {
    let certificates = Certificates::new()?;
    let relay = rendezvous().await?;
    let (server, backend) =
        start_server(certificates.config(relay.local_addr()?, true, false)).await?;
    let (node, tcp) = raw_peer(
        relay.local_addr()?,
        certificates.tunnels(&certificates.receiver, &certificates.exporter)?,
        false,
    )
    .await?;
    assert_eq!(
        tcp.path_to(&NodeId::new("exporter")),
        Some(PeerPath::Direct)
    );
    let peer = node.peer(NodeId::new("exporter"), Ordered::new())?;
    let mut stream = within(peer.connect()).await??.compat();
    stream.write_all(MARKER).await?;
    stream.flush().await?;
    let mut marker = [0; MARKER.len()];
    within(stream.read_exact(&mut marker)).await??;
    assert_eq!(&marker, MARKER);
    let payload: Vec<_> = (0..=255).rev().cycle().take(4096).collect();
    stream.write_all(&payload).await?;
    stream.shutdown().await?;
    let (mut socket, _) = within(backend.accept()).await??;
    let mut upload = Vec::new();
    within(socket.read_to_end(&mut upload)).await??;
    assert_eq!(upload, payload);
    socket.write_all(&payload).await?;
    socket.shutdown().await?;
    let mut reply = Vec::new();
    within(stream.read_to_end(&mut reply)).await??;
    assert_eq!(reply, payload);
    node.close().await;
    tcp.close().await;
    server.stop().await?;
    relay.close().await;
    Ok(())
}

#[tokio::test]
async fn untrusted_identity_and_wrong_exact_pins_never_open_backend() -> TestResult {
    let certificates = Certificates::new()?;
    let unrelated = Certificates::new()?;
    for direct in [false, true] {
        // A CA-signed but unpinned identity, an unrelated CA, and a wrong server pin.
        for (identity, pin) in [
            (&certificates.rogue, &certificates.exporter),
            (&unrelated.receiver, &certificates.exporter),
            (&certificates.receiver, &certificates.rogue),
        ] {
            let relay = if direct {
                None
            } else {
                Some(rendezvous().await?)
            };
            let address = match &relay {
                Some(relay) => relay.local_addr()?,
                None => unused_address().await?,
            };
            let config = if direct {
                certificates.direct(address, None, true)
            } else {
                certificates.config(address, true, true)
            };
            let (server, backend) = start_server(config).await?;
            let (node, tcp) = if direct {
                let (node, tcp) =
                    direct_peer(address, "receiver", certificates.tunnels(identity, pin)?).await?;
                direct_route(&node, &tcp).await?;
                (node, tcp)
            } else {
                raw_peer(address, certificates.tunnels(identity, pin)?, true).await?
            };
            let peer = node.peer(NodeId::new("exporter"), Ordered::new())?;
            if let Ok(stream) = within(peer.connect()).await? {
                let mut stream = stream.compat();
                // A TLS client may finish before the server's rejection is observed.
                let _ = stream.write_all(MARKER).await;
                let mut byte = [0];
                assert!(matches!(
                    within(stream.read(&mut byte)).await?,
                    Ok(0) | Err(_)
                ));
            }
            no_backend_connection(&backend).await;
            node.close().await;
            tcp.close().await;
            server.stop().await?;
            if let Some(relay) = relay {
                relay.close().await;
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn wrong_network_key_and_unlisted_alias_are_rejected_before_backend() -> TestResult {
    let certificates = Certificates::new()?;
    let relay = rendezvous().await?;
    let (server, backend) =
        start_server(certificates.config(relay.local_addr()?, true, true)).await?;
    let wrong = certificates.directory.path().join("wrong.key");
    fs::write(&wrong, "24".repeat(32))?;
    for unlisted in [false, true] {
        let mut config = certificates.config(relay.local_addr()?, false, true);
        if unlisted {
            config.local_id = "unlisted".to_owned();
        } else if let Connection::Rendezvous { key, .. } = &mut config.connection {
            key.clone_from(&wrong);
        }
        let result = within(Box::pin(run_client(
            listener().await?,
            config,
            std::future::pending(),
        )))
        .await?;
        assert!(result.is_err());
        no_backend_connection(&backend).await;
    }
    server.stop().await?;
    relay.close().await;
    Ok(())
}

#[tokio::test]
async fn invalid_application_marker_and_stalled_setup_never_open_backend() -> TestResult {
    let certificates = Certificates::new()?;
    let relay = rendezvous().await?;
    let mut config = certificates.config(relay.local_addr()?, true, true);
    config.limits.connect_timeout = Duration::from_millis(500);
    let (server, backend) = start_server(config).await?;
    let (node, tcp) = raw_peer(
        relay.local_addr()?,
        certificates.tunnels(&certificates.receiver, &certificates.exporter)?,
        true,
    )
    .await?;
    let peer = node.peer(NodeId::new("exporter"), Ordered::new())?;
    for invalid_marker in [true, false] {
        let mut stream = within(peer.connect()).await??.compat();
        if invalid_marker {
            stream.write_all(b"NOTUSBIP\0\0\0\0").await?;
            stream.flush().await?;
        }
        let mut byte = [0];
        assert!(matches!(
            within(stream.read(&mut byte)).await?,
            Ok(0) | Err(_)
        ));
        no_backend_connection(&backend).await;
    }
    // A rejected session must not kill the daemon or consume a permanent slot.
    let mut stream = within(peer.connect()).await??.compat();
    stream.write_all(MARKER).await?;
    stream.flush().await?;
    let mut reply = [0; MARKER.len()];
    within(stream.read_exact(&mut reply)).await??;
    assert_eq!(&reply, MARKER);
    let _ = within(backend.accept()).await??;
    node.close().await;
    tcp.close().await;
    server.stop().await?;
    relay.close().await;
    Ok(())
}

#[tokio::test]
async fn ten_concurrent_streams_exceed_groupnet_default_per_peer_limit() -> TestResult {
    let certificates = Certificates::new()?;
    let relay = rendezvous().await?;
    let mut server_config = certificates.config(relay.local_addr()?, true, true);
    server_config.limits.max_connections = 10;
    let mut client_config = certificates.config(relay.local_addr()?, false, true);
    client_config.limits.max_connections = 10;
    let (server, backend) = start_server(server_config).await?;
    let client = start_client(client_config).await?;
    let mut locals = Vec::new();
    let mut remotes = Vec::new();
    for number in 0..10_u8 {
        let mut local = TcpStream::connect(client.address).await?;
        local.write_all(&[number, 0, 255]).await?;
        locals.push(local);
    }
    for _ in 0..10 {
        let (remote, _) = within(backend.accept()).await??;
        remotes.push(remote);
    }
    for remote in &mut remotes {
        let mut data = [0; 3];
        within(remote.read_exact(&mut data)).await??;
        remote.write_all(&data).await?;
    }
    for (number, local) in locals.iter_mut().enumerate() {
        let mut data = [0; 3];
        within(local.read_exact(&mut data)).await??;
        assert_eq!(data, [u8::try_from(number)?, 0, 255]);
    }
    // Shutdown disconnects idle established streams, and drains both nodes.
    client.stop().await?;
    server.stop().await?;
    for remote in &mut remotes {
        let mut byte = [0];
        assert!(matches!(
            within(remote.read(&mut byte)).await?,
            Ok(0) | Err(_)
        ));
    }
    relay.close().await;
    Ok(())
}

#[tokio::test]
async fn capacity_blocks_extra_backend_until_first_stream_finishes() -> TestResult {
    let certificates = Certificates::new()?;
    let relay = rendezvous().await?;
    let mut server_config = certificates.config(relay.local_addr()?, true, true);
    server_config.limits.max_connections = 1;
    let mut client_config = certificates.config(relay.local_addr()?, false, true);
    client_config.limits.max_connections = 1;
    let (server, backend) = start_server(server_config).await?;
    let client = start_client(client_config).await?;
    let mut first = TcpStream::connect(client.address).await?;
    first.write_all(b"one").await?;
    let (mut remote, _) = within(backend.accept()).await??;
    let mut data = [0; 3];
    within(remote.read_exact(&mut data)).await??;
    assert_eq!(&data, b"one");
    let mut second = TcpStream::connect(client.address).await?;
    second.write_all(b"two").await?;
    no_backend_connection(&backend).await;
    first.shutdown().await?;
    within(remote.read_to_end(&mut Vec::new())).await??;
    remote.shutdown().await?;
    within(first.read_to_end(&mut Vec::new())).await??;
    let (mut remote, _) = within(backend.accept()).await??;
    within(remote.read_exact(&mut data)).await??;
    assert_eq!(&data, b"two");
    client.stop().await?;
    server.stop().await?;
    relay.close().await;
    Ok(())
}

#[tokio::test]
async fn shutdown_cancels_pending_route_setup_and_relay_loss_is_terminal() -> TestResult {
    let certificates = Certificates::new()?;
    let relay = rendezvous().await?;
    let client = start_client(certificates.config(relay.local_addr()?, false, true)).await?;
    let mut local = TcpStream::connect(client.address).await?;
    local.write_all(b"pending route").await?;
    client.stop().await?;
    let mut byte = [0];
    assert!(matches!(
        within(local.read(&mut byte)).await?,
        Ok(0) | Err(_)
    ));
    relay.close().await;

    let relay = rendezvous().await?;
    let (mut server, backend) =
        start_server(certificates.config(relay.local_addr()?, true, true)).await?;
    let (mut client, mut count) =
        start_monitored(certificates.config(relay.local_addr()?, false, true)).await?;
    // Prove endpoints are admitted before closing their sole physical relay.
    let mut local = TcpStream::connect(client.address).await?;
    local.write_all(b"connected").await?;
    let (mut remote, _) = within(backend.accept()).await??;
    let mut received = [0; 9];
    within(remote.read_exact(&mut received)).await??;
    assert_eq!(&received, b"connected");
    count_is(&mut count, 1).await?;
    relay.close().await;
    let task = server.task.take().ok_or("missing server task")?;
    assert!(within(task).await??.is_err());
    let task = client.task.take().ok_or("missing client task")?;
    assert!(within(task).await??.is_err());
    assert_eq!(*count.borrow(), 0);
    Ok(())
}

#[tokio::test]
async fn plaintext_boundaries_and_configuration_are_validated_before_network_io() -> TestResult {
    let certificates = Certificates::new()?;
    let address: SocketAddr = "127.0.0.1:9".parse()?;
    let config = certificates.config(address, true, true);
    for backend in ["192.0.2.1:3240", "0.0.0.0:3240", "127.0.0.1:0"] {
        let error = run_server(config.clone(), backend.parse()?, std::future::pending())
            .await
            .expect_err("invalid backend accepted");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }
    let public = TcpListener::bind("0.0.0.0:0").await?;
    let error = run_client(public, config.clone(), std::future::pending())
        .await
        .expect_err("public plaintext listener accepted");
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    for variant in 0..5 {
        let mut invalid = config.clone();
        match variant {
            0 => invalid.peer_id.clone_from(&invalid.local_id),
            1 => invalid.limits.max_connections = 0,
            2 => invalid.limits.connect_timeout = Duration::ZERO,
            3 => {
                if let Connection::Rendezvous { address, .. } = &mut invalid.connection {
                    *address = "0.0.0.0:7443".parse()?;
                }
            }
            _ => {
                if let Connection::Rendezvous { binds, .. } = &mut invalid.connection {
                    *binds = vec!["224.0.0.1:0".parse()?];
                }
            }
        }
        let error = run_client(listener().await?, invalid, std::future::pending())
            .await
            .expect_err("invalid configuration accepted");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }
    Ok(())
}

#[tokio::test]
async fn rendezvous_rejects_invalid_key_and_empty_or_duplicate_allowlist() -> TestResult {
    let certificates = Certificates::new()?;
    let listen = "127.0.0.1:0".parse()?;
    for peers in [Vec::new(), vec!["same".to_owned(), "same".to_owned()]] {
        assert!(
            run_rendezvous(listen, &certificates.network_key, peers, async {})
                .await
                .is_err()
        );
    }
    for invalid_key in ["42", &"gg".repeat(32), &"42".repeat(33)] {
        fs::write(&certificates.network_key, invalid_key)?;
        assert!(
            run_rendezvous(
                listen,
                &certificates.network_key,
                vec!["exporter".to_owned(), "receiver".to_owned()],
                async {},
            )
            .await
            .is_err()
        );
    }
    // Mixed-case hex and whitespace are accepted, but never silently an open key.
    fs::write(&certificates.network_key, format!(" {}\n", "aB".repeat(32)))?;
    run_rendezvous(
        listen,
        &certificates.network_key,
        vec!["exporter".to_owned(), "receiver".to_owned()],
        async {},
    )
    .await?;
    Ok(())
}
