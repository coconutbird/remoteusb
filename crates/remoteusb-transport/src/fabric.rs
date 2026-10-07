//! One exclusive peer's Groupnet network, its TCP connectivity and liveness.

use std::io;
use std::sync::Arc;
use std::time::Duration;

use groupnet::connectivity::{PathPolicy, TcpPunchConfig};
use groupnet::core::NodeId;
use groupnet::network::tunnel::TunneledStream;
use groupnet::network::{Network, NetworkConfig, RouterConfig};
use groupnet::transport::admission::{AcceptedPeer, Admission, JoinRequest};
use groupnet::transport::bulk::BulkTransport;
use groupnet::transport::link::LinkFuture;
use groupnet::transport::tcp::{TcpAdmissionConfig, TcpMsgConfig, TcpMsgTransport};
use tokio::task::JoinHandle;
use tokio::time::{Instant, sleep, timeout_at};

use crate::config::{Connection, PeerConfig, network_key};
use crate::flow::StreamWindow;

/// Cadence for liveness checks on handles that expose no closure notification.
pub(crate) const POLL: Duration = Duration::from_millis(25);

pub(crate) fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::NotConnected, "Groupnet fabric closed")
}

/// Runs a setup step under a shared absolute deadline.
pub(crate) async fn within<T>(
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

/// A cloneable per-stream view of the fabric's network, connectivity and peer.
#[derive(Clone)]
pub(crate) struct Link {
    network: Network,
    tcp: TcpMsgTransport,
    peer: NodeId,
    direct: bool,
}

impl Link {
    pub(crate) fn peer(&self) -> &NodeId {
        &self.peer
    }

    pub(crate) async fn accept(&self) -> io::Result<(NodeId, TunneledStream)> {
        self.network.accept().await
    }

    pub(crate) async fn connect(&self) -> io::Result<TunneledStream> {
        self.network.connect(&self.peer).await
    }

    pub(crate) fn log_stream(&self) {
        eprintln!(
            "USB/IP stream {}: path {:?}",
            self.peer,
            self.tcp.path_to(&self.peer)
        );
    }

    /// Waits until connectivity and routing both reach the peer.
    pub(crate) async fn route_ready(&self) -> io::Result<()> {
        loop {
            self.tcp.local_addrs()?;
            if self.network.router().is_closed() {
                return Err(closed());
            }
            if self.tcp.path_to(&self.peer).is_some()
                && self.network.router().route_to(&self.peer).is_some()
            {
                return Ok(());
            }
            sleep(POLL).await;
        }
    }

    /// Adjacent TCP admission and end-to-end TLS admission have independent
    /// generations. A direct forwarding task must not outlive its socket
    /// generation, even if the reliable tunnel would otherwise await a heartbeat
    /// timeout. Completes when the admitted direct session is withdrawn or
    /// replaced; rendezvous paths have no admitted generation and never complete.
    pub(crate) fn session_fence(&self) -> io::Result<impl Future<Output = ()> + Send + use<>> {
        let observed = if self.direct {
            let registry = self.tcp.sessions().ok_or_else(closed)?;
            let neighbors = registry.subscribe();
            let generation = neighbors
                .borrow()
                .iter()
                .find(|session| session.node == self.peer)
                .map(|session| session.id)
                .ok_or_else(closed)?;
            Some((neighbors, generation))
        } else {
            None
        };
        let peer = self.peer.clone();
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
}

/// Owns the network, its connectivity endpoint and any direct bootstrap task.
pub(crate) struct Fabric {
    link: Link,
    bootstrap: Option<JoinHandle<()>>,
}

impl Fabric {
    pub(crate) async fn start(config: &PeerConfig) -> io::Result<Self> {
        let tunnels = config.tunnels()?;
        let peer = config.peer_node();
        let deadline = Instant::now() + config.limits.connect_timeout;
        let frames = StreamWindow::USB.frame_queue(&config.limits);
        let tcp = within(deadline, connectivity(config, &peer, frames)).await?;
        let started = within(
            deadline,
            NetworkConfig::default()
                .with_router(RouterConfig {
                    forwarding: false,
                    max_routes: 1,
                    max_transports: 1,
                    // Unused coordination messages are bounded and never decoded
                    // by a membership engine or retained as replicated metadata.
                    message_queue: 1,
                    tunnel_queue: frames,
                    link_queue: frames,
                    ..RouterConfig::default()
                })
                .with_link(tcp.clone().into_bound_link(1))
                .with_tunnels(tunnels)
                .bind(config.local_node()),
        )
        .await;
        let network = match started {
            Ok(network) => network,
            Err(error) => {
                tcp.close().await;
                return Err(error);
            }
        };
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
        let bootstrap = match &config.connection {
            Connection::Direct {
                peer: Some(address),
                ..
            } => Some(tokio::spawn(bootstrap(tcp.clone(), peer.clone(), *address))),
            _ => None,
        };
        Ok(Self {
            link: Link {
                network,
                tcp,
                peer,
                direct: config.is_direct(),
            },
            bootstrap,
        })
    }

    pub(crate) fn link(&self) -> &Link {
        &self.link
    }

    pub(crate) async fn closed(&self) {
        loop {
            tokio::select! {
                () = self.link.network.router().cancelled() => return,
                () = sleep(POLL) => {
                    if self.link.tcp.local_addrs().is_err() {
                        return;
                    }
                }
            }
        }
    }

    pub(crate) async fn close(mut self) {
        if let Some(bootstrap) = self.bootstrap.take() {
            bootstrap.abort();
            let _ = bootstrap.await;
        }
        self.link.network.close().await;
        self.link.tcp.close().await;
    }
}

impl Drop for Fabric {
    fn drop(&mut self) {
        if let Some(bootstrap) = &self.bootstrap {
            bootstrap.abort();
        }
    }
}

async fn connectivity(
    config: &PeerConfig,
    peer: &NodeId,
    frames: usize,
) -> io::Result<TcpMsgTransport> {
    match &config.connection {
        Connection::Direct { bind, .. } => {
            TcpMsgTransport::bind_admitted(
                config.local_node(),
                *bind,
                TcpMsgConfig {
                    max_outbound: 1,
                    // Match native connectivity's pre-allocation frame bound.
                    max_frame_bytes: groupnet::connectivity::MAX_TCP_MESSAGE,
                    outbound_queue: frames,
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
                config.local_node(),
                *address,
                network_key(key)?,
                vec![peer.clone()],
            );
            punch.bind = binds[0];
            punch.candidate_binds = binds[1..].to_vec();
            punch.max_peers = 1;
            punch.queue_capacity = frames;
            punch.policy = if *relay_only {
                PathPolicy::RelayOnly
            } else {
                PathPolicy::DirectPreferred
            };
            TcpMsgTransport::bind_connectivity(punch).await
        }
    }
}

/// Native introduction/gossip metadata is untrusted: retries restore only the
/// explicitly configured direct target.
async fn bootstrap(tcp: TcpMsgTransport, peer: NodeId, address: std::net::SocketAddr) {
    loop {
        if tcp.path_to(&peer).is_none() {
            tcp.register_peer(peer.clone(), address);
            if tcp.connect_peer(&peer).is_err() {
                return;
            }
        }
        sleep(Duration::from_secs(1)).await;
    }
}
