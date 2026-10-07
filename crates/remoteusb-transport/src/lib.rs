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
//! Every link is reliable TCP, so tunnel flow control is a fixed bounded window
//! sized for long-latency USB/IP round trips rather than a second congestion loop.

mod config;
mod fabric;
mod flow;
mod session;

use std::io;
use std::net::SocketAddr;
use std::path::Path;

use groupnet::connectivity::{TcpRendezvous, TcpRendezvousConfig};
use groupnet::core::NodeId;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::time::sleep;

pub use config::{Connection, Limits, PeerConfig};

/// The protocol contract for peers built directly on Groupnet.
///
/// Both endpoints must exchange [`PREAMBLE`](wire::PREAMBLE) inside pinned TLS
/// and use identical [`tunnel_limits`](wire::tunnel_limits): a peer with a
/// smaller segment bound discards remoteusb segments and cannot complete TLS.
pub mod wire {
    use groupnet::network::tunnel::TunnelLimits;

    use crate::Limits;
    use crate::flow::StreamWindow;

    pub use crate::session::PREAMBLE;

    /// Tunnel limits remoteusb applies for the given endpoint bounds.
    #[must_use]
    pub fn tunnel_limits(limits: &Limits) -> TunnelLimits {
        StreamWindow::USB.tunnel_limits(limits)
    }
}

use config::{invalid_input, invalid_ip, network_key, validate_ids};
use fabric::POLL;
use flow::StreamWindow;
use session::{Exporter, Receiver, TaskStatus, serve};

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
    serve(
        &config,
        Exporter { backend },
        shutdown,
        TaskStatus::default(),
    )
    .await
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
    client(listener, config, shutdown, TaskStatus::default()).await
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
    client(listener, config, shutdown, TaskStatus::new(status)).await
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
    serve(&config, Receiver::new(listener), shutdown, status).await
}

/// Hosts keyed TCP rendezvous, traversal coordination and encrypted-stream relay.
///
/// The relay carries Groupnet ciphertext, not plaintext USB/IP. Only the explicit
/// nonempty node allowlist and shared key are admitted; there is no open mode.
/// The assigned address is logged, including an ephemeral port when requested.
/// Relay queues use the same stream window as endpoints.
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
    let rendezvous = TcpRendezvous::bind_config(
        listen,
        network_key(key)?,
        peers.into_iter().map(NodeId::new).collect(),
        TcpRendezvousConfig {
            session_queue: StreamWindow::USB.frame_queue(&Limits::default()),
            ..TcpRendezvousConfig::default()
        },
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
