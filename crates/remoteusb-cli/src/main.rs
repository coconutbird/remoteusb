//! Foreground command-line entry point for authenticated Groupnet USB/IP streams.

mod credentials;

use std::io;
use std::net::SocketAddr;
use std::num::{NonZeroU64, NonZeroUsize};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::{Args, Parser, Subcommand};
use remoteusb_transport::{Limits, PeerConfig, run_client, run_rendezvous, run_server};
use tokio::net::TcpListener;

/// Run USB/IP streams over authenticated Groupnet direct or relayed connections.
#[derive(Parser)]
#[command(name = "remoteusb", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

/// The role of this foreground process.
#[derive(Subcommand)]
enum Command {
    /// Generate a private CA, two endpoint identities, and a rendezvous network key.
    Init(InitArgs),
    /// Run keyed rendezvous and relay for the two authorized endpoint IDs.
    Rendezvous(RendezvousArgs),
    /// Accept authorized Groupnet streams and forward to a local USB/IP exporter.
    Serve(ServeArgs),
    /// Expose a loopback USB/IP endpoint forwarded to the authorized exporter.
    Connect(ConnectArgs),
}

/// Provisioning configuration.
#[derive(Args)]
struct InitArgs {
    /// New credentials directory; must not already exist (even if empty).
    #[arg(long, value_name = "DIR")]
    out: PathBuf,
}

/// Keyed rendezvous configuration; no endpoint private keys are needed.
#[derive(Args)]
struct RendezvousArgs {
    /// Rendezvous listen address; choose a reachable public address explicitly.
    #[arg(long, default_value = "127.0.0.1:7443")]
    listen: SocketAddr,

    /// Directory containing network.key; no other credential files are read.
    #[arg(long, value_name = "DIR")]
    credentials: PathBuf,

    /// Authorized exporter node ID; match serve's local ID.
    #[arg(long, default_value = "exporter")]
    exporter_id: String,

    /// Authorized receiver node ID; match connect's local ID.
    #[arg(long, default_value = "receiver")]
    receiver_id: String,
}

/// Routing, credentials, and resource bounds shared by both endpoint roles.
#[derive(Args)]
struct CommonArgs {
    /// Rendezvous IP address and port (not a DNS name).
    #[arg(long, value_name = "IP:PORT")]
    rendezvous: SocketAddr,

    /// Directory containing this role's key, CA, both public leaves, and network.key.
    #[arg(long, value_name = "DIR")]
    credentials: PathBuf,

    /// Local TCP candidate bind address; repeat for multiple interfaces.
    #[arg(long, default_value = "0.0.0.0:0", value_name = "IP:PORT")]
    candidate_bind: Vec<SocketAddr>,

    /// Force relayed streams instead of preferring direct hole-punched connections.
    #[arg(long)]
    relay_only: bool,

    /// Maximum simultaneous USB/IP streams, including pending setup.
    #[arg(long, default_value = "64")]
    max_connections: NonZeroUsize,

    /// Stream setup timeout in seconds; not an idle-device timeout.
    #[arg(long, default_value = "10")]
    connect_timeout_secs: NonZeroU64,
}

impl CommonArgs {
    /// Select credential files by fixed endpoint role, not by user-chosen node IDs.
    fn peer_config(self, local_id: String, peer_id: String, exporter: bool) -> PeerConfig {
        let (identity, peer) = if exporter {
            ("exporter", "receiver")
        } else {
            ("receiver", "exporter")
        };
        PeerConfig {
            local_id,
            peer_id,
            rendezvous: self.rendezvous,
            ca: self.credentials.join("ca.pem"),
            cert: self.credentials.join(format!("{identity}.pem")),
            key: self.credentials.join(format!("{identity}.key")),
            peer_cert: self.credentials.join(format!("{peer}.pem")),
            network_key: self.credentials.join("network.key"),
            candidate_binds: self.candidate_bind,
            relay_only: self.relay_only,
            limits: Limits {
                max_connections: self.max_connections.get(),
                connect_timeout: Duration::from_secs(self.connect_timeout_secs.get()),
            },
        }
    }
}

/// Exporter-side configuration.
#[derive(Args)]
struct ServeArgs {
    /// Existing USB/IP exporter endpoint; must be a loopback address.
    #[arg(long, default_value = "127.0.0.1:3240")]
    backend: SocketAddr,

    /// Local Groupnet node ID; must be allowlisted by rendezvous.
    #[arg(long, default_value = "exporter")]
    local_id: String,

    /// Exact authorized receiver Groupnet node ID.
    #[arg(long, default_value = "receiver")]
    peer_id: String,

    #[command(flatten)]
    common: CommonArgs,
}

/// Receiver-side configuration.
#[derive(Args)]
struct ConnectArgs {
    /// Local USB/IP listen address; must be a loopback address.
    #[arg(long, default_value = "127.0.0.1:3240")]
    listen: SocketAddr,

    /// Local Groupnet node ID; must be allowlisted by rendezvous.
    #[arg(long, default_value = "receiver")]
    local_id: String,

    /// Exact authorized exporter Groupnet node ID.
    #[arg(long, default_value = "exporter")]
    peer_id: String,

    #[command(flatten)]
    common: CommonArgs,
}

/// Bind an endpoint and announce the actual address, including ephemeral ports.
async fn bind(address: SocketAddr) -> io::Result<TcpListener> {
    let listener = TcpListener::bind(address).await?;
    eprintln!("USB/IP listener on {}", listener.local_addr()?);
    Ok(listener)
}

/// Enforce the local plaintext boundary before creating a listener.
fn require_loopback(address: SocketAddr, option: &str) -> io::Result<()> {
    if address.ip().is_loopback() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{option} must be a loopback address"),
        ))
    }
}

/// Execute one role and propagate shutdown-handler failures as fatal errors.
async fn execute(command: Command) -> io::Result<()> {
    let mut signal_error = None;
    let shutdown = async {
        signal_error = tokio::signal::ctrl_c().await.err();
    };

    let result = match command {
        Command::Init(args) => {
            drop(shutdown);
            credentials::initialize(&args.out)
        }
        Command::Rendezvous(args) => {
            run_rendezvous(
                args.listen,
                &args.credentials.join("network.key"),
                vec![args.exporter_id, args.receiver_id],
                shutdown,
            )
            .await
        }
        Command::Serve(args) => {
            require_loopback(args.backend, "--backend")?;
            let config = args.common.peer_config(args.local_id, args.peer_id, true);
            run_server(config, args.backend, shutdown).await
        }
        Command::Connect(args) => {
            require_loopback(args.listen, "--listen")?;
            let config = args.common.peer_config(args.local_id, args.peer_id, false);
            let listener = bind(args.listen).await?;
            run_client(listener, config, shutdown).await
        }
    };

    if let Some(error) = signal_error {
        return Err(io::Error::other(format!("Ctrl-C handler failed: {error}")));
    }
    result
}

/// Parse arguments, run until interrupted, and report fatal errors without secrets.
#[tokio::main]
async fn main() -> ExitCode {
    match execute(Cli::parse().command).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("remoteusb: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests;
