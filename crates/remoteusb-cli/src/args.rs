//! Direct-first CLI configuration with independently provisioned peer identities.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::num::{NonZeroU64, NonZeroUsize};
use std::path::PathBuf;
use std::time::Duration;

use clap::{Args, Parser, Subcommand};
use remoteusb_transport::{Connection, Limits, PeerConfig};

#[derive(Parser)]
#[command(
    name = "remoteusb",
    version,
    about = "Authenticated USB/IP connections and receiver-owned attachments"
)]
pub(super) struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub(super) enum Command {
    /// Generate endpoint credentials in a new protected directory.
    Init(InitArgs),
    /// Run optional keyed rendezvous and relay infrastructure.
    Rendezvous(RendezvousArgs),
    /// Export a loopback USB/IP backend over authenticated Groupnet streams.
    Serve(ServeArgs),
    /// Keep a foreground connection, optionally attaching one device.
    Connect(ConnectArgs),
    /// List devices exported by a peer; no USB/IP driver required.
    List(EndpointArgs),
    /// Attach a device and keep its receiving process alive until disconnected.
    Attach(AttachArgs),
    #[command(name = "__attachment-supervisor", hide = true)]
    Supervisor {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        arguments: Vec<String>,
    },
}

#[derive(Args)]
pub(super) struct InitArgs {
    #[arg(long, value_name = "DIR")]
    pub out: PathBuf,
}

#[derive(Args)]
pub(super) struct RendezvousArgs {
    #[arg(long, default_value = "127.0.0.1:7443")]
    pub listen: SocketAddr,
    /// Defaults to credentials beside the executable.
    #[arg(long, value_name = "DIR")]
    pub credentials: Option<PathBuf>,
    #[arg(long, default_value = "exporter")]
    pub exporter_id: String,
    #[arg(long, default_value = "receiver")]
    pub receiver_id: String,
}

#[derive(Args)]
pub(super) struct CommonArgs {
    /// Optional keyed discovery/relay address. Without this, use direct TCP.
    #[arg(long, value_name = "IP:PORT")]
    pub rendezvous: Option<SocketAddr>,
    /// Defaults to credentials beside the executable, not the working directory.
    #[arg(long, value_name = "DIR")]
    pub credentials: Option<PathBuf>,
    /// Override this endpoint's provisioned node ID.
    #[arg(long)]
    pub local_id: Option<String>,
    /// TCP candidate binds for rendezvous mode only; repeat for multiple interfaces.
    #[arg(long, requires = "rendezvous", value_name = "IP:PORT")]
    pub candidate_bind: Vec<SocketAddr>,
    /// Force relay mode; requires --rendezvous.
    #[arg(long, requires = "rendezvous")]
    pub relay_only: bool,
    #[arg(long, default_value = "64")]
    pub max_connections: NonZeroUsize,
    #[arg(long, default_value = "10")]
    pub connect_timeout_secs: NonZeroU64,
}

#[derive(Args)]
pub(super) struct ServeArgs {
    #[arg(long, default_value = "127.0.0.1:3240")]
    pub backend: SocketAddr,
    /// Direct authenticated listener; default 0.0.0.0:7443. Not used with rendezvous.
    #[arg(long, conflicts_with = "rendezvous", value_name = "IP:PORT")]
    pub listen: Option<SocketAddr>,
    #[arg(long, default_value = "receiver")]
    pub peer_id: String,
    #[command(flatten)]
    pub common: CommonArgs,
}

#[derive(Args)]
pub(super) struct EndpointArgs {
    /// Exporter IP[:port] (default 7443), or peer node ID with --rendezvous.
    pub target: String,
    /// Provisioned exporter node ID in direct mode (default exporter).
    #[arg(long, conflicts_with = "rendezvous")]
    pub peer_id: Option<String>,
    #[command(flatten)]
    pub common: CommonArgs,
}

#[derive(Args)]
pub(super) struct ConnectArgs {
    #[command(flatten)]
    pub endpoint: EndpointArgs,
    /// Optional local USB/IP listener. Default: unused loopback port.
    #[arg(long, default_value = "127.0.0.1:0")]
    pub listen: SocketAddr,
    /// Attach once and supervise cleanup when the receiver exits.
    #[arg(long, value_name = "BUSID")]
    pub attach: Option<String>,
    #[arg(long, requires = "attach", value_name = "EXE")]
    pub usbip: Option<PathBuf>,
}

#[derive(Args)]
pub(super) struct AttachArgs {
    #[command(flatten)]
    pub endpoint: EndpointArgs,
    pub busid: String,
    /// Override the installed Windows usbip-win2 executable.
    #[arg(long, value_name = "EXE")]
    pub usbip: Option<PathBuf>,
}

pub(super) fn credential_directory(explicit: Option<PathBuf>) -> io::Result<PathBuf> {
    explicit.map_or_else(
        || {
            let executable = std::env::current_exe()?;
            let parent = executable
                .parent()
                .ok_or_else(|| io::Error::other("executable has no parent directory"))?;
            Ok(parent.join("credentials"))
        },
        Ok,
    )
}

pub(super) fn direct_address(target: &str) -> io::Result<SocketAddr> {
    let address = target
        .parse::<SocketAddr>()
        .or_else(|_| target.parse::<IpAddr>().map(|ip| SocketAddr::new(ip, 7443)))
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "direct target must be an IP or IP:port; use a peer node ID with --rendezvous",
            )
        })?;
    if address.port() == 0
        || address.ip().is_unspecified()
        || address.ip().is_multicast()
        || address.ip() == IpAddr::V4(Ipv4Addr::BROADCAST)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid direct peer address",
        ));
    }
    Ok(address)
}

impl CommonArgs {
    pub(super) fn config(
        self,
        peer_id: String,
        exporter: bool,
        direct: Option<Connection>,
    ) -> io::Result<PeerConfig> {
        let credentials = credential_directory(self.credentials)?;
        let (identity, peer) = if exporter {
            ("exporter", "receiver")
        } else {
            ("receiver", "exporter")
        };
        let connection = match self.rendezvous {
            Some(address) => {
                let binds = if self.candidate_bind.is_empty() {
                    vec![SocketAddr::new(
                        if address.is_ipv4() {
                            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
                        } else {
                            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
                        },
                        0,
                    )]
                } else {
                    self.candidate_bind
                };
                Connection::Rendezvous {
                    address,
                    key: credentials.join("network.key"),
                    binds,
                    relay_only: self.relay_only,
                }
            }
            None => direct.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "missing direct connection configuration",
                )
            })?,
        };
        Ok(PeerConfig {
            local_id: self.local_id.unwrap_or_else(|| identity.into()),
            peer_id,
            ca: credentials.join("ca.pem"),
            cert: credentials.join(format!("{identity}.pem")),
            key: credentials.join(format!("{identity}.key")),
            peer_cert: credentials.join(format!("{peer}.pem")),
            connection,
            limits: Limits {
                max_connections: self.max_connections.get(),
                connect_timeout: Duration::from_secs(self.connect_timeout_secs.get()),
            },
        })
    }
}

impl EndpointArgs {
    pub(super) fn config(self) -> io::Result<PeerConfig> {
        if self.common.rendezvous.is_some() {
            self.common.config(self.target, false, None)
        } else {
            let address = direct_address(&self.target)?;
            let bind = SocketAddr::new(
                if address.is_ipv4() {
                    IpAddr::V4(Ipv4Addr::UNSPECIFIED)
                } else {
                    IpAddr::V6(Ipv6Addr::UNSPECIFIED)
                },
                0,
            );
            self.common.config(
                self.peer_id.unwrap_or_else(|| "exporter".into()),
                false,
                Some(Connection::Direct {
                    bind,
                    peer: Some(address),
                }),
            )
        }
    }
}
