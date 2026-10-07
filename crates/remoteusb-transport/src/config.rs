//! Independently provisioned endpoint identity, connection mode and resource bounds.

use std::fs::File;
use std::io::{self, BufReader};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use groupnet::connectivity::NetworkKey;
use groupnet::core::NodeId;
use groupnet::network::TunnelConfig;
use groupnet::network::tunnel::{PeerIdentity, TlsIdentity};
use rustls::pki_types::CertificateDer;

use crate::flow::StreamWindow;

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
    pub(crate) fn validate(&self) -> io::Result<()> {
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

    pub(crate) fn local_node(&self) -> NodeId {
        NodeId::new(self.local_id.as_str())
    }

    pub(crate) fn peer_node(&self) -> NodeId {
        NodeId::new(self.peer_id.as_str())
    }

    pub(crate) fn is_direct(&self) -> bool {
        matches!(self.connection, Connection::Direct { .. })
    }

    /// Loads every credential before any socket is bound or connected.
    pub(crate) fn tunnels(&self) -> io::Result<TunnelConfig> {
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
        let limits = StreamWindow::USB.tunnel_limits(&self.limits);
        limits.validate()?;
        Ok(TunnelConfig::new(
            identity,
            [PeerIdentity::new(self.peer_node(), peer[0].as_ref())?],
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

pub(crate) fn validate_ids(ids: &[&str]) -> io::Result<()> {
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

pub(crate) fn network_key(path: &Path) -> io::Result<NetworkKey> {
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

pub(crate) fn invalid_ip(ip: IpAddr) -> bool {
    ip.is_multicast() || matches!(ip, IpAddr::V4(address) if address.is_broadcast())
}

pub(crate) fn invalid_input(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, error.to_string())
}
