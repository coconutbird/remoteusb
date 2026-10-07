//! Tunnel admission bounds and the queue sizing derived from them.
//!
//! Groupnet owns tunnel flow control: slow start over a bounded window, with
//! receive limits independent of the peer's segment size. remoteusb sets only
//! its admission bounds. Every endpoint queue that drops when full (router link
//! queues, TCP and punch outbound queues) holds Groupnet's derived
//! per-session packet queue for every admitted stream, so a full window is never
//! dropped locally and mistaken for congestion. The relay's per-session queue
//! backpressures instead of dropping and uses the same sizing to avoid stalls.

use std::num::NonZeroUsize;

use groupnet::network::tunnel::TunnelLimits;
use groupnet::transport::QueueCapacity;

use crate::Limits;

/// Groupnet's default tunnel policy, admitting one exclusive peer with
/// `max_connections` concurrent sessions. The node memory budget grows with
/// the configured session count so every session's guaranteed floor fits.
pub(crate) fn tunnel_limits(limits: &Limits) -> TunnelLimits {
    /// Each session keeps a guaranteed floor in both directions.
    const DIRECTIONS: NonZeroUsize = NonZeroUsize::new(2).unwrap();
    let sessions = limits.max_connections.get_nonzero();
    let defaults = TunnelLimits::default();
    let floor = NonZeroUsize::try_from(defaults.min_window).unwrap_or(NonZeroUsize::MAX);
    let floors = sessions.saturating_mul(DIRECTIONS).saturating_mul(floor);
    TunnelLimits {
        max_peers: NonZeroUsize::MIN,
        max_sessions: sessions,
        sessions_per_peer: sessions,
        accept_queue: limits.max_connections,
        setup_timeout: limits.connect_timeout,
        memory_budget: defaults.memory_budget.max(floors),
        ..defaults
    }
}

/// Frames every admitted stream can enqueue at once on a node-wide queue.
pub(crate) fn frame_queue(limits: &Limits) -> QueueCapacity {
    tunnel_limits(limits)
        .packet_queue()
        .saturating_mul(limits.max_connections.get())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admitted_streams_cannot_overflow_shared_queues() {
        for connections in [1, 64, 4096] {
            let limits = Limits {
                max_connections: QueueCapacity::of(connections),
                ..Limits::default()
            };
            let tunnel = tunnel_limits(&limits);
            assert!(tunnel.validate().is_ok());
            let frames = tunnel.stream_frames().saturating_mul(connections);
            assert!(frame_queue(&limits).get() >= frames.min(QueueCapacity::MAX.get()));
        }
    }
}
