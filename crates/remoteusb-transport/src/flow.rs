//! One flow policy sizes every queue on a USB/IP stream's path.
//!
//! remoteusb tunnels always ride reliable TCP (direct, punched or relayed), so
//! TCP owns congestion control. Groupnet's tunnel window is therefore a bounded
//! in-flight and receive allowance sized for long-latency USB/IP round trips,
//! not a second congestion controller that starts tiny and grows per round trip.
//! Every endpoint queue that drops when full (router link and tunnel queues,
//! per-session packet inboxes, TCP and punch outbound queues) holds a full
//! window of segments plus acknowledgements for every admitted stream: a local
//! drop is indistinguishable from loss and triggers retransmission backoff.
//! The relay's per-session queue backpressures instead of dropping and uses the
//! same sizing to avoid stalls.

use std::time::Duration;

use groupnet::network::tunnel::TunnelLimits;

use crate::Limits;

/// Bounded per-stream, per-direction in-flight allowance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct StreamWindow {
    /// Ciphertext bytes per reliability segment; well below the 65,000-byte
    /// routing envelope so headers always fit.
    segment: usize,
    /// Segments in flight and buffered for delivery in each direction.
    segments: usize,
}

impl StreamWindow {
    /// 2 MiB per direction: about 200 Mbit/s at 80 ms round-trip time, with
    /// 64 KiB USB/IP transfers carried in two segments.
    pub(crate) const USB: Self = Self {
        segment: 32 * 1024,
        segments: 64,
    };

    /// Frames one stream can enqueue per direction: a window of data, a window
    /// of acknowledgements for the reverse direction, and retransmission headroom.
    const fn frames_per_stream(self) -> usize {
        self.segments * 4
    }

    /// Node-wide frame capacity for every concurrently admitted stream.
    pub(crate) fn frame_queue(self, limits: &Limits) -> usize {
        self.frames_per_stream()
            .saturating_mul(limits.max_connections)
            .min(tokio::sync::Semaphore::MAX_PERMITS)
    }

    /// Tunnel limits for one exclusive peer. Retransmission timers are
    /// conservative because only local queue drops are repaired: a spurious
    /// timeout over TCP duplicates data and halves the window.
    pub(crate) fn tunnel_limits(self, limits: &Limits) -> TunnelLimits {
        TunnelLimits {
            max_peers: 1,
            max_sessions: limits.max_connections,
            sessions_per_peer: limits.max_connections,
            accept_queue: limits.max_connections,
            packet_queue: self.frames_per_stream(),
            stream_buffer: self.segment * 8,
            payload: self.segment,
            window: self.segments,
            initial_congestion: self.segments,
            setup_timeout: limits.connect_timeout,
            initial_rto: Duration::from_secs(1),
            min_rto: Duration::from_millis(250),
            max_rto: Duration::from_secs(4),
            ..TunnelLimits::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usb_window_is_valid_and_covers_every_admitted_stream() {
        let limits = Limits::default();
        let window = StreamWindow::USB;
        assert!(window.tunnel_limits(&limits).validate().is_ok());
        let tunnel = window.tunnel_limits(&limits);
        assert!(tunnel.packet_queue >= 2 * tunnel.window);
        assert!(window.frame_queue(&limits) >= limits.max_connections * 2 * tunnel.window);
    }
}
