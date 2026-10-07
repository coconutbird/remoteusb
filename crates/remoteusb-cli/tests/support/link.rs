//! Loopback WAN emulator: one-way delay, bandwidth pacing, and bounded queues.
//!
//! Each accepted connection opens one upstream connection after an emulated
//! handshake round trip. Both directions are paced independently and own a
//! bounded pool of reusable chunks, so a slow reader applies TCP backpressure to
//! its writer instead of buffering. EOF becomes a delayed half-close; any read or
//! write error closes both sockets of that connection.

use std::ffi::OsString;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::num::NonZeroU32;
use std::ops::RangeInclusive;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::{Instant, sleep, sleep_until, timeout};

/// Round-trip time override in whole milliseconds.
pub const RTT_VARIABLE: &str = "REMOTEUSB_WAN_RTT_MS";
/// Per-direction bandwidth override in whole Mbit/s.
pub const BANDWIDTH_VARIABLE: &str = "REMOTEUSB_WAN_MBIT";

const DEFAULT_RTT_MS: u64 = 80;
const DEFAULT_MBIT: u64 = 50;
const RTT_MS: RangeInclusive<u64> = 1..=1000;
// With the maximum one-way delay this stays below the chunk-pool ceiling below.
const MBIT: RangeInclusive<u64> = 1..=1000;
const CHUNK_BYTES: usize = 16 * 1024;
// Headroom for small USB/IP messages, which occupy whole chunks while in flight.
const QUEUE_MARGIN: u64 = 64;
const CONNECT_DEADLINE: Duration = Duration::from_secs(10);
const CLOSE_DEADLINE: Duration = Duration::from_secs(10);

/// Link rate applied independently to each direction.
#[derive(Clone, Copy, Debug)]
pub struct Bandwidth {
    pub mbit: NonZeroU32,
}

impl Bandwidth {
    /// Serialization time of `bytes` on this link.
    pub fn transmit(self, bytes: usize) -> Duration {
        let bits = u64::try_from(bytes).expect("byte count fits u64") * 8;
        // bits / (mbit * 10^6) seconds == bits * 1000 / mbit nanoseconds.
        Duration::from_nanos(bits * 1000 / u64::from(self.mbit.get()))
    }

    fn bytes_per_second(self) -> u64 {
        u64::from(self.mbit.get()) * 125_000
    }
}

/// Validated WAN characteristics.
#[derive(Clone, Copy, Debug)]
pub struct Profile {
    pub rtt: Duration,
    pub bandwidth: Bandwidth,
}

impl Profile {
    /// Reads `RTT_VARIABLE` and `BANDWIDTH_VARIABLE` through `lookup`; unset
    /// values use 80 ms and 50 Mbit/s. Invalid values are errors, never defaults.
    pub fn from_lookup(lookup: impl Fn(&'static str) -> Option<OsString>) -> io::Result<Self> {
        let rtt_ms = bounded(RTT_VARIABLE, lookup(RTT_VARIABLE), DEFAULT_RTT_MS, &RTT_MS)?;
        let mbit = bounded(
            BANDWIDTH_VARIABLE,
            lookup(BANDWIDTH_VARIABLE),
            DEFAULT_MBIT,
            &MBIT,
        )?;
        Ok(Self {
            rtt: Duration::from_millis(rtt_ms),
            bandwidth: Bandwidth {
                mbit: u32::try_from(mbit)
                    .ok()
                    .and_then(NonZeroU32::new)
                    .expect("validated bandwidth range"),
            },
        })
    }

    fn one_way(self) -> Duration {
        self.rtt / 2
    }

    /// Chunks needed to keep one direction's bandwidth-delay product in flight.
    fn queue_chunks(self) -> usize {
        let in_flight =
            u128::from(self.bandwidth.bytes_per_second()) * self.one_way().as_micros() / 1_000_000;
        let chunks = u64::try_from(in_flight)
            .expect("validated profile bounds in-flight bytes")
            .div_ceil(u64::try_from(CHUNK_BYTES).expect("chunk size fits u64"));
        usize::try_from(chunks + QUEUE_MARGIN).expect("validated profile bounds the queue")
    }
}

fn bounded(
    name: &str,
    value: Option<OsString>,
    default: u64,
    range: &RangeInclusive<u64>,
) -> io::Result<u64> {
    let Some(value) = value else {
        return Ok(default);
    };
    value
        .to_str()
        .and_then(|text| text.trim().parse::<u64>().ok())
        .filter(|number| range.contains(number))
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "{name} must be a whole number from {} to {}",
                    range.start(),
                    range.end()
                ),
            )
        })
}

/// TCP proxy on an ephemeral loopback port. Dropping it aborts every task;
/// [`WanLink::close`] also waits for them.
pub struct WanLink {
    address: SocketAddr,
    stop: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<io::Result<()>>>,
}

impl WanLink {
    /// Listens on `127.0.0.1:0` and forwards every connection to `target`.
    pub async fn start(target: SocketAddr, profile: Profile) -> io::Result<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let (stop, stopped) = oneshot::channel();
        let task = tokio::spawn(serve(listener, target, profile, stopped));
        Ok(Self {
            address,
            stop: Some(stop),
            task: Some(task),
        })
    }

    /// Address that clients use instead of the target.
    pub fn address(&self) -> SocketAddr {
        self.address
    }

    /// Stops accepting, aborts open connections, and joins all tasks.
    pub async fn close(mut self) -> io::Result<()> {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        let Some(task) = self.task.as_mut() else {
            return Ok(());
        };
        let joined = timeout(CLOSE_DEADLINE, task)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "WAN emulator did not stop"))?;
        self.task = None;
        joined.map_err(io::Error::other)?
    }
}

impl Drop for WanLink {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

async fn serve(
    listener: TcpListener,
    target: SocketAddr,
    profile: Profile,
    mut stopped: oneshot::Receiver<()>,
) -> io::Result<()> {
    // Aborting this task drops the set, which aborts every connection.
    let mut connections = JoinSet::new();
    let result = loop {
        tokio::select! {
            _ = &mut stopped => break Ok(()),
            accepted = listener.accept() => match accepted {
                Ok((client, _)) => {
                    connections.spawn(relay(client, target, profile));
                }
                Err(error) => break Err(error),
            },
            Some(finished) = connections.join_next(), if !connections.is_empty() => {
                match finished {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => eprintln!("[wan] connection closed: {error}"),
                    Err(error) => break Err(io::Error::other(error)),
                }
            }
        }
    };
    connections.shutdown().await;
    result
}

async fn relay(client: TcpStream, target: SocketAddr, profile: Profile) -> io::Result<()> {
    // Emulate the TCP handshake round trip before the first byte can cross.
    sleep(profile.rtt).await;
    let upstream = timeout(CONNECT_DEADLINE, TcpStream::connect(target))
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "WAN emulator upstream connection timed out",
            )
        })??;
    client.set_nodelay(true)?;
    upstream.set_nodelay(true)?;
    let (client_read, client_write) = client.into_split();
    let (upstream_read, upstream_write) = upstream.into_split();
    tokio::try_join!(
        direction(client_read, upstream_write, profile),
        direction(upstream_read, client_write, profile),
    )?;
    Ok(())
}

struct Packet {
    chunk: Box<[u8]>,
    len: usize,
    arrival: Instant,
}

async fn direction(
    mut source: OwnedReadHalf,
    mut sink: OwnedWriteHalf,
    profile: Profile,
) -> io::Result<()> {
    let capacity = profile.queue_chunks();
    let (in_flight, mut arrivals) = mpsc::channel::<Packet>(capacity);
    let (recycle, mut recycled) = mpsc::channel::<Box<[u8]>>(capacity);
    let forward = async move {
        let mut allocated = 0;
        let mut link_free = Instant::now();
        loop {
            // Allocate lazily up to the pool size, then wait for delivered chunks.
            let mut chunk = match recycled.try_recv() {
                Ok(chunk) => chunk,
                Err(_) if allocated < capacity => {
                    allocated += 1;
                    vec![0; CHUNK_BYTES].into_boxed_slice()
                }
                Err(_) => match recycled.recv().await {
                    Some(chunk) => chunk,
                    None => return Ok(()),
                },
            };
            let len = source.read(&mut chunk).await?;
            if len == 0 {
                // Dropping the sender lets delivery drain, then half-close.
                return Ok(());
            }
            let departure = link_free.max(Instant::now()) + profile.bandwidth.transmit(len);
            link_free = departure;
            let packet = Packet {
                chunk,
                len,
                arrival: departure + profile.one_way(),
            };
            if in_flight.send(packet).await.is_err() {
                return Ok(());
            }
        }
    };
    let deliver = async move {
        while let Some(packet) = arrivals.recv().await {
            sleep_until(packet.arrival).await;
            sink.write_all(&packet.chunk[..packet.len]).await?;
            // The pool never exceeds the channel capacity; a closed reader drops it.
            let _ = recycle.try_send(packet.chunk);
        }
        sink.shutdown().await
    };
    tokio::try_join!(forward, deliver)?;
    Ok(())
}
