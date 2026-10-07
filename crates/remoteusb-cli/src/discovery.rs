//! Bounded USB/IP device discovery through the authenticated local tunnel.

use std::future::Future;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};

use remoteusb_transport::{PeerConfig, run_client};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

const REQUEST: [u8; 8] = [0x01, 0x11, 0x80, 0x05, 0, 0, 0, 0];
const MAX_DEVICES: u32 = 1024;

#[derive(Debug, PartialEq, Eq)]
struct Device {
    busid: String,
    vendor: u16,
    product: u16,
    class: u8,
    interfaces: u8,
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

async fn decode(reader: &mut (impl AsyncRead + Unpin)) -> io::Result<Vec<Device>> {
    let mut header = [0; 12];
    reader.read_exact(&mut header).await?;
    if header[..4] != [0x01, 0x11, 0, 0x05] {
        return Err(invalid("invalid USB/IP device-list version or reply code"));
    }
    if header[4..8] != [0; 4] {
        return Err(io::Error::other("USB/IP backend rejected device discovery"));
    }
    let count = u32::from_be_bytes(header[8..12].try_into().expect("four bytes"));
    if count > MAX_DEVICES {
        return Err(invalid("USB/IP device list exceeds 1024 devices"));
    }
    let mut devices = Vec::with_capacity(usize::try_from(count).expect("bounded count"));
    for _ in 0..count {
        let mut record = [0; 312];
        reader.read_exact(&mut record).await?;
        let id = &record[256..288];
        let end = id
            .iter()
            .position(|byte| *byte == 0)
            .ok_or_else(|| invalid("unterminated USB/IP BUSID"))?;
        if end == 0
            || !id[..end]
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'.' | b'_'))
        {
            return Err(invalid("invalid USB/IP BUSID"));
        }
        let device = Device {
            busid: String::from_utf8(id[..end].to_vec())
                .map_err(|_| invalid("invalid USB/IP BUSID"))?,
            vendor: u16::from_be_bytes([record[300], record[301]]),
            product: u16::from_be_bytes([record[302], record[303]]),
            class: record[306],
            interfaces: record[311],
        };
        for _ in 0..device.interfaces {
            let mut interface = [0; 4];
            reader.read_exact(&mut interface).await?;
        }
        devices.push(device);
    }
    Ok(devices)
}

async fn query(address: SocketAddr) -> io::Result<Vec<Device>> {
    let mut socket = TcpStream::connect(address).await?;
    socket.write_all(&REQUEST).await?;
    decode(&mut socket).await
}

pub(super) async fn run(config: PeerConfig, shutdown: impl Future<Output = ()>) -> io::Result<()> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let deadline = config.limits.connect_timeout;
    let (stop, stopped) = oneshot::channel();
    let mut tunnel = tokio::spawn(run_client(listener, config, async {
        let _ = stopped.await;
    }));
    tokio::pin!(shutdown);
    let mut finished = None;
    let listed = tokio::select! {
        () = &mut shutdown => Ok(None),
        result = &mut tunnel => { finished = Some(result); Err(io::Error::other("connection ended before device discovery completed")) },
        result = tokio::time::timeout(deadline, query(address)) => result
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "device discovery timed out"))
            .and_then(|result| result).map(Some),
    };
    let _ = stop.send(());
    match finished {
        Some(result) => result,
        None => tunnel.await,
    }
    .map_err(io::Error::other)??;
    if let Some(devices) = listed? {
        println!("BUSID\tVID:PID\tCLASS\tINTERFACES");
        for device in devices {
            println!(
                "{}\t{:04x}:{:04x}\t{:02x}\t{}",
                device.busid, device.vendor, device.product, device.class, device.interfaces
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{Device, MAX_DEVICES, decode};

    fn reply(count: u32) -> Vec<u8> {
        let mut reply = vec![1, 0x11, 0, 5, 0, 0, 0, 0];
        reply.extend_from_slice(&count.to_be_bytes());
        reply
    }

    #[tokio::test]
    async fn composite_interfaces_do_not_misalign_the_next_device() {
        let mut bytes = reply(2);
        for (bus, interfaces) in [(b"12-4", 3), (b"13-1", 1)] {
            let mut record = [0; 312];
            record[256..260].copy_from_slice(bus);
            record[300..304].copy_from_slice(&[0x10, 0x50, 4, 7]);
            record[311] = interfaces;
            bytes.extend_from_slice(&record);
            for _ in 0..interfaces {
                bytes.extend_from_slice(&[3, 0, 0, 0]);
            }
        }
        assert_eq!(
            decode(&mut bytes.as_slice()).await.unwrap(),
            vec![
                Device {
                    busid: "12-4".into(),
                    vendor: 0x1050,
                    product: 0x0407,
                    class: 0,
                    interfaces: 3
                },
                Device {
                    busid: "13-1".into(),
                    vendor: 0x1050,
                    product: 0x0407,
                    class: 0,
                    interfaces: 1
                },
            ]
        );
    }

    #[tokio::test]
    async fn malformed_lists_cannot_allocate_unbounded_memory_or_print_control_sequences() {
        assert!(
            decode(&mut reply(MAX_DEVICES + 1).as_slice())
                .await
                .is_err()
        );
        let mut bytes = reply(1);
        let mut record = [0; 312];
        record[256..260].copy_from_slice(b"\x1b[2J");
        bytes.extend_from_slice(&record);
        assert!(decode(&mut bytes.as_slice()).await.is_err());
        record[256..288].fill(b'1');
        bytes.truncate(12);
        bytes.extend_from_slice(&record);
        assert!(decode(&mut bytes.as_slice()).await.is_err());
    }

    #[tokio::test]
    async fn truncated_interfaces_and_error_replies_are_not_reported_as_success() {
        let mut bytes = reply(1);
        let mut record = [0; 312];
        record[256..259].copy_from_slice(b"1-2");
        record[311] = 1;
        bytes.extend_from_slice(&record);
        assert!(decode(&mut bytes.as_slice()).await.is_err());
        let mut denied = reply(0);
        denied[7] = 1;
        assert!(decode(&mut denied.as_slice()).await.is_err());
        let mut wrong = reply(0);
        wrong[3] = 3;
        assert!(decode(&mut wrong.as_slice()).await.is_err());
    }
}
