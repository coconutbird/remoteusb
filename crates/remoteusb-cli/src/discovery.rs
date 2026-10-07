//! Discover connected devices without sharing or attaching them.

use std::future::Future;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};

use remoteusb_transport::{PeerConfig, run_client};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

use crate::inventory::{self, Device};

async fn query(address: SocketAddr) -> io::Result<Vec<Device>> {
    let mut socket = TcpStream::connect(address).await?;
    socket.write_all(&inventory::REQUEST).await?;
    inventory::receive(&mut socket).await.map_err(|error| {
        io::Error::new(
            error.kind(),
            format!(
                "cannot read managed device inventory; update both remoteusb endpoints: {error}"
            ),
        )
    })
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
        println!("BUSID\tVID:PID\tSTATUS\tNAME");
        for device in devices {
            let status = if device.busy {
                "Busy"
            } else if device.shared {
                "Shared"
            } else {
                "Available"
            };
            println!(
                "{}\t{:04x}:{:04x}\t{status}\t{}",
                device.busid,
                device.vendor,
                device.product,
                inventory::display_name(&device)
            );
        }
    }
    Ok(())
}
