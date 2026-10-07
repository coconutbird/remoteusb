//! Host device policy and on-demand sharing stay outside the transport layer.

mod backend;
mod platform;

use std::collections::BTreeSet;
use std::future::Future;
use std::io::{self, BufRead, IsTerminal, Read, Write};
use std::net::{Ipv4Addr, SocketAddr};

use remoteusb_transport::{Connection, run_server};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

use crate::args::ServeArgs;
use crate::inventory::{self, Device};
use crate::usbip::BusId;
use platform::DeviceHost as _;

fn select_devices(text: &str, devices: &[Device]) -> io::Result<BTreeSet<BusId>> {
    let mut selected = BTreeSet::new();
    for item in text
        .split(|character: char| character == ',' || character.is_whitespace())
        .filter(|item| !item.is_empty())
    {
        let index = item
            .parse::<usize>()
            .ok()
            .and_then(|number| number.checked_sub(1))
            .filter(|index| *index < devices.len())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "choose device numbers from the displayed list",
                )
            })?;
        selected.insert(devices[index].busid);
    }
    if selected.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "no devices selected; exporter not started",
        ));
    }
    Ok(selected)
}

fn pick(devices: &[Device]) -> io::Result<BTreeSet<BusId>> {
    if !io::stdin().is_terminal() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "--pick requires an interactive terminal; use --device BUSID instead",
        ));
    }
    eprintln!("Choose devices receivers may attach (nothing is shared yet):");
    for (index, device) in devices.iter().enumerate() {
        eprintln!(
            "  {}. {}  {}{}",
            index + 1,
            device.busid,
            inventory::display_name(device),
            if device.busy { " [busy]" } else { "" }
        );
    }
    eprint!("Device numbers, separated by commas (empty cancels): ");
    io::stderr().flush()?;
    let mut input = String::new();
    io::stdin().lock().take(4097).read_line(&mut input)?;
    if input.len() > 4096 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "device selection is too long",
        ));
    }
    select_devices(&input, devices)
}

pub(super) async fn run(args: ServeArgs, shutdown: impl Future<Output = ()>) -> io::Result<()> {
    crate::require_loopback(args.backend, "--backend")?;
    if args.backend.port() == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "--backend requires a nonzero port",
        ));
    }
    let host = platform::Host::new()?;
    let devices = host.inventory().await?;
    let allowed = if args.pick {
        Some(pick(&devices)?)
    } else if args.devices.is_empty() {
        None
    } else {
        Some(args.devices.into_iter().collect())
    };
    if let Some(ids) = &allowed {
        eprintln!(
            "Available for on-demand sharing: {}",
            ids.iter().map(BusId::as_str).collect::<Vec<_>>().join(", ")
        );
        eprintln!(
            "BUSID restrictions follow physical port IDs; verify the device after reconnecting hardware."
        );
    } else {
        eprintln!(
            "All exportable USB devices are available on demand; no device is bound until a receiver selects it."
        );
    }
    let direct = Connection::Direct {
        bind: args
            .listen
            .unwrap_or_else(|| SocketAddr::from((Ipv4Addr::UNSPECIFIED, 7443))),
        peer: None,
    };
    let config = args.common.config(args.peer_id, true, Some(direct))?;
    let max_connections = config.limits.max_connections;
    let setup_timeout = config.limits.connect_timeout;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let managed_address = listener.local_addr()?;
    let (stop_transport, stopped_transport) = oneshot::channel();
    let (stop_backend, stopped_backend) = oneshot::channel();
    let transport = run_server(config, managed_address, async {
        let _ = stopped_transport.await;
    });
    let managed = backend::run(
        host,
        listener,
        args.backend,
        allowed,
        async {
            let _ = stopped_backend.await;
        },
        max_connections,
        setup_timeout,
    );
    tokio::pin!(transport, managed, shutdown);
    let (transport_result, managed_result) = tokio::select! {
        () = &mut shutdown => (None, None),
        result = &mut transport => (Some(result), None),
        result = &mut managed => (None, Some(result)),
    };
    let _ = stop_transport.send(());
    let _ = stop_backend.send(());
    let transport_result = match transport_result {
        Some(result) => result,
        None => transport.await,
    };
    let managed_result = match managed_result {
        Some(result) => result,
        None => managed.await,
    };
    if let Err(error) = managed_result {
        if let Err(transport_error) = transport_result {
            eprintln!("Transport shutdown: {transport_error}");
        }
        return Err(io::Error::other(format!(
            "exporter device cleanup: {error}"
        )));
    }
    transport_result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selection_rejects_empty_invalid_and_out_of_range_choices() {
        let devices = vec![Device {
            busid: "1-2".parse().unwrap(),
            vendor: 1,
            product: 2,
            name: "Device".into(),
            shared: false,
            busy: false,
        }];
        for text in ["", "0", "2", "one", "1,2"] {
            assert!(select_devices(text, &devices).is_err());
        }
        assert_eq!(
            select_devices("1, 1", &devices).unwrap(),
            BTreeSet::from(["1-2".parse().unwrap()])
        );
    }

    #[tokio::test]
    async fn zero_backend_port_is_rejected_before_platform_access() {
        use crate::args::{Cli, Command};
        use clap::Parser;
        let cli = Cli::try_parse_from(["remoteusb", "serve", "--backend", "127.0.0.1:0"]).unwrap();
        let Command::Serve(args) = cli.command else {
            panic!("expected serve")
        };
        let error = run(args, std::future::pending()).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }
}
