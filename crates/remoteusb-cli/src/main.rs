//! Foreground CLI for authenticated USB/IP, with independently supervised attachments.

mod args;
mod attachment;
mod credentials;
mod discovery;

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::process::ExitCode;

use clap::Parser;
use remoteusb_transport::{Connection, run_client, run_rendezvous, run_server};
use tokio::net::TcpListener;

use args::{Cli, Command};

async fn bind(address: SocketAddr) -> io::Result<TcpListener> {
    require_loopback(address, "--listen")?;
    let listener = TcpListener::bind(address).await?;
    eprintln!("USB/IP listener on {}", listener.local_addr()?);
    Ok(listener)
}

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

async fn execute(command: Command) -> io::Result<()> {
    // Supervisors are independent from the foreground console and watch a pipe,
    // not the Ctrl-C handler that belongs to the receiver process.
    if let Command::Supervisor { arguments } = command {
        return attachment::supervise(arguments).await;
    }
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
            let credentials = args::credential_directory(args.credentials)?;
            run_rendezvous(
                args.listen,
                &credentials.join("network.key"),
                vec![args.exporter_id, args.receiver_id],
                shutdown,
            )
            .await
        }
        Command::Serve(args) => {
            require_loopback(args.backend, "--backend")?;
            let direct = Connection::Direct {
                bind: args
                    .listen
                    .unwrap_or_else(|| SocketAddr::from((Ipv4Addr::UNSPECIFIED, 7443))),
                peer: None,
            };
            let config = args.common.config(args.peer_id, true, Some(direct))?;
            run_server(config, args.backend, shutdown).await
        }
        Command::Connect(args) => {
            let attachment = args
                .attach
                .map(|busid| attachment::Attachment::new(busid, args.usbip))
                .transpose()?;
            let config = args.endpoint.config()?;
            let listener = bind(args.listen).await?;
            match attachment {
                Some(attachment) => attachment.run(listener, config, shutdown).await,
                None => run_client(listener, config, shutdown).await,
            }
        }
        Command::Attach(args) => {
            let attachment = attachment::Attachment::new(args.busid, args.usbip)?;
            let config = args.endpoint.config()?;
            let listener = bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await?;
            attachment.run(listener, config, shutdown).await
        }
        Command::List(args) => discovery::run(args.config()?, shutdown).await,
        Command::Supervisor { .. } => unreachable!("supervisor dispatched before console setup"),
    };
    if let Some(error) = signal_error {
        return Err(io::Error::other(format!("Ctrl-C handler failed: {error}")));
    }
    result
}

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
