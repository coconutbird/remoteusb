//! Explicit Windows USB/IP attachment; driver installation and policy remain external.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use remoteusb_transport::{PeerConfig, run_client};
use tokio::net::TcpListener;
use tokio::process::Command;
use tokio::sync::oneshot;

pub(super) struct Attachment {
    busid: String,
    executable: PathBuf,
}

impl Attachment {
    pub(super) fn new(busid: String, executable: Option<PathBuf>) -> io::Result<Self> {
        if !cfg!(windows) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "--attach currently requires Windows usbip-win2; attach manually on other systems",
            ));
        }
        if busid.is_empty()
            || busid.len() > 31
            || !busid
                .bytes()
                .all(|b| b.is_ascii_digit() || b == b'-' || b == b'.')
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid USB/IP BUSID",
            ));
        }
        let executable = executable
            .or_else(|| {
                std::env::var_os("ProgramFiles")
                    .map(|root| PathBuf::from(root).join("USBip").join("usbip.exe"))
            })
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    "specify --usbip with the installed usbip-win2 executable",
                )
            })?;
        if !executable.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "USB/IP client not found at {}; install usbip-win2 or specify --usbip",
                    executable.display()
                ),
            ));
        }
        Ok(Self { busid, executable })
    }

    async fn command(&self, arguments: &[String]) -> io::Result<Vec<u8>> {
        let output = tokio::time::timeout(
            Duration::from_secs(30),
            Command::new(&self.executable)
                .args(arguments)
                .stdin(Stdio::null())
                .kill_on_drop(true)
                .output(),
        )
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "USB/IP client timed out; inspect usbip.exe port for an indeterminate attachment",
            )
        })??;
        if !output.status.success() {
            return Err(io::Error::other(format!(
                "USB/IP client failed ({}); check driver installation and administrator privileges: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        Ok(output.stdout)
    }

    async fn attach(&self, address: SocketAddr) -> io::Result<u8> {
        let output = self
            .command(&[
                "--tcp-port".into(),
                address.port().to_string(),
                "attach".into(),
                "--remote".into(),
                address.ip().to_string(),
                "--bus-id".into(),
                self.busid.clone(),
                "--once".into(),
                "--terse".into(),
            ])
            .await?;
        port(&output)
    }

    async fn detach(&self, port: u8) -> io::Result<()> {
        self.command(&["detach".into(), "--port".into(), port.to_string()])
            .await?;
        eprintln!("Detached USB/IP port {port}");
        Ok(())
    }

    pub(super) async fn run(
        self,
        listener: TcpListener,
        config: PeerConfig,
        shutdown: impl Future<Output = ()>,
    ) -> io::Result<()> {
        let address = listener.local_addr()?;
        let (stop, stopped) = oneshot::channel();
        let mut tunnel = tokio::spawn(run_client(listener, config, async {
            let _ = stopped.await;
        }));
        let attaching = self.attach(address);
        tokio::pin!(attaching, shutdown);
        let mut finished = None;
        let mut interrupted = false;
        // Never abandon an in-flight successful attach before collecting its port.
        // Keep the tunnel alive until attachment completion and driver detachment.
        let attached = tokio::select! {
            result = &mut attaching => result,
            () = &mut shutdown => { interrupted = true; attaching.await },
            result = &mut tunnel => { finished = Some(result); attaching.await },
        };
        let driver_result = match attached {
            Ok(port) => {
                eprintln!(
                    "Attached USB/IP BUSID {} on port {port} through {address}; Ctrl-C detaches this port",
                    self.busid
                );
                if !interrupted && finished.is_none() {
                    tokio::select! {
                        () = &mut shutdown => {},
                        result = &mut tunnel => { finished = Some(result); },
                    }
                }
                self.detach(port).await.map_err(|error| io::Error::other(format!(
                    "could not detach owned USB/IP port {port}: {error}; run usbip.exe detach --port {port}")))
            }
            Err(error) => Err(error),
        };
        let _ = stop.send(());
        let tunnel_result = match finished {
            Some(result) => result,
            None => tunnel.await,
        }
        .map_err(io::Error::other)?;
        if let Err(error) = &driver_result {
            eprintln!("USB/IP attachment: {error}");
        }
        tunnel_result?;
        driver_result
    }
}

fn port(output: &[u8]) -> io::Result<u8> {
    std::str::from_utf8(output).ok().and_then(|text| text.trim().parse::<u8>().ok())
        .filter(|port| *port != 0)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData,
            "USB/IP client did not return one port in 1..=255; inspect usbip.exe port; refusing to detach an unknown device"))
}

#[cfg(test)]
mod tests {
    use super::port;

    #[test]
    fn only_an_unambiguous_owned_port_can_be_detached() {
        assert_eq!(port(b"1\r\n").unwrap(), 1);
        assert_eq!(port(b"255\n").unwrap(), 255);
        for output in [b"0".as_slice(), b"256", b"-1", b"1\n2", b"", b"\xff"] {
            assert!(port(output).is_err());
        }
    }
}
