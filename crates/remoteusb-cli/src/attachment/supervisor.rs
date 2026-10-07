use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::Command;
use tokio::sync::oneshot;

use super::proxy::Proxy;
use super::status::{endpoint_present, stopped_count};
use super::{client_busid, independent_process, port};
use crate::usbip::BusId;

const DRIVER_TIMEOUT: Duration = Duration::from_secs(30);
const REAP_TIMEOUT: Duration = Duration::from_secs(2);
const START_TIMEOUT: Duration = Duration::from_secs(10);
const CLEANUP_DEADLINE: Duration = Duration::from_secs(30);
const STATUS_INTERVAL: Duration = Duration::from_millis(200);
const MAX_DRIVER_OUTPUT: u64 = 128 * 1024;

struct DriverOutput {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

struct CommandFailure {
    error: io::Error,
    finished: bool,
}

impl From<io::Error> for CommandFailure {
    fn from(error: io::Error) -> Self {
        Self {
            error,
            finished: false,
        }
    }
}

struct Settings {
    busid: BusId,
    executable: PathBuf,
    address: SocketAddr,
}

impl Settings {
    fn parse(arguments: Vec<String>) -> io::Result<Self> {
        let [busid, executable, address]: [String; 3] = arguments.try_into().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "supervisor requires BUSID, USB/IP executable and loopback address",
            )
        })?;
        let busid = client_busid(&busid)?;
        let address: SocketAddr = address.parse().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid supervisor listener address",
            )
        })?;
        if !address.ip().is_loopback() || address.port() == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "supervisor requires a nonzero loopback listener",
            ));
        }
        if executable.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "missing USB/IP executable",
            ));
        }
        Ok(Self {
            busid,
            executable: PathBuf::from(executable),
            address,
        })
    }

    async fn attach(&self, endpoint: SocketAddr, finished: &mut bool) -> io::Result<u8> {
        let output = self
            .command(&[
                "--tcp-port".into(),
                endpoint.port().to_string(),
                "attach".into(),
                "--remote".into(),
                endpoint.ip().to_string(),
                "--bus-id".into(),
                self.busid.to_string(),
                "--once".into(),
                "--terse".into(),
            ])
            .await;
        match output {
            Ok(output) => {
                *finished = true;
                port(&output.stdout)
            }
            Err(failure) => {
                *finished = failure.finished;
                Err(failure.error)
            }
        }
    }

    async fn stop_retries(&self, endpoint: SocketAddr) -> io::Result<u32> {
        let output = self
            .command(&[
                "--debug".into(),
                "--tcp-port".into(),
                endpoint.port().to_string(),
                "attach".into(),
                "--remote".into(),
                endpoint.ip().to_string(),
                "--bus-id".into(),
                self.busid.to_string(),
                "--stop".into(),
            ])
            .await
            .map_err(|failure| failure.error)?;
        stopped_count(&output.stderr)
    }

    async fn confirm_cleanup(&self, endpoint: SocketAddr, canceled: &mut bool) -> io::Result<()> {
        tokio::time::timeout(CLEANUP_DEADLINE, async {
            loop {
                if !*canceled {
                    // Positive count is the fence for the teardown-created retry.
                    // A zero count is never proof that retry insertion has finished.
                    *canceled = self.stop_retries(endpoint).await? > 0;
                }
                if *canceled {
                    let output = self.command(&["port".into()]).await.map_err(|failure| failure.error)?;
                    if !endpoint_present(&output.stdout, endpoint, self.busid)? {
                        return Ok(());
                    }
                }
                tokio::time::sleep(STATUS_INTERVAL).await;
            }
        }).await.map_err(|_| io::Error::new(io::ErrorKind::TimedOut,
            "owned socket closed, but driver retry cancellation/endpoint absence could not be confirmed"))?
    }

    async fn command(&self, arguments: &[String]) -> Result<DriverOutput, CommandFailure> {
        let mut command = Command::new(&self.executable);
        command
            .args(arguments)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        independent_process(&mut command);
        let mut child = command.spawn().map_err(|error| CommandFailure {
            error: io::Error::new(
                error.kind(),
                format!(
                    "could not launch USB/IP client {}: {error}",
                    self.executable.display()
                ),
            ),
            finished: true, // No process was launched; no driver call could occur.
        })?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("missing USB/IP stdout"))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| io::Error::other("missing USB/IP stderr"))?;
        let result = tokio::time::timeout(DRIVER_TIMEOUT, async {
            tokio::try_join!(bounded_output(stdout), bounded_output(stderr), child.wait())
        })
        .await;
        let result = result.unwrap_or_else(|_| {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "driver command timed out",
            ))
        });
        let (stdout, stderr, status) = match result {
            Ok(output) => output,
            Err(error) => {
                // A killed/failed command may already have changed the driver.
                // Never infer a port, retry attach or detach another attachment.
                // Explicitly request termination; do not let waiting for a hung
                // driver postpone the worker's own bounded lifetime indefinitely.
                let _ = child.start_kill();
                let finished = tokio::time::timeout(REAP_TIMEOUT, child.wait())
                    .await
                    .is_ok_and(|result| result.is_ok());
                return Err(CommandFailure {
                    error: io::Error::other(format!(
                        "{error}; driver completion is indeterminate; driver child termination confirmed: {finished}; inspect usbip.exe port"
                    )),
                    finished,
                });
            }
        };
        if !status.success() {
            return Err(CommandFailure {
                error: io::Error::other(format!(
                    "USB/IP client failed ({status}); check driver installation and administrator privileges: {}; driver completion may be indeterminate; inspect usbip.exe port",
                    String::from_utf8_lossy(&stderr).trim()
                )),
                finished: true,
            });
        }
        Ok(DriverOutput { stdout, stderr })
    }
}

async fn bounded_output(reader: impl AsyncRead + Unpin) -> io::Result<Vec<u8>> {
    let mut output = Vec::new();
    reader
        .take(MAX_DRIVER_OUTPUT + 1)
        .read_to_end(&mut output)
        .await?;
    if output.len() as u64 > MAX_DRIVER_OUTPUT {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "USB/IP client output exceeded its limit",
        ));
    }
    Ok(output)
}

// Blocking stdin belongs to a dedicated thread, never Tokio's global stdin
// helper: a lingering blocking runtime task must not delay process termination.
fn parent_lease() -> io::Result<(oneshot::Receiver<()>, oneshot::Receiver<()>)> {
    let (start, started) = oneshot::channel();
    let (stop, stopped) = oneshot::channel();
    std::thread::Builder::new()
        .name("attachment-parent-lease".into())
        .spawn(move || {
            let mut stdin = io::stdin().lock();
            watch_parent(&mut stdin, start, stop);
        })?;
    Ok((started, stopped))
}

fn watch_parent(input: &mut impl Read, start: oneshot::Sender<()>, stop: oneshot::Sender<()>) {
    let mut byte = [0];
    if input.read_exact(&mut byte).is_ok() && byte[0] == b'A' {
        let _ = start.send(());
        // EOF is normal stop and process death alike. Unexpected input also
        // revokes this private lease; it never authorizes another attachment.
        let _ = input.read(&mut byte);
    }
    let _ = stop.send(());
}

fn message(text: &str) -> io::Result<()> {
    let mut stdout = io::stdout().lock();
    writeln!(stdout, "{text}")?;
    stdout.flush()
}

async fn finish_attachment(
    attachment: impl Future<Output = io::Result<u8>>,
    stopped: impl Future<Output = ()>,
) -> (io::Result<u8>, bool) {
    tokio::pin!(attachment, stopped);
    tokio::select! {
        result = &mut attachment => (result, false),
        () = &mut stopped => (attachment.await, true),
    }
}

async fn run(settings: &Settings) -> io::Result<()> {
    let (started, mut stopped) = parent_lease()?;
    let mut proxy = Proxy::start(settings.address).await?;
    message("READY")?;
    let started = tokio::time::timeout(START_TIMEOUT, started).await;
    match started {
        Ok(Ok(())) => {}
        Ok(Err(_)) => {
            let endpoint = proxy.address();
            proxy.release().await?;
            let _ = message(&format!("CLEANED {endpoint}"));
            return Ok(());
        }
        Err(_) => {
            proxy.release().await?;
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "parent did not authorize attachment before setup deadline",
            ));
        }
    }
    let endpoint = proxy.address();
    let mut command_finished = false;
    let (result, parent_gone) =
        finish_attachment(settings.attach(endpoint, &mut command_finished), async {
            let _ = (&mut stopped).await;
            // Stop forwarding immediately on EOF, but never abandon collecting the
            // driver command's completion/diagnostic port.
            proxy.request_close();
        })
        .await;
    let attachment_error = match result {
        Ok(reported_port) => {
            // Port is diagnostic only: it can be reused after connection loss.
            let acknowledged = message(&format!("ATTACHED {reported_port}")).is_ok();
            if !parent_gone && acknowledged {
                tokio::select! {
                    _ = &mut stopped => {},
                    () = proxy.ended() => {},
                }
            }
            None
        }
        Err(error) => {
            report_error(&error);
            Some(error)
        }
    };
    let mut canceled = false;
    let mut warned = false;
    loop {
        let cleanup = match proxy.close().await {
            Ok(())
                if attachment_error.is_some() && command_finished && !proxy.may_have_attached() =>
            {
                // With --once, initial import failure creates no retry. Zero
                // reply bytes or a valid negative OP_REP_IMPORT proves rejection
                // before device creation, once child completion/socket drain hold.
                break;
            }
            Ok(()) => {
                settings
                    .confirm_cleanup(proxy.address(), &mut canceled)
                    .await
            }
            Err(error) => Err(error),
        };
        match cleanup {
            Ok(()) => break,
            Err(error) => {
                if !warned {
                    let error = io::Error::other(format!(
                        "state indeterminate; private endpoint {} BUSID {} remains reserved and rejects reconnects while independent cleanup continues: {error}",
                        proxy.address(),
                        settings.busid
                    ));
                    report_error(&error);
                    warned = true;
                }
                // This delay only paces subsequent bounded attempts, never acts
                // as proof. The reservation is retained until the actual fence.
                tokio::time::sleep(STATUS_INTERVAL).await;
            }
        }
    }
    let endpoint = proxy.address();
    let release = proxy.release().await;
    if let Err(error) = &release {
        report_error(error);
    }
    if release.is_ok() {
        let _ = message(&format!("CLEANED {endpoint}"));
    }
    if let Some(error) = attachment_error {
        Err(error)
    } else {
        release
    }
}

fn report_error(error: &io::Error) {
    let detail: String = error
        .to_string()
        .chars()
        .take(400)
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect();
    let _ = message(&format!("ERROR {detail}"));
    let _ = writeln!(io::stderr(), "USB/IP supervisor: {detail}");
}

pub(crate) async fn supervise(arguments: Vec<String>) -> io::Result<()> {
    let result = if cfg!(windows) {
        match Settings::parse(arguments) {
            Ok(settings) => run(&settings).await,
            Err(error) => Err(error),
        }
    } else {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "attachment supervisor requires Windows usbip-win2",
        ))
    };
    if let Err(error) = &result {
        report_error(error);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::{Settings, finish_attachment, watch_parent};
    use tokio::sync::oneshot;

    #[test]
    fn supervisor_accepts_only_exact_private_arguments_and_loopback() {
        let args = |address: &str| vec!["1-2".into(), "usbip.exe".into(), address.into()];
        assert!(Settings::parse(args("127.0.0.1:1234")).is_ok());
        assert!(Settings::parse(args("[::1]:1234")).is_ok());
        for address in [
            "0.0.0.0:1234",
            "192.0.2.1:1234",
            "127.0.0.1:0",
            "localhost:1234",
        ] {
            assert!(Settings::parse(args(address)).is_err());
        }
        let mut extra = args("127.0.0.1:1234");
        extra.push("extra".into());
        assert!(Settings::parse(extra).is_err());
    }

    #[test]
    fn parent_eof_and_invalid_start_revoke_the_exact_lease() {
        for bytes in [b"".as_slice(), b"X"] {
            let (start, mut started) = oneshot::channel();
            let (stop, mut stopped) = oneshot::channel();
            let mut input = bytes;
            watch_parent(&mut input, start, stop);
            assert_eq!(
                started.try_recv().unwrap_err(),
                oneshot::error::TryRecvError::Closed
            );
            stopped.try_recv().unwrap();
        }
        let (start, mut started) = oneshot::channel();
        let (stop, mut stopped) = oneshot::channel();
        watch_parent(&mut b"A".as_slice(), start, stop);
        started.try_recv().unwrap();
        stopped.try_recv().unwrap();
    }

    #[tokio::test]
    async fn parent_death_does_not_cancel_collection_of_the_reported_port() {
        let (complete, completed) = oneshot::channel();
        let (stop, mut stopped) = oneshot::channel();
        let finishing = finish_attachment(async { Ok(completed.await.unwrap()) }, async {
            let _ = (&mut stopped).await;
        });
        tokio::pin!(finishing);
        stop.send(()).unwrap();
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(1), &mut finishing)
                .await
                .is_err()
        );
        complete.send(7).unwrap();
        let (port, parent_gone) = finishing.await;
        assert_eq!(port.unwrap(), 7);
        assert!(parent_gone);
    }

    #[tokio::test]
    async fn failed_driver_completion_is_preserved_after_parent_death() {
        let (complete, completed) = oneshot::channel::<()>();
        let (stop, mut stopped) = oneshot::channel();
        let finishing = finish_attachment(
            async {
                completed.await.unwrap();
                Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "ambiguous port",
                ))
            },
            async {
                let _ = (&mut stopped).await;
            },
        );
        tokio::pin!(finishing);
        stop.send(()).unwrap();
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(1), &mut finishing)
                .await
                .is_err()
        );
        complete.send(()).unwrap();
        let (result, parent_gone) = finishing.await;
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::InvalidData);
        assert!(parent_gone);
    }

    #[tokio::test]
    async fn successful_attach_retains_the_live_parent_lease() {
        let (stop, mut stopped) = oneshot::channel();
        let (port, parent_gone) = finish_attachment(async { Ok(8) }, async {
            let _ = (&mut stopped).await;
        })
        .await;
        assert_eq!(port.unwrap(), 8);
        assert!(!parent_gone);
        stop.send(()).unwrap();
        stopped.await.unwrap();
    }
}
