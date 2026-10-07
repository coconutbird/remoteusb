//! Explicit Windows USB/IP attachment; driver installation and policy remain external.
//!
//! A detached supervisor owns a private endpoint and its one driver connection.
//! Closing stdin requests connection closure and targeted retry cancellation,
//! including during in-flight attachment. Killing both processes or losing power
//! cannot be recovered by this watchdog. Numeric driver slots are diagnostic only.

mod proxy;
mod status;
mod supervisor;

use std::io;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use remoteusb_transport::{PeerConfig, run_client_with_status};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::process::{Child, ChildStdout, Command};
use tokio::sync::{oneshot, watch};

use crate::usbip::BusId;

pub(super) use supervisor::supervise;

const SETUP_TIMEOUT: Duration = Duration::from_secs(5);
const ATTACH_TIMEOUT: Duration = Duration::from_secs(35);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(80);
const TUNNEL_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_MESSAGE: usize = 2048;

type SupervisorMessages = Messages<BufReader<ChildStdout>>;

pub(super) struct Attachment {
    busid: BusId,
    executable: PathBuf,
}

impl Attachment {
    pub(super) fn new(busid: BusId, executable: Option<PathBuf>) -> io::Result<Self> {
        if !cfg!(windows) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "attachment requires Windows usbip-win2; attach manually on other systems",
            ));
        }
        let busid = client_busid(busid.as_str())?;
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

    fn spawn(&self, address: std::net::SocketAddr) -> io::Result<Child> {
        let executable = self.executable.to_str().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "USB/IP executable path must be Unicode",
            )
        })?;
        let mut command = Command::new(std::env::current_exe()?);
        command
            .arg("__attachment-supervisor")
            .args([self.busid.as_str(), executable, &address.to_string()])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            // Never kill the owner of an in-flight attach when this parent drops.
            .kill_on_drop(false);
        independent_process(&mut command);
        command.spawn()
    }

    pub(super) async fn run(
        self,
        listener: TcpListener,
        config: PeerConfig,
        shutdown: impl Future<Output = ()>,
    ) -> io::Result<()> {
        let address = listener.local_addr()?;
        let mut worker = self.spawn(address)?;
        let mut control = worker.stdin.take();
        let stdout = worker
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("missing supervisor stdout"))?;
        let mut messages = Messages::new(BufReader::new(stdout));
        let (stop, stopped) = oneshot::channel();
        let (status, mut active) = watch::channel(0);
        let mut tunnel = tokio::spawn(run_client_with_status(
            listener,
            config,
            async {
                let _ = stopped.await;
            },
            status,
        ));
        tokio::pin!(shutdown);
        let mut tunnel_finished = None;
        let attachment_result = {
            let attached = async {
                expect_message(&mut messages, "READY", SETUP_TIMEOUT).await?;
                let stdin = control
                    .as_mut()
                    .ok_or_else(|| io::Error::other("missing supervisor stdin"))?;
                tokio::time::timeout(SETUP_TIMEOUT, stdin.write_all(b"A"))
                    .await
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::TimedOut, "supervisor start timed out")
                    })??;
                let message = message_with_timeout(&mut messages, ATTACH_TIMEOUT).await?;
                attachment_message(&message)
            };
            tokio::pin!(attached);
            tokio::select! {
                result = &mut attached => result,
                () = &mut shutdown => Err(io::Error::new(io::ErrorKind::Interrupted, "attachment interrupted during setup; supervisor will collect the port and clean up")),
                result = &mut tunnel => {
                    tunnel_finished = Some(result);
                    Err(io::Error::other("attachment transport stopped during setup; supervisor will clean up"))
                },
            }
        };
        let session_result = match attachment_result {
            Ok(port) => {
                eprintln!(
                    "Attached USB/IP BUSID {} (reported driver port {port}) through {address}; Ctrl-C closes this attachment",
                    self.busid
                );
                tokio::select! {
                    () = &mut shutdown => Ok(()),
                    result = &mut tunnel => { tunnel_finished = Some(result); Ok(()) },
                    result = worker.wait() => match result {
                        Ok(status) if status.success() => Ok(()),
                        Ok(status) => Err(io::Error::other(format!(
                            "attachment supervisor unexpectedly exited with {status}; inspect usbip.exe port for BUSID {} (reported port {port})", self.busid
                        ))),
                        Err(error) => Err(io::Error::new(error.kind(), format!("could not observe attachment supervisor: {error}"))),
                    },
                    () = wait_for_no_streams(&mut active) => {
                        eprintln!("Attached USB/IP stream ended; requesting owned-connection cleanup for BUSID {}", self.busid);
                        Ok(())
                    },
                }
            }
            Err(error) => Err(error),
        };
        // EOF asks the independent worker to close its owned driver connection.
        // Keep transport alive until targeted cleanup completes, even if setup was interrupted.
        drop(control.take());
        let cleanup_result = finish_worker(&mut worker, &mut messages).await;
        let _ = stop.send(());
        let tunnel_result = match tunnel_finished {
            Some(result) => result
                .map_err(io::Error::other)
                .and_then(std::convert::identity),
            None => {
                if let Ok(result) = tokio::time::timeout(TUNNEL_TIMEOUT, &mut tunnel).await {
                    result
                        .map_err(io::Error::other)
                        .and_then(std::convert::identity)
                } else {
                    tunnel.abort();
                    let drained = tokio::time::timeout(TUNNEL_TIMEOUT, &mut tunnel).await;
                    Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        if drained.is_err() {
                            "attachment tunnel shutdown and aborted-task drain timed out"
                        } else {
                            "attachment tunnel shutdown timed out; aborted task drained"
                        },
                    ))
                }
            }
        };
        combine_results(session_result, cleanup_result, tunnel_result)
    }
}

fn combine_results(
    session: io::Result<()>,
    cleanup: io::Result<()>,
    tunnel: io::Result<()>,
) -> io::Result<()> {
    let mut errors = Vec::new();
    for (phase, result) in [
        ("attachment", session),
        ("supervisor cleanup", cleanup),
        ("transport", tunnel),
    ] {
        if let Err(error) = result {
            eprintln!("USB/IP {phase}: {error}");
            errors.push(format!("{phase}: {error}"));
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(io::Error::other(errors.join("; ")))
    }
}

async fn finish_worker(worker: &mut Child, messages: &mut SupervisorMessages) -> io::Result<()> {
    // Drain the bounded protocol while waiting, so errors remain observable and
    // the worker never waits on a full pipe during independent cleanup.
    tokio::time::timeout(CLEANUP_TIMEOUT, async {
        let mut protocol_error = None;
        let mut acknowledged = false;
        loop {
            let message = match messages.read().await {
                Ok(message) => message,
                Err(error) => { protocol_error = Some(error); break; },
            };
            match message.as_str() {
                "" => break,
                "READY" => {},
                _ if message.starts_with("ATTACHED ") => {
                    eprintln!("USB/IP supervisor: {message}");
                }
                _ if message.starts_with("CLEANED ") => {
                    if let Err(error) = cleanup_message(&message) {
                        protocol_error = Some(error);
                        break;
                    }
                    acknowledged = true;
                    eprintln!("USB/IP supervisor: {message}");
                }
                _ if message.starts_with("ERROR ") => {
                    protocol_error = Some(io::Error::other(message[6..].to_owned()));
                    break;
                }
                _ => {
                    protocol_error = Some(io::Error::new(io::ErrorKind::InvalidData, "invalid supervisor cleanup response"));
                    break;
                },
            }
        }
        // A malformed/lost diagnostic must not skip waiting for the actual owner.
        let status = worker.wait().await?;
        if let Some(error) = protocol_error {
            Err(io::Error::other(format!("{error} (supervisor {status})")))
        } else if status.success() && acknowledged {
            Ok(())
        } else if status.success() {
            Err(io::Error::new(io::ErrorKind::UnexpectedEof, "supervisor exited without a confirmed connection-cleanup acknowledgement"))
        } else {
            Err(io::Error::other(format!("supervisor exited with {status}; inspect usbip.exe port")))
        }
    }).await.map_err(|_| io::Error::new(io::ErrorKind::TimedOut,
        "supervisor cleanup wait timed out; the independent worker was NOT killed; inspect usbip.exe port"))?
}

async fn wait_for_no_streams(active: &mut watch::Receiver<usize>) {
    while *active.borrow_and_update() != 0 {
        if active.changed().await.is_err() {
            return;
        }
    }
}

async fn expect_message(
    messages: &mut SupervisorMessages,
    expected: &str,
    deadline: Duration,
) -> io::Result<()> {
    let message = message_with_timeout(messages, deadline).await?;
    if message == expected {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "supervisor setup failed: {message}"
        )))
    }
}

async fn message_with_timeout(
    messages: &mut SupervisorMessages,
    deadline: Duration,
) -> io::Result<String> {
    tokio::time::timeout(deadline, messages.read())
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "supervisor acknowledgment timed out; cleanup will be requested",
            )
        })?
}

struct Messages<R> {
    reader: R,
    // Retain partially consumed lines if Ctrl-C or an ACK timeout cancels read.
    pending: Vec<u8>,
}

impl<R: AsyncBufRead + Unpin> Messages<R> {
    fn new(reader: R) -> Self {
        Self {
            reader,
            pending: Vec::new(),
        }
    }

    async fn read(&mut self) -> io::Result<String> {
        loop {
            let buffer = self.reader.fill_buf().await?;
            if buffer.is_empty() {
                return if self.pending.is_empty() {
                    Ok(String::new())
                } else {
                    Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "truncated supervisor response",
                    ))
                };
            }
            let count = buffer
                .iter()
                .position(|byte| *byte == b'\n')
                .map_or(buffer.len(), |index| index + 1);
            if self.pending.len() + count > MAX_MESSAGE {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "oversized supervisor response",
                ));
            }
            self.pending.extend_from_slice(&buffer[..count]);
            self.reader.consume(count);
            if self.pending.last() == Some(&b'\n') {
                self.pending.pop();
                return String::from_utf8(std::mem::take(&mut self.pending)).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "non-UTF8 supervisor response")
                });
            }
        }
    }
}

fn attachment_message(message: &str) -> io::Result<u8> {
    let value = message
        .strip_prefix("ATTACHED ")
        .ok_or_else(|| io::Error::other(format!("supervisor attachment failed: {message}")))?;
    port(value.as_bytes())
}

fn cleanup_message(message: &str) -> io::Result<()> {
    let address = message
        .strip_prefix("CLEANED ")
        .and_then(|address| address.parse::<std::net::SocketAddr>().ok())
        .filter(|address| address.ip().is_loopback() && address.port() != 0);
    if address.is_some() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid supervisor cleanup acknowledgement",
        ))
    }
}

/// usbip-win2 receives the BUSID as a command-line value and echoes it in
/// `port` URIs, so the importer accepts only the numeric Linux form (ASCII
/// digits, `-` and `.`) of the wire grammar.
fn client_busid(busid: &str) -> io::Result<BusId> {
    if busid
        .bytes()
        .all(|byte| byte.is_ascii_digit() || matches!(byte, b'-' | b'.'))
        && let Ok(busid) = busid.parse()
    {
        return Ok(busid);
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "invalid USB/IP BUSID",
    ))
}

fn port(output: &[u8]) -> io::Result<u8> {
    std::str::from_utf8(output).ok().and_then(|text| text.trim().parse::<u8>().ok())
        .filter(|port| *port != 0)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData,
            "USB/IP client did not return one port in 1..=255; inspect usbip.exe port; cleanup remains scoped to the owned connection"))
}

fn independent_process(command: &mut Command) {
    #[cfg(windows)]
    // DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP: no parent console and no
    // inherited Ctrl-C group. Stdio pipe lifetime, not a reusable PID, is the lease.
    command.creation_flags(0x0000_0008 | 0x0000_0200);
    #[cfg(not(windows))]
    let _ = command;
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_MESSAGE, Messages, attachment_message, cleanup_message, client_busid, port,
        wait_for_no_streams,
    };
    use tokio::io::{AsyncWriteExt, BufReader};
    use tokio::sync::watch;

    #[test]
    fn only_an_unambiguous_reported_port_is_accepted() {
        assert_eq!(port(b"1\r\n").unwrap(), 1);
        assert_eq!(port(b"255\n").unwrap(), 255);
        for output in [b"0".as_slice(), b"256", b"-1", b"1\n2", b"", b"\xff"] {
            assert!(port(output).is_err());
        }
        assert_eq!(attachment_message("ATTACHED 9").unwrap(), 9);
        assert!(attachment_message("READY 9").is_err());
    }

    #[test]
    fn cleanup_acknowledgement_requires_a_real_private_endpoint() {
        assert!(cleanup_message("CLEANED 127.0.0.1:1234").is_ok());
        assert!(cleanup_message("CLEANED [::1]:1234").is_ok());
        for message in [
            "CLEANED 127.0.0.1:0",
            "CLEANED 192.0.2.1:1234",
            "CLEANED 7",
            "ATTACHED 7",
            "CLEANED localhost:1234",
        ] {
            assert!(cleanup_message(message).is_err());
        }
    }

    #[test]
    fn busid_never_becomes_an_option_or_shell_fragment() {
        for busid in ["1-2", "3-4.5"] {
            assert_eq!(client_busid(busid).unwrap().as_str(), busid);
        }
        for busid in [
            "",
            "--remote",
            "1 2",
            "1;2",
            "é",
            "12345678901234567890123456789012",
        ] {
            assert!(client_busid(busid).is_err());
        }
    }

    #[tokio::test]
    async fn supervisor_messages_are_bounded_and_complete() {
        assert_eq!(
            Messages::new(b"READY\n".as_slice()).read().await.unwrap(),
            "READY"
        );
        assert!(
            Messages::new(b"ATTACHED 1".as_slice())
                .read()
                .await
                .is_err()
        );
        assert!(Messages::new(b"\xff\n".as_slice()).read().await.is_err());
        let bytes = vec![b'x'; MAX_MESSAGE + 1];
        assert!(Messages::new(bytes.as_slice()).read().await.is_err());
    }

    #[tokio::test]
    async fn canceled_ack_retains_partial_line_for_cleanup() {
        let (mut writer, reader) = tokio::io::duplex(64);
        let mut messages = Messages::new(BufReader::new(reader));
        writer.write_all(b"ATT").await.unwrap();
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(1), messages.read())
                .await
                .is_err()
        );
        writer
            .write_all(b"ACHED 7\nCLEANED 127.0.0.1:1234\n")
            .await
            .unwrap();
        assert_eq!(messages.read().await.unwrap(), "ATTACHED 7");
        assert_eq!(messages.read().await.unwrap(), "CLEANED 127.0.0.1:1234");
    }

    #[tokio::test]
    async fn attached_stream_zero_is_a_terminal_lifecycle_event() {
        let (status, mut receiver) = watch::channel(1);
        let stopped = wait_for_no_streams(&mut receiver);
        tokio::pin!(stopped);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(1), &mut stopped)
                .await
                .is_err()
        );
        status.send(0).unwrap();
        stopped.await;
        let (_, mut receiver) = watch::channel(0);
        wait_for_no_streams(&mut receiver).await;
    }
}
