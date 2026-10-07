//! Owned `remoteusb` child process whose output is echoed and retained.
//!
//! Output is always drained, independent of waiters: an attachment supervisor
//! inherits the receiver's stderr, and a full or closed pipe must never stall
//! or break its cleanup.

use std::collections::VecDeque;
use std::ffi::OsStr;
use std::io;
use std::process::Stdio;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncRead, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::timeout;

const STOP_DEADLINE: Duration = Duration::from_secs(15);
// Descendants such as the attachment supervisor may still hold inherited stderr.
const JOIN_DEADLINE: Duration = Duration::from_secs(30);
const RETAINED_LINES: usize = 1024;

#[derive(Default)]
struct Transcript {
    lines: VecDeque<String>,
    closed: bool,
}

impl Transcript {
    fn push(&mut self, line: String) {
        if self.lines.len() == RETAINED_LINES {
            self.lines.pop_front();
        }
        self.lines.push_back(line);
    }
}

/// One drained output stream.
struct Capture {
    transcript: watch::Receiver<Transcript>,
    reader: Option<JoinHandle<io::Result<()>>>,
}

impl Capture {
    fn start(label: String, stream: impl AsyncRead + Unpin + Send + 'static) -> Self {
        let (sender, transcript) = watch::channel(Transcript::default());
        let reader = tokio::spawn(async move {
            let mut stream = BufReader::new(stream);
            let mut line = Vec::new();
            let result = loop {
                line.clear();
                match stream.read_until(b'\n', &mut line).await {
                    Ok(0) => break Ok(()),
                    Ok(_) => {
                        // Driver tools may emit non-UTF-8 text; never stop draining.
                        let text = String::from_utf8_lossy(&line).trim_end().to_owned();
                        eprintln!("[{label}] {text}");
                        sender.send_modify(|transcript| transcript.push(text));
                    }
                    Err(error) => break Err(error),
                }
            };
            sender.send_modify(|transcript| transcript.closed = true);
            result
        });
        Self {
            transcript,
            reader: Some(reader),
        }
    }

    /// Waits for end of stream, then returns the retained lines.
    async fn join(&mut self, label: &str) -> io::Result<Vec<String>> {
        if let Some(reader) = self.reader.as_mut() {
            let joined = timeout(JOIN_DEADLINE, &mut *reader).await;
            if joined.is_err() {
                reader.abort();
            }
            self.reader = None;
            joined
                .map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!(
                            "{label} output stayed open; a descendant process is still running"
                        ),
                    )
                })?
                .map_err(io::Error::other)??;
        }
        Ok(self.transcript.borrow().lines.iter().cloned().collect())
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        if let Some(reader) = &self.reader {
            reader.abort();
        }
    }
}

/// A `remoteusb` invocation killed on drop. Call [`Process::join`] or
/// [`Process::finish`] to stop it and join its output readers within deadlines.
pub struct Process {
    label: &'static str,
    child: Child,
    stdout: Capture,
    stderr: Capture,
}

impl Process {
    pub fn spawn(
        label: &'static str,
        arguments: impl IntoIterator<Item = impl AsRef<OsStr>>,
    ) -> io::Result<Self> {
        let mut child = Command::new(env!("CARGO_BIN_EXE_remoteusb"))
            .args(arguments)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!("cannot start remoteusb {label}: {error}"),
                )
            })?;
        let stdout = child.stdout.take().expect("stdout is piped");
        let stderr = child.stderr.take().expect("stderr is piped");
        Ok(Self {
            label,
            child,
            stdout: Capture::start(format!("{label} stdout"), stdout),
            stderr: Capture::start(label.to_owned(), stderr),
        })
    }

    /// Returns the first stderr line accepted by `parse`, including lines that
    /// arrived earlier. Fails if the process exits or the deadline passes first.
    pub async fn wait_for_stderr<T>(
        &mut self,
        what: &str,
        deadline: Duration,
        mut parse: impl FnMut(&str) -> Option<T>,
    ) -> io::Result<T> {
        let label = self.label;
        let mut transcript = self.stderr.transcript.clone();
        let mut found = None;
        let in_time = tokio::select! {
            biased;
            seen = timeout(deadline, transcript.wait_for(|transcript| {
                found = transcript.lines.iter().find_map(|line| parse(line));
                found.is_some() || transcript.closed
            })) => seen.is_ok(),
            status = self.child.wait() => {
                let status = status?;
                return Err(io::Error::other(format!(
                    "remoteusb {label} exited with {status} before {what}"
                )));
            }
        };
        if !in_time {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("remoteusb {label}: no {what} within {deadline:?}"),
            ));
        }
        found.ok_or_else(|| {
            io::Error::other(format!("remoteusb {label} closed stderr before {what}"))
        })
    }

    /// Fails if the process already exited.
    pub fn require_running(&mut self, during: &str) -> io::Result<()> {
        match self.child.try_wait()? {
            None => Ok(()),
            Some(status) => Err(io::Error::other(format!(
                "remoteusb {} exited with {status} during {during}",
                self.label
            ))),
        }
    }

    /// Kills the process if it is still running and reaps it.
    pub async fn stop(&mut self) -> io::Result<()> {
        if self.child.try_wait()?.is_some() {
            return Ok(());
        }
        if let Err(error) = self.child.start_kill()
            && self.child.try_wait()?.is_none()
        {
            return Err(io::Error::new(
                error.kind(),
                format!("cannot stop remoteusb {}: {error}", self.label),
            ));
        }
        timeout(STOP_DEADLINE, self.child.wait())
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("remoteusb {} did not exit after kill", self.label),
                )
            })?
            .map(drop)
    }

    /// Stops the process, joins both output readers, and returns stdout lines.
    pub async fn join(mut self) -> io::Result<Vec<String>> {
        self.stop().await?;
        self.stderr.join(self.label).await?;
        self.stdout.join(self.label).await
    }

    /// Waits for a short-lived command to succeed and returns its stdout lines.
    pub async fn finish(mut self, deadline: Duration) -> io::Result<Vec<String>> {
        let label = self.label;
        let Ok(status) = timeout(deadline, self.child.wait()).await else {
            self.join().await?;
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("remoteusb {label} did not finish within {deadline:?}"),
            ));
        };
        let status = status?;
        let stdout = self.join().await?;
        if status.success() {
            Ok(stdout)
        } else {
            Err(io::Error::other(format!(
                "remoteusb {label} failed with {status}; its stderr is shown above"
            )))
        }
    }
}
