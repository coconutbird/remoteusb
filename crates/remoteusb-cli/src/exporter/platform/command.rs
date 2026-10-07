use std::io;
use std::process::Stdio;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;

const DEADLINE: Duration = Duration::from_secs(15);
const REAP_DEADLINE: Duration = Duration::from_secs(3);
const MAX_OUTPUT: usize = 1024 * 1024;

// Callers must await this future, including during shutdown: killing a command
// cannot undo a driver mutation. Always inspect state and recover partial binds.
pub(super) async fn run(program: &str, args: &[&str], input: &[u8]) -> io::Result<Vec<u8>> {
    run_with_stderr(program, args, input)
        .await
        .map(|(stdout, _)| stdout)
}

pub(super) async fn run_with_stderr(
    program: &str,
    args: &[&str],
    input: &[u8],
) -> io::Result<(Vec<u8>, Vec<u8>)> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(if input.is_empty() { Stdio::null() } else { Stdio::piped() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|error| io::Error::new(error.kind(), format!("cannot start {program}: {error}; install the OS USB/IP tools and run with driver-management permissions")))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("missing command stdout"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| io::Error::other("missing command stderr"))?;
    let mut stdin = child.stdin.take();
    let operation = async {
        let send = async {
            if let Some(pipe) = stdin.as_mut() {
                pipe.write_all(input).await?;
                pipe.shutdown().await?;
            }
            drop(stdin.take());
            Ok::<_, io::Error>(())
        };
        let ((), stdout, stderr, status) =
            tokio::try_join!(send, bounded(stdout), bounded(stderr), child.wait())?;
        if !status.success() {
            return Err(io::Error::other(format!(
                "{program} {} failed ({status}): {}",
                args.join(" "),
                String::from_utf8_lossy(&stderr).trim()
            )));
        }
        Ok((stdout, stderr))
    };
    match tokio::time::timeout(DEADLINE, operation).await {
        Ok(Ok(output)) => Ok(output),
        result => {
            let error = match result {
                Ok(Err(error)) => error,
                Err(_) => io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!(
                        "{program} {} exceeded 15 seconds; driver state may have changed",
                        args.join(" ")
                    ),
                ),
                Ok(Ok(output)) => return Ok(output),
            };
            // A Linux driver can leave a process in uninterruptible kernel sleep.
            // Never wait indefinitely, and never claim that it was stopped.
            if let Err(kill_error) = child.start_kill()
                && child
                    .try_wait()
                    .map_err(|wait_error| {
                        io::Error::new(
                            io::ErrorKind::WouldBlock,
                            format!(
                                "{error}; cannot determine whether command exited: {wait_error}"
                            ),
                        )
                    })?
                    .is_none()
            {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    format!(
                        "{error}; cannot stop command: {kill_error}; inspect driver state manually"
                    ),
                ));
            }
            match tokio::time::timeout(REAP_DEADLINE, child.wait()).await {
                Ok(Ok(_)) => Err(error),
                Ok(Err(reap_error)) => Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    format!("{error}; cannot reap command: {reap_error}"),
                )),
                Err(_) => Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    format!(
                        "{error}; command did not exit after termination; a kernel driver may be stuck, inspect driver state manually"
                    ),
                )),
            }
        }
    }
}

async fn bounded(reader: impl AsyncRead + Unpin) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader
        .take((MAX_OUTPUT + 1) as u64)
        .read_to_end(&mut bytes)
        .await?;
    if bytes.len() > MAX_OUTPUT {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "driver command output exceeds 1 MiB",
        ));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn process_output_is_bounded_at_exact_limit() {
        let bytes = vec![b'x'; MAX_OUTPUT];
        assert_eq!(bounded(bytes.as_slice()).await.unwrap().len(), MAX_OUTPUT);
        let oversized = vec![b'x'; MAX_OUTPUT + 1];
        assert_eq!(
            bounded(oversized.as_slice()).await.unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
}
