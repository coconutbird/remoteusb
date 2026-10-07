//! Permanent opt-in WAN qualification with a real device passed by the operator.
//!
//! On a Windows receiver with usbipd-win (exporting) and usbip-win2 (receiving),
//! the ignored test runs a real exporter and receiver of this build through a
//! loopback WAN link with delay and bandwidth pacing, then reports timings as
//! `WAN RESULT key=value` lines. There is no synthetic device mode. Only the
//! BUSID named by `REMOTEUSB_WAN_DEVICE` is shared, through the exporter's own
//! on-demand policy; the test never binds, unbinds, or detaches devices itself.

#[cfg(windows)]
#[path = "support/link.rs"]
mod link;

#[cfg(windows)]
#[path = "support/drive.rs"]
mod drive;

#[cfg(windows)]
#[path = "support/process.rs"]
mod process;

#[cfg(not(windows))]
#[test]
#[ignore = "attaches the real device named by REMOTEUSB_WAN_DEVICE through an emulated WAN; run explicitly on a Windows receiver"]
fn real_device_over_emulated_wan() -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "automatic attachment requires Windows usbip-win2; run this test on a Windows receiver",
    ))
}

#[cfg(windows)]
mod hardware {
    use std::ffi::OsString;
    use std::fmt::Display;
    use std::io;
    use std::net::SocketAddr;
    use std::path::{Path, PathBuf};
    use std::time::{Duration, Instant};

    use tempfile::TempDir;
    use tokio::runtime::Runtime;
    use tokio::time::{sleep, timeout};

    use super::drive::VolumeCheck;
    use super::link::{Profile, WanLink};
    use super::process::Process;

    const DEVICE_VARIABLE: &str = "REMOTEUSB_WAN_DEVICE";
    const USBIP_VARIABLE: &str = "REMOTEUSB_USBIP";
    const INIT_DEADLINE: Duration = Duration::from_secs(30);
    const EXPORTER_DEADLINE: Duration = Duration::from_secs(45);
    const LIST_DEADLINE: Duration = Duration::from_secs(30);
    const ATTACH_DEADLINE: Duration = Duration::from_secs(90);
    const VOLUME_DEADLINE: Duration = Duration::from_secs(90);
    const IO_DEADLINE: Duration = Duration::from_mins(10);
    const RESTORE_DEADLINE: Duration = Duration::from_secs(90);
    const POLL_INTERVAL: Duration = Duration::from_millis(500);
    const PROBE_DEADLINE: Duration = Duration::from_secs(5);
    const RUNTIME_SHUTDOWN: Duration = Duration::from_secs(10);

    #[test]
    #[ignore = "attaches the real device named by REMOTEUSB_WAN_DEVICE through an emulated WAN; run explicitly on a Windows receiver"]
    fn real_device_over_emulated_wan() -> io::Result<()> {
        let mut session = Session::new(WanSettings::from_env()?)?;
        session.run()?;
        session.close()
    }

    /// Operator-supplied configuration, validated once before anything starts.
    struct WanSettings {
        /// Passed through unchanged; the CLI owns BUSID grammar.
        busid: String,
        profile: Profile,
        volume: Option<VolumeCheck>,
        usbip: Option<PathBuf>,
    }

    impl WanSettings {
        fn from_env() -> io::Result<Self> {
            let busid = std::env::var_os(DEVICE_VARIABLE)
                .ok_or_else(|| {
                    invalid("set REMOTEUSB_WAN_DEVICE to the exporter BUSID of the device the operator connected, for example 1-2")
                })?
                .into_string()
                .map_err(|_| invalid("REMOTEUSB_WAN_DEVICE must be Unicode"))?;
            // `serve --device` splits on commas; allow exactly one device.
            if busid.is_empty() || busid.contains(',') || busid.trim() != busid {
                return Err(invalid(
                    "REMOTEUSB_WAN_DEVICE must name exactly one BUSID, for example 1-2",
                ));
            }
            let usbip = std::env::var_os(USBIP_VARIABLE).map(PathBuf::from);
            if usbip
                .as_ref()
                .is_some_and(|path| path.as_os_str().is_empty())
            {
                return Err(invalid("REMOTEUSB_USBIP must not be empty"));
            }
            Ok(Self {
                busid,
                profile: Profile::from_lookup(std::env::var_os)?,
                volume: VolumeCheck::from_env()?,
                usbip,
            })
        }
    }

    fn invalid(message: &str) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidInput, message)
    }

    /// `STATUS` column of `remoteusb list`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum DeviceStatus {
        Available,
        Shared,
        Busy,
    }

    impl DeviceStatus {
        /// Status of `busid` in `remoteusb list` stdout, or `None` if not listed.
        fn find(listing: &[String], busid: &str) -> io::Result<Option<Self>> {
            for row in listing {
                let mut columns = row.split('\t');
                if columns.next() != Some(busid) {
                    continue;
                }
                return match columns.nth(1) {
                    Some("Available") => Ok(Some(Self::Available)),
                    Some("Shared") => Ok(Some(Self::Shared)),
                    Some("Busy") => Ok(Some(Self::Busy)),
                    _ => Err(io::Error::other(format!("unrecognized list row: {row}"))),
                };
            }
            Ok(None)
        }
    }

    /// Exporter transport listener from
    /// `Groupnet node exporter: <connection>, listeners [127.0.0.1:PORT]`.
    fn exporter_listener(line: &str) -> Option<SocketAddr> {
        let (_, listeners) = line.split_once("listeners [")?;
        listeners
            .trim_end_matches(']')
            .split(", ")
            .filter_map(|address| address.parse::<SocketAddr>().ok())
            .find(|address| address.ip().is_loopback() && address.port() != 0)
    }

    /// `Groupnet endpoint exporter ready: peer receiver`.
    fn exporter_ready(line: &str) -> Option<()> {
        line.starts_with("Groupnet endpoint exporter ready")
            .then_some(())
    }

    /// `Attached USB/IP BUSID <busid> (reported driver port N) through ...`.
    fn attached(busid: &str) -> impl FnMut(&str) -> Option<()> + '_ {
        move |line| {
            line.strip_prefix("Attached USB/IP BUSID ")?
                .strip_prefix(busid)?
                .starts_with(' ')
                .then_some(())
        }
    }

    fn report(key: &str, value: impl Display) {
        println!("WAN RESULT {key}={value}");
    }

    /// Owns the runtime and the rig. Dropping it on any path, including panic
    /// unwinding and early errors, runs the ordered cleanup once.
    struct Session {
        runtime: Option<Runtime>,
        rig: Rig,
    }

    impl Session {
        fn new(settings: WanSettings) -> io::Result<Self> {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            let directory = tempfile::Builder::new()
                .prefix("remoteusb-wan-")
                .tempdir()?;
            Ok(Self {
                runtime: Some(runtime),
                rig: Rig {
                    credentials: directory.path().join("credentials"),
                    settings,
                    exporter: None,
                    receiver: None,
                    link: None,
                    baseline: None,
                    _directory: directory,
                },
            })
        }

        fn run(&mut self) -> io::Result<()> {
            let runtime = self
                .runtime
                .as_ref()
                .ok_or_else(|| io::Error::other("WAN session already closed"))?;
            runtime.block_on(self.rig.run())
        }

        /// Cleans up and reports cleanup failures as the test result.
        fn close(mut self) -> io::Result<()> {
            self.cleanup()
        }

        fn cleanup(&mut self) -> io::Result<()> {
            let Some(runtime) = self.runtime.take() else {
                return Ok(());
            };
            let result = runtime.block_on(self.rig.cleanup());
            runtime.shutdown_timeout(RUNTIME_SHUTDOWN);
            result
        }
    }

    impl Drop for Session {
        fn drop(&mut self) {
            if let Err(error) = self.cleanup() {
                eprintln!("WAN cleanup failed: {error}");
            }
        }
    }

    /// Generated credentials, both CLI endpoints, and the link between them.
    struct Rig {
        settings: WanSettings,
        credentials: PathBuf,
        exporter: Option<Process>,
        receiver: Option<Process>,
        link: Option<WanLink>,
        /// Device status before attachment; cleanup waits for it to return.
        baseline: Option<DeviceStatus>,
        // Dropped last, after every process using the credentials.
        _directory: TempDir,
    }

    impl Rig {
        async fn run(&mut self) -> io::Result<()> {
            let profile = self.settings.profile;
            report("rtt_ms", profile.rtt.as_millis());
            report("bandwidth_mbit", profile.bandwidth.mbit);
            let init = [
                OsString::from("init"),
                OsString::from("--out"),
                self.credentials.clone().into_os_string(),
            ];
            Process::spawn("init", init)?.finish(INIT_DEADLINE).await?;
            let backend = self.start_exporter().await?;
            let proxy = self
                .link
                .insert(WanLink::start(backend, profile).await?)
                .address();

            let started = Instant::now();
            let status = self.list_status(proxy).await?.ok_or_else(|| {
                io::Error::other(format!(
                    "exporter does not list BUSID {}; check REMOTEUSB_WAN_DEVICE and the connected device",
                    self.settings.busid
                ))
            })?;
            report("list_ms", started.elapsed().as_millis());
            if status == DeviceStatus::Busy {
                return Err(io::Error::other(format!(
                    "BUSID {} is already Busy; another receiver owns it",
                    self.settings.busid
                )));
            }
            self.baseline = Some(status);

            let started = Instant::now();
            let arguments = self.attach_arguments(proxy);
            let receiver = self.receiver.insert(Process::spawn("receiver", arguments)?);
            receiver
                .wait_for_stderr(
                    "attachment",
                    ATTACH_DEADLINE,
                    attached(&self.settings.busid),
                )
                .await?;
            report("attach_ms", started.elapsed().as_millis());

            if let Some(volume) = self.settings.volume.take() {
                check_volume(receiver, volume).await?;
            }
            receiver.require_running("the WAN test")
        }

        /// Starts `serve` for the selected BUSID; returns its loopback listener.
        async fn start_exporter(&mut self) -> io::Result<SocketAddr> {
            let arguments = self.with_credentials(&[
                "serve",
                "--listen",
                "127.0.0.1:0",
                "--device",
                &self.settings.busid,
            ]);
            let exporter = self.exporter.insert(Process::spawn("exporter", arguments)?);
            let listener = exporter
                .wait_for_stderr("listener address", EXPORTER_DEADLINE, exporter_listener)
                .await?;
            exporter
                .wait_for_stderr("readiness", EXPORTER_DEADLINE, exporter_ready)
                .await?;
            Ok(listener)
        }

        fn attach_arguments(&self, proxy: SocketAddr) -> Vec<OsString> {
            let mut arguments =
                self.with_credentials(&["attach", &proxy.to_string(), &self.settings.busid]);
            if let Some(usbip) = &self.settings.usbip {
                arguments.push("--usbip".into());
                arguments.push(usbip.clone().into_os_string());
            }
            arguments
        }

        fn with_credentials(&self, words: &[&str]) -> Vec<OsString> {
            let mut arguments: Vec<OsString> = words.iter().map(OsString::from).collect();
            arguments.push("--credentials".into());
            arguments.push(self.credentials.clone().into_os_string());
            arguments
        }

        async fn list_status(&self, proxy: SocketAddr) -> io::Result<Option<DeviceStatus>> {
            let listing =
                Process::spawn("list", self.with_credentials(&["list", &proxy.to_string()]))?
                    .finish(LIST_DEADLINE)
                    .await?;
            DeviceStatus::find(&listing, &self.settings.busid)
        }

        /// Ordered, idempotent teardown. Killing the receiver lets its independent
        /// supervisor close the connection it owns; the exporter then restores
        /// only the sharing it created, observed through `list` before it stops.
        async fn cleanup(&mut self) -> io::Result<()> {
            let mut failures = Failures::default();
            let attached = self.receiver.is_some();
            if let Some(receiver) = self.receiver.as_mut() {
                failures.record("stop receiver", receiver.stop().await);
            }
            if attached && let (Some(link), Some(baseline)) = (&self.link, self.baseline) {
                failures.record(
                    "restore exporter sharing",
                    self.await_restored(link.address(), baseline).await,
                );
            }
            if let Some(exporter) = self.exporter.as_mut() {
                failures.record("stop exporter", exporter.stop().await);
            }
            if let Some(link) = self.link.take() {
                failures.record("close WAN link", link.close().await);
            }
            for process in [self.receiver.take(), self.exporter.take()]
                .into_iter()
                .flatten()
            {
                failures.record("join process output", process.join().await.map(drop));
            }
            failures.into_result()
        }

        async fn await_restored(
            &self,
            proxy: SocketAddr,
            baseline: DeviceStatus,
        ) -> io::Result<()> {
            let deadline = Instant::now() + RESTORE_DEADLINE;
            loop {
                let observed = match self.list_status(proxy).await {
                    Ok(Some(status)) if status == baseline => return Ok(()),
                    Ok(Some(status)) => format!("{status:?}"),
                    Ok(None) => "not listed".to_owned(),
                    Err(error) => error.to_string(),
                };
                if Instant::now() >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!(
                            "BUSID {} did not return to {baseline:?} within {RESTORE_DEADLINE:?}; last observed: {observed}",
                            self.settings.busid
                        ),
                    ));
                }
                sleep(POLL_INTERVAL).await;
            }
        }
    }

    /// Waits for the attached volume, then runs the shared drive verification.
    async fn check_volume(receiver: &mut Process, volume: VolumeCheck) -> io::Result<()> {
        let started = Instant::now();
        wait_for_volume(receiver, volume.root()).await?;
        report("volume_ms", started.elapsed().as_millis());
        let checked = timeout(IO_DEADLINE, tokio::task::spawn_blocking(move || volume.run()))
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("volume I/O did not finish within {IO_DEADLINE:?}; blocked I/O cannot be cancelled"),
                )
            })?
            .map_err(io::Error::other)??;
        report("io_bytes", checked.bytes);
        report("io_ms", checked.elapsed.as_millis());
        report("io_mb_per_s", checked.throughput());
        Ok(())
    }

    async fn wait_for_volume(receiver: &mut Process, root: &Path) -> io::Result<()> {
        let deadline = Instant::now() + VOLUME_DEADLINE;
        loop {
            receiver.require_running("volume discovery")?;
            let probe = timeout(
                PROBE_DEADLINE,
                tokio::task::spawn_blocking({
                    let root = root.to_path_buf();
                    move || std::fs::metadata(root)
                }),
            )
            .await;
            if matches!(probe, Ok(Ok(Ok(metadata))) if metadata.is_dir()) {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!(
                        "{} did not appear within {VOLUME_DEADLINE:?} after attachment; check REMOTEUSB_TEST_DRIVE",
                        root.display()
                    ),
                ));
            }
            sleep(POLL_INTERVAL).await;
        }
    }

    /// Cleanup keeps going after a failed step and reports every failure.
    #[derive(Default)]
    struct Failures(Vec<String>);

    impl Failures {
        fn record(&mut self, step: &str, result: io::Result<()>) {
            if let Err(error) = result {
                self.0.push(format!("{step}: {error}"));
            }
        }

        fn into_result(self) -> io::Result<()> {
            if self.0.is_empty() {
                Ok(())
            } else {
                Err(io::Error::other(self.0.join("; ")))
            }
        }
    }
}
