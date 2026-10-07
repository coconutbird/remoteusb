use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::inventory::Device;

use super::{BindError, command};

#[path = "linux/sysfs.rs"]
mod sysfs;

use sysfs::{DEVICES, DRIVERS, Snapshot};

pub(super) struct Candidate {
    identity: sysfs::Identity,
}

pub(super) async fn candidate(busid: &str) -> io::Result<Candidate> {
    read_snapshot(busid).await.map(|snapshot| Candidate {
        identity: snapshot.identity,
    })
}

pub(super) struct Lease {
    original: Option<Snapshot>,
}

impl Lease {
    pub(super) async fn restore(self) -> io::Result<()> {
        let Some(original) = self.original else {
            return Ok(());
        };
        restore(&original).await
    }
}

pub(super) async fn inventory() -> io::Result<Vec<Device>> {
    let root = Path::new(DEVICES);
    let mut devices = Vec::new();
    let entries = fs::read_dir(root).map_err(|error| {
        io::Error::new(error.kind(), format!(
            "cannot enumerate {DEVICES}: {error}; Linux USB kernel support and the usbip-host module must be available before starting the exporter"
        ))
    })?;
    for (count, entry) in entries.enumerate() {
        if count >= 8192 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "USB sysfs directory exceeds 8192 entries",
            ));
        }
        let entry = entry?;
        let Some(busid) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if !sysfs::device_busid(&busid) {
            continue;
        }
        match sysfs::snapshot(root, &busid).await {
            Ok(snapshot) => devices.push(snapshot.device),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::Unsupported
                ) =>
            {
                continue;
            }
            Err(error) => {
                return Err(io::Error::new(
                    error.kind(),
                    format!("cannot inspect USB {busid}: {error}"),
                ));
            }
        }
        if devices.len() > 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "USB inventory exceeds 1024 devices",
            ));
        }
    }
    devices.sort_by(|left, right| left.busid.cmp(&right.busid));
    Ok(devices)
}

pub(super) async fn bind(busid: &str, candidate: Candidate) -> Result<Lease, BindError> {
    let original = read_snapshot(busid).await?;
    if original.identity != candidate.identity {
        return Err(io::Error::other(format!(
            "USB {busid} identity changed while acquiring its ownership lock"
        ))
        .into());
    }
    if original.device.busy {
        return Err(io::Error::new(
            io::ErrorKind::ResourceBusy,
            format!("USB {busid} is already in use or in USB/IP error state"),
        )
        .into());
    }
    if original.device.shared {
        return Ok(Lease { original: None });
    }
    // Never load modules or alter preexisting match-table policy. The stock
    // usbip tool cannot distinguish ownership of an existing match entry.
    if matching(busid).await? {
        return Err(io::Error::new(io::ErrorKind::ResourceBusy, format!("USB {busid} has a preexisting usbip-host match entry without sharing; refusing to overwrite it")).into());
    }
    check(&original).await?;
    // Upstream usbip bind first unbinds the device's driver, then creates a
    // match entry and binds usbip-host. Any of these stages can fail.
    // https://github.com/torvalds/linux/blob/master/tools/usb/usbip/src/usbip_bind.c
    let result = command::run("usbip", &["bind", "--busid", busid], &[]).await;
    if result
        .as_ref()
        .is_err_and(|error| error.kind() == io::ErrorKind::WouldBlock)
    {
        return Err(BindError::unreconciled(result.err().unwrap_or_else(|| {
            io::Error::other("USB/IP command is still running")
        })));
    }
    let after = read_snapshot(busid).await;
    if result.is_err() && after.as_ref().is_ok_and(|current| current.device.shared) {
        // A failed bind is not proof that we created this sharing: an external
        // usbip bind may have won the race. Never unbind based only on snapshots.
        return Err(BindError::unreconciled(io::Error::other(format!(
            "USB {busid} became shared during a failed bind ({}); ownership is ambiguous, leaving sharing untouched",
            result
                .err()
                .map_or_else(|| "unknown failure".to_owned(), |error| error.to_string())
        ))));
    }
    let valid = after.as_ref().is_ok_and(|current| {
        current.identity == original.identity && current.device.shared && !current.device.busy
    });
    if result.is_ok() && valid {
        return Ok(Lease {
            original: Some(original),
        });
    }
    let error = result.err().unwrap_or_else(|| {
        io::Error::other(format!(
            "USB {busid} changed identity or did not enter available USB/IP state"
        ))
    });
    match restore(&original).await {
        Ok(()) => Err(error.into()),
        Err(cleanup) => Err(BindError::unreconciled(io::Error::other(format!(
            "{error}; partial Linux bind recovery failed: {cleanup}; inspect USB {busid} driver and usbip-host match table manually"
        )))),
    }
}

async fn restore(original: &Snapshot) -> io::Result<()> {
    check(original).await?;
    let busid = &original.device.busid;
    let mut current = read_snapshot(busid).await?;
    if current.driver.as_deref() == Some("usbip-host") {
        // Upstream unbind also deletes match_busid and triggers device_attach
        // through usbip-host/rebind. This reprobes the default driver, not
        // necessarily the drivers that were bound before our session.
        // https://github.com/torvalds/linux/blob/master/tools/usb/usbip/src/usbip_unbind.c
        let result = command::run("usbip", &["unbind", "--busid", busid], &[]).await;
        if result
            .as_ref()
            .is_err_and(|error| error.kind() == io::ErrorKind::WouldBlock)
        {
            return result.map(|_| ());
        }
        check(original).await?;
        current = read_snapshot(busid).await?;
        if current.driver.as_deref() == Some("usbip-host") {
            return Err(io::Error::other(format!(
                "USB {busid} remains shared: {}",
                result.err().map_or_else(
                    || "usbip unbind reported success".to_owned(),
                    |error| error.to_string()
                )
            )));
        }
        // A nonzero exit may merely mean the default reprobe failed; continue
        // with explicit original-driver recovery and verify the final state.
    }
    check(original).await?;
    if matching(busid).await? {
        write_attribute(
            original,
            Path::new(DRIVERS).join("usbip-host/match_busid"),
            &format!("del {busid}"),
        )
        .await?;
    }
    restore_device_driver(original, &current).await?;
    restore_configuration(original).await?;
    if !original.interfaces.is_empty() {
        let current = read_snapshot(busid).await?;
        if current.configuration != original.configuration
            || current.interfaces.keys().ne(original.interfaces.keys())
        {
            return Err(io::Error::other(format!(
                "USB {busid} configuration/interfaces changed; cannot safely restore original interface drivers"
            )));
        }
        for (interface, expected) in &original.interfaces {
            restore_interface(original, interface, expected.as_deref()).await?;
        }
    }
    check(original).await?;
    let final_state = read_snapshot(busid).await?;
    if final_state.driver != original.driver
        || final_state.interfaces != original.interfaces
        || final_state.configuration != original.configuration
        || matching(busid).await?
    {
        return Err(io::Error::other(format!(
            "USB {busid} driver state differs from its pre-session snapshot after cleanup"
        )));
    }
    Ok(())
}

async fn restore_configuration(original: &Snapshot) -> io::Result<()> {
    let current = read_snapshot(&original.device.busid).await?;
    if current.configuration == original.configuration {
        return Ok(());
    }
    // usbip-host/rebind reprobes the generic USB driver, which may select its
    // default configuration rather than the pre-session configuration.
    // bConfigurationValue_store calls usb_set_configuration; -1 explicitly
    // unconfigures a device that originally had no active configuration.
    let value = original.configuration.map_or_else(
        || "-1".to_owned(),
        |configuration| configuration.to_string(),
    );
    write_attribute(
        original,
        Path::new(DEVICES)
            .join(&original.device.busid)
            .join("bConfigurationValue"),
        &value,
    )
    .await?;
    let restored = read_snapshot(&original.device.busid).await?;
    if restored.configuration != original.configuration {
        return Err(io::Error::other(format!(
            "USB {} did not return to its original configuration",
            original.device.busid
        )));
    }
    Ok(())
}

async fn restore_device_driver(original: &Snapshot, current: &Snapshot) -> io::Result<()> {
    if current.driver == original.driver {
        return Ok(());
    }
    // The tool's rebind can select the core USB driver. Any other unexpected
    // device driver indicates external interference; do not unbind it.
    if let Some(driver) = &current.driver {
        if driver != "usb" {
            return Err(io::Error::other(format!(
                "USB {} now uses unexpected driver {driver}; refusing cleanup",
                original.device.busid
            )));
        }
        driver_write(original, driver, "unbind", &original.device.busid).await?;
    }
    if let Some(driver) = &original.driver {
        driver_write(original, driver, "bind", &original.device.busid).await?;
    }
    Ok(())
}

async fn restore_interface(
    original: &Snapshot,
    interface: &str,
    expected: Option<&str>,
) -> io::Result<()> {
    check(original).await?;
    let path = Path::new(DEVICES).join(interface);
    let current = sysfs::driver(&path)?;
    if current.as_deref() == expected {
        return Ok(());
    }
    if let Some(driver) = current {
        driver_write(original, &driver, "unbind", interface).await?;
    }
    if let Some(driver) = expected {
        driver_write(original, driver, "bind", interface).await?;
    }
    check(original).await?;
    if sysfs::driver(&path)?.as_deref() != expected {
        return Err(io::Error::other(format!(
            "USB interface {interface} did not return to original driver {expected:?}"
        )));
    }
    Ok(())
}

async fn driver_write(
    original: &Snapshot,
    driver: &str,
    action: &str,
    busid: &str,
) -> io::Result<()> {
    write_attribute(
        original,
        Path::new(DRIVERS).join(driver).join(action),
        busid,
    )
    .await
}

async fn write_attribute(original: &Snapshot, path: PathBuf, value: &str) -> io::Result<()> {
    check(original).await?;
    let path = path
        .to_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "non-UTF8 USB sysfs path"))?;
    // Driver bind/unbind can block inside the kernel. An isolated, bounded
    // writer avoids leaving an unbounded spawn_blocking task in the runtime.
    // tee opens these existing sysfs attributes; it never installs a driver.
    command::run("tee", &["--", path], value.as_bytes()).await.map(|_| ())
        .map_err(|error| io::Error::new(error.kind(), format!("cannot restore USB {} via {path}: {error}; root/sysfs write permission is required", original.device.busid)))
}

async fn read_snapshot(busid: &str) -> io::Result<Snapshot> {
    sysfs::snapshot(Path::new(DEVICES), busid).await
}

async fn check(snapshot: &Snapshot) -> io::Result<()> {
    snapshot.check(Path::new(DEVICES)).await
}

async fn matching(busid: &str) -> io::Result<bool> {
    let value = sysfs::attribute(&Path::new(DRIVERS).join("usbip-host"), "match_busid").await
        .map_err(|error| io::Error::new(error.kind(), format!("cannot inspect usbip-host match table: {error}; load the installed usbip-host module before exporting")))?;
    Ok(value.split_ascii_whitespace().any(|entry| entry == busid))
}
