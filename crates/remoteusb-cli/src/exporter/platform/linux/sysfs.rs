use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use crate::usbip::BusId;

pub(super) const DEVICES: &str = "/sys/bus/usb/devices";
pub(super) const DRIVERS: &str = "/sys/bus/usb/drivers";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Identity {
    path: PathBuf,
    inode: u64,
    filesystem: u64,
    device_number: u32,
    vendor: u16,
    product: u16,
    serial: Option<String>,
}

#[derive(Debug)]
pub(super) struct Snapshot {
    pub(super) identity: Identity,
    pub(super) device: crate::inventory::Device,
    pub(super) driver: Option<String>,
    pub(super) interfaces: BTreeMap<String, Option<String>>,
    pub(super) configuration: Option<u8>,
}

// Read actual USB device records, not interface symlinks or root hubs. Linux
// imports on vhci_hcd cannot be exported again (the usbip tool rejects loops).
pub(super) fn device_busid(busid: BusId) -> bool {
    let Some((bus, ports)) = busid.as_str().split_once('-') else {
        return false;
    };
    numeric_component(bus) && ports.split('.').all(numeric_component)
}

fn numeric_component(value: &str) -> bool {
    !value.is_empty() && !value.starts_with('0') && value.bytes().all(|byte| byte.is_ascii_digit())
}

fn interface_name(busid: &str, name: &str) -> bool {
    let Some(suffix) = name
        .strip_prefix(busid)
        .and_then(|value| value.strip_prefix(':'))
    else {
        return false;
    };
    let Some((configuration, interface)) = suffix.split_once('.') else {
        return false;
    };
    name.len() <= 63
        && [configuration, interface]
            .into_iter()
            .all(|value| !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
}

pub(super) async fn snapshot(root: &Path, busid: BusId) -> io::Result<Snapshot> {
    if !device_busid(busid) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not a Linux USB device BUSID",
        ));
    }
    let path = fs::canonicalize(root.join(busid.as_str()))?;
    if path.components().any(|component| {
        component
            .as_os_str()
            .to_string_lossy()
            .starts_with("vhci_hcd")
    }) {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "cannot export an imported vhci_hcd USB device",
        ));
    }
    let metadata = fs::metadata(&path)?;
    let vendor = hexadecimal(&attribute(&path, "idVendor").await?)?;
    let product = hexadecimal(&attribute(&path, "idProduct").await?)?;
    if hexadecimal(&attribute(&path, "bDeviceClass").await?)? == 9 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "USB hubs cannot be exported",
        ));
    }
    let identity = Identity {
        path: path.clone(),
        inode: metadata.ino(),
        filesystem: metadata.dev(),
        device_number: attribute(&path, "devnum")
            .await?
            .parse()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid USB devnum"))?,
        vendor,
        product,
        serial: optional_attribute(&path, "serial").await?,
    };
    let current_driver = driver(&path)?;
    let shared = current_driver.as_deref() == Some("usbip-host");
    let busy = shared
        && attribute(&path, "usbip_status")
            .await?
            .parse::<u32>()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid USB/IP status"))?
            != 1;
    let mut interfaces = BTreeMap::new();
    for entry in fs::read_dir(&path)? {
        let entry = entry?;
        let name = entry.file_name().into_string().map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "non-UTF8 USB interface name")
        })?;
        if interface_name(busid.as_str(), &name) {
            interfaces.insert(name, driver(&entry.path())?);
            if interfaces.len() > 256 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "USB device exceeds 256 interfaces",
                ));
            }
        }
    }
    let name = optional_attribute(&path, "product")
        .await?
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| format!("USB {vendor:04x}:{product:04x}"));
    let snapshot = Snapshot {
        identity,
        device: crate::inventory::Device {
            busid,
            vendor,
            product,
            name: super::super::device_name(&name),
            shared,
            busy,
        },
        driver: current_driver,
        interfaces,
        configuration: configuration(&attribute(&path, "bConfigurationValue").await?)?,
    };
    // Detect hotplug/reenumeration while collecting the snapshot.
    snapshot.check(root).await?;
    Ok(snapshot)
}

impl Snapshot {
    pub(super) async fn check(&self, root: &Path) -> io::Result<()> {
        let path = fs::canonicalize(root.join(self.device.busid.as_str())).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "USB {} disappeared; refusing cleanup by reusable BUSID: {error}",
                    self.device.busid
                ),
            )
        })?;
        let metadata = fs::metadata(&path)?;
        let same = path == self.identity.path
            && metadata.ino() == self.identity.inode
            && metadata.dev() == self.identity.filesystem
            && attribute(&path, "devnum").await?.parse::<u32>().ok()
                == Some(self.identity.device_number)
            && hexadecimal(&attribute(&path, "idVendor").await?)? == self.identity.vendor
            && hexadecimal(&attribute(&path, "idProduct").await?)? == self.identity.product
            && optional_attribute(&path, "serial").await? == self.identity.serial;
        if !same {
            return Err(io::Error::other(format!(
                "USB {} identity changed; refusing to modify the replacement device",
                self.device.busid
            )));
        }
        Ok(())
    }
}

pub(super) fn driver(path: &Path) -> io::Result<Option<String>> {
    match fs::read_link(path.join("driver")) {
        Ok(target) => {
            let name = target
                .file_name()
                .and_then(|value| value.to_str())
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid USB driver symlink")
                })?;
            if !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
                || name == "."
                || name == ".."
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid USB driver name",
                ));
            }
            Ok(Some(name.to_owned()))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

pub(super) async fn attribute(path: &Path, name: &str) -> io::Result<String> {
    let path = path.join(name);
    // Metadata lookup does not invoke the USB attribute's show callback. In
    // particular product, serial and bConfigurationValue reads acquire the
    // kernel's USB device lock and must not run in an uncancellable Rust task.
    fs::metadata(&path)?;
    let path = path
        .to_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "non-UTF8 USB sysfs path"))?;
    let bytes = super::super::command::run("cat", &["--", path], &[]).await?;
    if bytes.len() > 4096 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "USB sysfs attribute exceeds 4096 bytes",
        ));
    }
    String::from_utf8(bytes)
        .map(|value| value.trim().to_owned())
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "USB sysfs attribute is not UTF-8",
            )
        })
}

async fn optional_attribute(path: &Path, name: &str) -> io::Result<Option<String>> {
    match attribute(path, name).await {
        Ok(value) => Ok(Some(value)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn configuration(value: &str) -> io::Result<Option<u8>> {
    if value.is_empty() {
        return Ok(None);
    }
    if !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid USB configuration value",
        ));
    }
    value
        .parse()
        .map(Some)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

fn hexadecimal(value: &str) -> io::Result<u16> {
    if value.is_empty() || value.len() > 4 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid USB hexadecimal attribute",
        ));
    }
    u16::from_str_radix(value, 16)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The BUSID `fixture` creates.
    fn busid() -> BusId {
        "1-2".parse().unwrap()
    }

    #[test]
    fn busids_exclude_interfaces_hubs_and_path_traversal() {
        // Inventory skips names that are not BUSIDs or not device records.
        let device = |name: &str| name.parse::<BusId>().is_ok_and(device_busid);
        for valid in ["1-2", "12-3.4.5"] {
            assert!(device(valid));
        }
        for invalid in [
            "usb1",
            "1-0",
            "0-1",
            "1-2:1.0",
            "1-2..3",
            "../1-2",
            "1-2/driver",
            "01-2",
        ] {
            assert!(!device(invalid));
        }
    }

    #[test]
    fn interface_names_require_exact_device_parent_and_numeric_suffixes() {
        assert!(interface_name("1-2", "1-2:1.0"));
        assert!(interface_name("1-2", "1-2:1.255"));
        for invalid in [
            "1-20:1.0",
            "1-2:1.0/driver",
            "1-2:1.x",
            "1-2:1.0.1",
            "1-2::1.0",
        ] {
            assert!(!interface_name("1-2", invalid));
        }
    }

    #[test]
    fn hexadecimal_attributes_fail_closed() {
        assert_eq!(hexadecimal("aBcD").unwrap(), 0xabcd);
        for invalid in ["", "10000", "-1", "0x12", "gg"] {
            assert!(hexadecimal(invalid).is_err());
        }
    }

    #[test]
    fn configuration_preserves_nondefault_and_unconfigured_states() {
        assert_eq!(configuration("2").unwrap(), Some(2));
        assert_eq!(configuration("255").unwrap(), Some(255));
        assert_eq!(configuration("").unwrap(), None);
        for invalid in ["256", "-1", "1 2", "1\n2", "abc"] {
            assert!(configuration(invalid).is_err());
        }
    }

    fn fixture(root: &Path) -> PathBuf {
        let device = root.join("1-2");
        fs::create_dir(&device).unwrap();
        for (name, value) in [
            ("idVendor", "1234\n"),
            ("idProduct", "abcd\n"),
            ("bDeviceClass", "00\n"),
            ("devnum", "3\n"),
            ("bConfigurationValue", "1\n"),
            ("serial", "serial\n"),
        ] {
            fs::write(device.join(name), value).unwrap();
        }
        device
    }

    #[tokio::test]
    async fn snapshots_preserve_bound_and_unbound_interface_driver_identity() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        let device = fixture(root.path());
        let drivers = root.path().join("drivers");
        fs::create_dir_all(drivers.join("usb")).unwrap();
        fs::create_dir_all(drivers.join("custom-storage")).unwrap();
        symlink(drivers.join("usb"), device.join("driver")).unwrap();
        let first = device.join("1-2:1.0");
        fs::create_dir(&first).unwrap();
        symlink(drivers.join("custom-storage"), first.join("driver")).unwrap();
        fs::create_dir(device.join("1-2:1.1")).unwrap();
        let state = snapshot(root.path(), busid()).await.unwrap();
        assert_eq!(state.driver.as_deref(), Some("usb"));
        assert_eq!(
            state.interfaces.get("1-2:1.0"),
            Some(&Some("custom-storage".to_owned()))
        );
        assert_eq!(state.interfaces.get("1-2:1.1"), Some(&None));
        assert!(!state.device.shared);
    }

    #[tokio::test]
    async fn preexisting_sharing_and_busy_status_are_reported_without_mutation() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        let device = fixture(root.path());
        let driver = root.path().join("usbip-host");
        fs::create_dir(&driver).unwrap();
        symlink(&driver, device.join("driver")).unwrap();
        fs::write(device.join("usbip_status"), "1\n").unwrap();
        let available = snapshot(root.path(), busid()).await.unwrap();
        assert!(available.device.shared);
        assert!(!available.device.busy);
        fs::write(device.join("usbip_status"), "2\n").unwrap();
        assert!(snapshot(root.path(), busid()).await.unwrap().device.busy);
        fs::write(device.join("usbip_status"), "invalid").unwrap();
        assert!(snapshot(root.path(), busid()).await.is_err());
    }

    #[tokio::test]
    async fn identity_rejects_busid_reuse_even_same_hardware_and_serial() {
        let root = tempfile::tempdir().unwrap();
        let device = fixture(root.path());
        let original = snapshot(root.path(), busid()).await.unwrap();
        fs::rename(&device, root.path().join("old")).unwrap();
        fixture(root.path());
        assert!(original.check(root.path()).await.is_err());
    }

    #[tokio::test]
    async fn identity_rejects_reenumeration_and_hubs() {
        let root = tempfile::tempdir().unwrap();
        let device = fixture(root.path());
        let original = snapshot(root.path(), busid()).await.unwrap();
        fs::write(device.join("devnum"), "4").unwrap();
        assert!(original.check(root.path()).await.is_err());
        fs::write(device.join("bDeviceClass"), "09").unwrap();
        assert!(snapshot(root.path(), busid()).await.is_err());
    }
}
