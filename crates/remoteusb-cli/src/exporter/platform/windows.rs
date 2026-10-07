use std::collections::BTreeSet;
use std::fs::File;
use std::io;

use serde::Deserialize;

use crate::inventory::Device;
use crate::usbip::BusId;

use super::{BindError, DeviceHost, Lease, command, lock};

// usbipd-win's DeviceExtensions.GetAll excludes USB hubs and monitor stubs.
// State also contains disconnected persisted entries, which are retained here
// for GUID cleanup but never returned as importable devices.
// https://github.com/dorssel/usbipd-win/blob/master/Usbipd.Automation/Device.cs
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct State {
    devices: Vec<Record>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Record {
    bus_id: Option<ReportedBusId>,
    instance_id: String,
    description: String,
    persisted_guid: Option<String>,
    #[serde(rename = "ClientIPAddress")]
    client_ip_address: Option<String>,
    stub_instance_id: Option<String>,
    #[serde(default)]
    is_forced: bool,
}

/// usbipd's `BusId` text. Only records with a USB hardware ID must carry a
/// valid BUSID ([`parse_state`] rejects the rest); other records may report
/// arbitrary text, kept as `Invalid`, which never equals a BUSID.
#[derive(Debug, Deserialize)]
#[serde(from = "String")]
enum ReportedBusId {
    Valid(BusId),
    Invalid,
}

impl From<String> for ReportedBusId {
    fn from(text: String) -> Self {
        text.parse().map_or(Self::Invalid, Self::Valid)
    }
}

impl Record {
    fn busid(&self) -> Option<BusId> {
        match self.bus_id {
            Some(ReportedBusId::Valid(busid)) => Some(busid),
            Some(ReportedBusId::Invalid) | None => None,
        }
    }

    fn available(&self) -> bool {
        self.busid()
            .is_some_and(|busid| !matches!(busid.as_str(), "IncompatibleHub" | "0-0"))
            && hardware_id(&self.instance_id).is_some()
    }

    fn busy(&self) -> bool {
        self.client_ip_address.is_some() || self.stub_instance_id.is_some()
    }

    fn same_identity(&self, instance: &str) -> bool {
        self.instance_id.eq_ignore_ascii_case(instance)
    }
}

/// usbipd-win sharing control.
#[derive(Clone, Copy, Debug)]
pub(in crate::exporter) struct WindowsHost;

impl DeviceHost for WindowsHost {
    type Lease = WindowsLease;

    fn new() -> io::Result<Self> {
        Ok(Self)
    }

    async fn inventory(&self) -> io::Result<Vec<Device>> {
        let mut devices = Vec::new();
        for record in state().await? {
            if !record.available() {
                continue;
            }
            let (Some(busid), Some((vendor, product))) =
                (record.busid(), hardware_id(&record.instance_id))
            else {
                continue;
            };
            devices.push(Device {
                busid,
                vendor,
                product,
                name: super::device_name(&record.description),
                shared: record.persisted_guid.is_some(),
                busy: record.busy(),
            });
        }
        devices.sort_by_key(|device| device.busid);
        Ok(devices)
    }

    async fn bind(&self, busid: BusId) -> Result<WindowsLease, BindError> {
        let instance = candidate(busid).await?;
        let lock = lock::acquire(busid).await?;
        let identity_lock = lock::acquire_identity(&instance).await?;
        // On failure, locals drop in reverse order: `identity_lock`, then
        // `lock`, both after `share` finished any partial-bind cleanup.
        let sharing = share(busid, &instance).await?;
        Ok(WindowsLease {
            sharing,
            lock,
            identity_lock,
        })
    }
}

/// A bound device and its ownership locks. Field order is drop order, so an
/// unrestored lease releases `lock` before `identity_lock`, as `restore` does.
pub(in crate::exporter) struct WindowsLease {
    sharing: Sharing,
    lock: File,
    identity_lock: File,
}

impl Lease for WindowsLease {
    async fn restore(self) -> io::Result<()> {
        let result = self.sharing.restore().await;
        // Ownership ends only after cleanup: BUSID lock, then identity lock.
        drop(self.lock);
        drop(self.identity_lock);
        result
    }
}

/// Instance identity of the exportable device currently at `busid`.
async fn candidate(busid: BusId) -> io::Result<String> {
    state()
        .await?
        .into_iter()
        .find(|record| record.available() && record.busid() == Some(busid))
        .map(|record| record.instance_id)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("USB BUSID {busid} is no longer connected or exportable"),
            )
        })
}

struct Sharing {
    // None means the sharing existed before this session. Never unbind it.
    owned: Option<(String, String)>,
}

impl Sharing {
    async fn restore(self) -> io::Result<()> {
        let Some((instance, guid)) = self.owned else {
            return Ok(());
        };
        let records = state().await?;
        let Some(record) = records
            .iter()
            .find(|record| record.persisted_guid.as_deref() == Some(&guid))
        else {
            return Ok(());
        };
        if !record.same_identity(&instance) {
            return Err(io::Error::other(format!(
                "refusing to unbind GUID {guid}: Windows device identity changed"
            )));
        }
        if record.is_forced {
            return Err(io::Error::other(format!(
                "refusing to unbind GUID {guid}: an external owner forced the Windows driver after this lease started"
            )));
        }
        // This works when unplugged or moved, and cannot target a reused BUSID.
        let result = command::run("usbipd", &["unbind", "--guid", &guid], &[]).await;
        let records = state().await.map_err(|error| {
            io::Error::other(format!("cannot verify cleanup of GUID {guid}: {error}"))
        })?;
        if records
            .iter()
            .any(|record| record.persisted_guid.as_deref() == Some(&guid))
        {
            return Err(io::Error::other(format!(
                "sharing GUID {guid} remains after cleanup: {}",
                result.err().map_or_else(
                    || "usbipd reported success".to_owned(),
                    |error| error.to_string()
                )
            )));
        }
        result.map(|_| ())
    }
}

/// Share `busid` if `instance` still occupies it; the caller holds both locks.
async fn share(busid: BusId, instance: &str) -> Result<Sharing, BindError> {
    let before = state().await?;
    let selected = before
        .iter()
        .find(|record| record.available() && record.busid() == Some(busid))
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("USB BUSID {busid} is no longer connected or exportable"),
            )
        })?;
    if !selected.same_identity(instance) {
        return Err(io::Error::other(format!(
            "USB {busid} identity changed while acquiring its ownership lock"
        ))
        .into());
    }
    if selected.busy() {
        return Err(io::Error::new(
            io::ErrorKind::ResourceBusy,
            format!("USB BUSID {busid} is already attached"),
        )
        .into());
    }
    if selected.persisted_guid.is_some() {
        return Ok(Sharing { owned: None });
    }
    if selected.is_forced {
        return Err(io::Error::new(io::ErrorKind::Unsupported, format!("USB {busid} has a preexisting forced driver without a sharing GUID; normal usbipd bind would change that driver, so restore its driver manually first")).into());
    }
    let result =
        command::run_with_stderr("usbipd", &["bind", "--busid", busid.as_str()], &[]).await;
    if result
        .as_ref()
        .is_err_and(|error| error.kind() == io::ErrorKind::WouldBlock)
    {
        return Err(BindError::unreconciled(result.err().unwrap_or_else(|| {
            io::Error::other("usbipd command is still running")
        })));
    }
    // Even a failed or terminated bind may have persisted a GUID before exiting.
    let after = state().await.map_err(|error| BindError::unreconciled(io::Error::other(format!("cannot determine sharing created for {busid} ({}): {error}; inspect usbipd state and remove only the new binding for instance {}", result.as_ref().err().map_or_else(|| "bind reported success".to_owned(), ToString::to_string), selected.instance_id))))?;
    let current = after
        .iter()
        .find(|record| record.same_identity(&selected.instance_id));
    if result
        .as_ref()
        .is_ok_and(|(_, stderr)| already_shared(stderr))
    {
        // usbipd explicitly reports a no-op: another owner shared the device
        // after our snapshot. Preserve that binding even though its GUID is new.
        if current.is_some_and(|record| {
            record.busid() == Some(busid) && record.persisted_guid.is_some() && !record.busy()
        }) {
            return Ok(Sharing { owned: None });
        }
        return Err(io::Error::other(
            "device changed during an idempotent usbipd bind; sharing was not claimed",
        )
        .into());
    }
    if let Err(error) = result {
        let changed = failed_bind_changed_target(&before, &after, &selected.instance_id, busid);
        return Err(if changed {
            BindError::unreconciled(io::Error::other(format!(
                "{error}; new sharing appeared during a failed bind, but usbipd did not prove who created its GUID; refusing to remove possibly external sharing"
            )))
        } else {
            error.into()
        });
    }
    let owned =
        newly_owned(&before, &after, &selected.instance_id).map_err(BindError::unreconciled)?;
    if after.iter().any(|record| {
        record.busid() == Some(busid)
            && !record.same_identity(&selected.instance_id)
            && record.persisted_guid.as_ref().is_some_and(|guid| {
                !before
                    .iter()
                    .any(|old| old.persisted_guid.as_ref() == Some(guid))
            })
    }) {
        // BUSID-only bind cannot atomically guard against hotplug. Do not guess
        // ownership of a replacement's GUID or continue offering this BUSID.
        let cleanup = Sharing { owned }.restore().await;
        return Err(BindError::unreconciled(io::Error::other(format!(
            "BUSID {busid} was reused during bind and the replacement has new sharing; inspect usbipd state manually; original-instance cleanup: {cleanup:?}"
        ))));
    }
    let current = after
        .iter()
        .find(|record| record.same_identity(&selected.instance_id));
    let valid = current.is_some_and(|record| {
        record.busid() == Some(busid) && record.persisted_guid.is_some() && !record.busy()
    });
    let sharing = Sharing { owned };
    if result.is_ok() && valid && sharing.owned.is_some() {
        return Ok(sharing);
    }
    let error = result.err().unwrap_or_else(|| {
        io::Error::other(format!(
            "USB identity/sharing changed while binding {busid}; refusing import"
        ))
    });
    match sharing.restore().await {
        Ok(()) => Err(error.into()),
        Err(cleanup) => Err(BindError::unreconciled(io::Error::other(format!(
            "{error}; partial bind cleanup failed: {cleanup}"
        )))),
    }
}

fn failed_bind_changed_target(
    before: &[Record],
    after: &[Record],
    instance: &str,
    busid: BusId,
) -> bool {
    after.iter().any(|record| {
        (record.same_identity(instance) || record.busid() == Some(busid))
            && record.persisted_guid.as_ref().is_some_and(|guid| {
                !before
                    .iter()
                    .any(|old| old.persisted_guid.as_ref() == Some(guid))
            })
    })
}

fn newly_owned(
    before: &[Record],
    after: &[Record],
    instance: &str,
) -> io::Result<Option<(String, String)>> {
    let Some(record) = after.iter().find(|record| record.same_identity(instance)) else {
        return Ok(None);
    };
    let Some(guid) = &record.persisted_guid else {
        return Ok(None);
    };
    if before
        .iter()
        .any(|record| record.persisted_guid.as_ref() == Some(guid))
    {
        return Err(io::Error::other(
            "bind reused a preexisting sharing GUID; refusing to claim or remove it",
        ));
    }
    Ok(Some((record.instance_id.clone(), guid.clone())))
}

async fn state() -> io::Result<Vec<Record>> {
    parse_state(&command::run("usbipd", &["state"], &[]).await?)
}

fn parse_state(bytes: &[u8]) -> io::Result<Vec<Record>> {
    let mut state: State = serde_json::from_slice(bytes).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, format!("invalid usbipd state JSON: {error}; a usbipd-win version with the state command is required")))?;
    if state.devices.len() > 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "usbipd state exceeds 1024 devices",
        ));
    }
    let mut busids = BTreeSet::new();
    let mut instances = BTreeSet::new();
    let mut guids = BTreeSet::new();
    for record in &mut state.devices {
        if let Some(guid) = record.persisted_guid.as_mut() {
            guid.make_ascii_lowercase();
        }
        if record.instance_id.is_empty()
            || !instances.insert(record.instance_id.to_ascii_uppercase())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "usbipd state contains empty/duplicate instance identities",
            ));
        }
        // Exactly the records that would be exportable with a valid BUSID
        // (neither `IncompatibleHub` nor `0-0` is invalid) must carry one.
        if matches!(record.bus_id, Some(ReportedBusId::Invalid))
            && hardware_id(&record.instance_id).is_some()
        {
            return Err(crate::invalid_data("invalid USB BUSID"));
        }
        if let Some(busid) = record.busid()
            && record.available()
            && !busids.insert(busid)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "usbipd state contains duplicate BUSIDs",
            ));
        }
        if let Some(guid) = &record.persisted_guid
            && (!valid_guid(guid) || !guids.insert(guid))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "usbipd state contains invalid/duplicate sharing GUIDs",
            ));
        }
    }
    Ok(state.devices)
}

fn valid_guid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
}

fn hardware_id(instance: &str) -> Option<(u16, u16)> {
    let upper = instance.to_ascii_uppercase();
    let id = upper.strip_prefix("USB\\")?.split('\\').next()?;
    let vendor = id.strip_prefix("VID_")?.get(..4)?;
    let tail = id.get(8..)?.strip_prefix("&PID_")?;
    let product = tail.get(..4)?;
    if tail.len() > 4 && !tail[4..].starts_with('&') {
        return None;
    }
    Some((
        u16::from_str_radix(vendor, 16).ok()?,
        u16::from_str_radix(product, 16).ok()?,
    ))
}

fn already_shared(stderr: &[u8]) -> bool {
    String::from_utf8_lossy(stderr)
        .to_ascii_lowercase()
        .contains("already shared")
}

#[cfg(test)]
mod tests {
    use super::*;

    const GUID: &str = "12345678-1234-1234-1234-123456789abc";
    fn record(busid: Option<&str>, instance: &str, guid: Option<&str>) -> Record {
        Record {
            bus_id: busid.map(|busid| ReportedBusId::from(busid.to_owned())),
            instance_id: instance.to_owned(),
            description: "Device".to_owned(),
            persisted_guid: guid.map(str::to_owned),
            client_ip_address: None,
            stub_instance_id: None,
            is_forced: false,
        }
    }

    #[test]
    fn hardware_ids_are_exact_and_case_insensitive() {
        assert_eq!(
            hardware_id("usb\\vid_1234&pid_ABCD\\serial"),
            Some((0x1234, 0xabcd))
        );
        assert_eq!(
            hardware_id("USB\\VID_1234&PID_ABCD&REV_0100\\serial"),
            Some((0x1234, 0xabcd))
        );
        assert_eq!(hardware_id("ROOT\\VID_1234&PID_ABCD"), None);
        assert_eq!(hardware_id("USB\\VID_1234&PID_ABCDjunk"), None);
    }

    #[test]
    fn disconnected_and_incompatible_entries_are_not_exportable() {
        assert!(!record(None, "USB\\VID_1234&PID_ABCD\\s", Some(GUID)).available());
        assert!(!record(Some("IncompatibleHub"), "USB\\VID_1234&PID_ABCD\\s", None).available());
    }

    #[test]
    fn moved_or_unplugged_instance_cleanup_uses_new_guid_only() {
        let before = vec![record(Some("1-2"), "USB\\VID_1234&PID_ABCD\\s", None)];
        let after = vec![
            record(None, "usb\\vid_1234&pid_abcd\\s", Some(GUID)),
            record(Some("1-2"), "USB\\VID_9999&PID_0001\\replacement", None),
        ];
        assert_eq!(
            newly_owned(&before, &after, &before[0].instance_id)
                .unwrap()
                .unwrap()
                .1,
            GUID
        );
        let preexisting = vec![record(None, "USB\\VID_9999&PID_0001\\old", Some(GUID))];
        assert!(newly_owned(&preexisting, &after, &before[0].instance_id).is_err());
    }

    #[test]
    fn failed_bind_ignores_unrelated_sharing_but_tracks_moved_and_replacement_devices() {
        let selected = "USB\\VID_1234&PID_ABCD\\a";
        let unrelated = "USB\\VID_1234&PID_ABCD\\b";
        let before = vec![
            record(Some("1-2"), selected, None),
            record(Some("1-3"), unrelated, None),
        ];
        let target: BusId = "1-2".parse().unwrap();
        let unrelated_change = vec![record(Some("1-3"), unrelated, Some(GUID))];
        assert!(!failed_bind_changed_target(
            &before,
            &unrelated_change,
            selected,
            target
        ));
        let moved = vec![record(Some("1-4"), selected, Some(GUID))];
        assert!(failed_bind_changed_target(
            &before, &moved, selected, target
        ));
        let replacement = vec![record(Some("1-2"), unrelated, Some(GUID))];
        assert!(failed_bind_changed_target(
            &before,
            &replacement,
            selected,
            target
        ));
    }

    #[test]
    fn idempotent_bind_diagnostics_do_not_grant_ownership() {
        assert!(already_shared(
            b"usbipd: info: Device with busid '1-2' was already shared.\n"
        ));
        assert!(!already_shared(
            b"usbipd: warning: A reboot may be required.\n"
        ));
    }

    #[test]
    fn state_rejects_duplicate_and_malformed_ownership() {
        let json = br#"{"Devices":[{"BusId":"1-2","InstanceId":"USB\\VID_1234&PID_5678\\s","Description":"Device","PersistedGuid":"not-a-guid"}]}"#;
        assert!(parse_state(json).is_err());
        assert!(!valid_guid("12345678-1234-1234-1234-123456789abz"));
        assert!(valid_guid(GUID));
        let json = br#"{"Devices":[{"BusId":"1-2","InstanceId":"USB\\VID_1234&PID_5678\\s","Description":"Device"},{"BusId":"1-2","InstanceId":"USB\\VID_1234&PID_5678\\other","Description":"Device"}]}"#;
        assert!(parse_state(json).is_err());
    }

    #[test]
    fn only_exportable_records_require_valid_busids() {
        let json = br#"{"Devices":[{"BusId":"1 2","InstanceId":"USB\\VID_1234&PID_5678\\s","Description":"Device"}]}"#;
        assert_eq!(
            parse_state(json).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        let json =
            br#"{"Devices":[{"BusId":"1 2","InstanceId":"ROOT\\HUB\\s","Description":"Hub"}]}"#;
        let records = parse_state(json).unwrap();
        assert!(!records[0].available());
        assert_eq!(records[0].busid(), None);
    }
}
