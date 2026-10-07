//! Private inventory metadata, separate from USB/IP descriptors and payloads.

use std::collections::BTreeSet;
use std::io;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::invalid_data;
use crate::usbip::BusId;

pub(crate) const REQUEST: [u8; 8] = *b"RUSBINV1";
const MAX_BYTES: usize = 1024 * 1024;
const MAX_DEVICES: usize = 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct Device {
    pub busid: BusId,
    pub vendor: u16,
    pub product: u16,
    pub name: String,
    pub shared: bool,
    pub busy: bool,
}

fn validate(devices: &[Device]) -> io::Result<()> {
    if devices.len() > MAX_DEVICES {
        return Err(invalid_data("USB inventory exceeds 1024 devices"));
    }
    let mut ids = BTreeSet::new();
    for device in devices {
        if !ids.insert(device.busid)
            || device.name.len() > 4096
            || device.name.chars().any(char::is_control)
        {
            return Err(invalid_data(
                "USB inventory has duplicate BUSIDs or invalid display names",
            ));
        }
    }
    Ok(())
}

pub(crate) async fn send(
    writer: &mut (impl AsyncWrite + Unpin),
    devices: &[Device],
) -> io::Result<()> {
    validate(devices)?;
    let bytes = serde_json::to_vec(devices).map_err(io::Error::other)?;
    if bytes.len() > MAX_BYTES {
        return Err(invalid_data("USB inventory exceeds one MiB"));
    }
    let length = u32::try_from(bytes.len()).map_err(io::Error::other)?;
    writer.write_all(&length.to_be_bytes()).await?;
    writer.write_all(&bytes).await
}

pub(crate) async fn receive(reader: &mut (impl AsyncRead + Unpin)) -> io::Result<Vec<Device>> {
    let length = usize::try_from(reader.read_u32().await?).map_err(io::Error::other)?;
    if length > MAX_BYTES {
        return Err(invalid_data("USB inventory exceeds one MiB"));
    }
    let mut bytes = vec![0; length];
    reader.read_exact(&mut bytes).await?;
    let devices: Vec<Device> = serde_json::from_slice(&bytes)
        .map_err(|error| invalid_data(format!("invalid USB inventory: {error}")))?;
    validate(&devices)?;
    Ok(devices)
}

/// Prefer the offline USB database; the OS description helps unknown products.
pub(crate) fn display_name(device: &Device) -> String {
    use usb_ids::FromId;
    if let Some(entry) = usb_ids::Device::from_vid_pid(device.vendor, device.product) {
        return format!("{} : {}", entry.vendor().name(), entry.name());
    }
    if !device.name.is_empty() {
        return device.name.clone();
    }
    let vendor =
        usb_ids::Vendor::from_id(device.vendor).map_or("Unknown vendor", usb_ids::Vendor::name);
    format!("{vendor} : Unknown device")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn rejects_oversized_and_truncated_inventory_before_display() {
        assert!(
            receive(&mut (u32::MAX.to_be_bytes().as_slice()))
                .await
                .is_err()
        );
        assert!(receive(&mut [0, 0, 0, 2, b'['].as_slice()).await.is_err());
    }

    #[tokio::test]
    async fn decoding_rejects_invalid_busids() {
        for (busid, valid) in [("1-2", true), ("../device", false)] {
            let json = format!(
                r#"[{{"busid":"{busid}","vendor":1,"product":2,"name":"Device","shared":false,"busy":false}}]"#
            );
            let mut bytes = u32::try_from(json.len()).unwrap().to_be_bytes().to_vec();
            bytes.extend_from_slice(json.as_bytes());
            assert_eq!(receive(&mut bytes.as_slice()).await.is_ok(), valid);
        }
    }

    #[test]
    fn rejects_terminal_controls_and_duplicate_devices() {
        let mut device = Device {
            busid: "1-2".parse().unwrap(),
            vendor: 1,
            product: 2,
            name: "Device".into(),
            shared: false,
            busy: false,
        };
        assert!(validate(&[device.clone(), device.clone()]).is_err());
        device.name = "\u{1b}[2J".into();
        assert!(validate(&[device]).is_err());
    }
}
