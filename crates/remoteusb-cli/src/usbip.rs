//! USB/IP 1.1.1 management wire facts shared by the exporter and importer.
//!
//! The CLI inspects only `OP_DEVLIST`/`OP_IMPORT` headers and device records;
//! everything after a successful import is opaque URB traffic. Integers are
//! big-endian.

use std::fmt;
use std::io;
use std::ops::Range;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::invalid_data;

/// Protocol version carried by every management header.
const VERSION: u16 = 0x0111;

/// `ST_OK`. Failures run from `ST_NA` (1) through `ST_ERROR` (5); other
/// nonzero statuses are still failures but prove nothing about device state.
pub(crate) const ST_OK: u32 = 0;
const ST_NA: u32 = 1;
const ST_ERROR: u32 = 5;

/// Management header: version, operation code, status.
pub(crate) const HEADER_BYTES: usize = 8;
/// Exported-device record: 256-byte sysfs path, BUSID field, bus/device
/// numbers, speed and descriptors, ending with `bNumInterfaces`.
pub(crate) const DEVICE_BYTES: usize = 312;
/// NUL-terminated, zero-padded BUSID field.
pub(crate) const BUSID_BYTES: usize = 32;
/// One interface record per `bNumInterfaces` follows a device-list record.
const INTERFACE_BYTES: usize = 4;
/// `bNumInterfaces` is one byte, which bounds one device's interface records.
pub(crate) const MAX_INTERFACE_BYTES: usize = 255 * INTERFACE_BYTES;
/// A successful `OP_REP_IMPORT` carries exactly one device record.
pub(crate) const IMPORT_REPLY_BYTES: usize = HEADER_BYTES + DEVICE_BYTES;

const RECORD_BUSID: Range<usize> = 256..256 + BUSID_BYTES;
#[cfg(test)]
const RECORD_IDS: Range<usize> = 300..304;
const RECORD_INTERFACES: usize = DEVICE_BYTES - 1;

/// Management operations the CLI forwards or answers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OpCode {
    ReqDevlist,
    RepDevlist,
    ReqImport,
    RepImport,
}

impl OpCode {
    const fn code(self) -> u16 {
        match self {
            Self::ReqDevlist => 0x8005,
            Self::RepDevlist => 0x0005,
            Self::ReqImport => 0x8003,
            Self::RepImport => 0x0003,
        }
    }

    const fn from_code(code: u16) -> Option<Self> {
        match code {
            0x8005 => Some(Self::ReqDevlist),
            0x0005 => Some(Self::RepDevlist),
            0x8003 => Some(Self::ReqImport),
            0x0003 => Some(Self::RepImport),
            _ => None,
        }
    }
}

/// A protocol-1.1.1 management header. Parsing rejects other versions and
/// unknown operations, so encoding a parsed header reproduces its bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct OpHeader {
    pub(crate) code: OpCode,
    pub(crate) status: u32,
}

impl OpHeader {
    pub(crate) const DEVLIST_REQUEST: Self = Self::new(OpCode::ReqDevlist, ST_OK);
    pub(crate) const IMPORT_REQUEST: Self = Self::new(OpCode::ReqImport, ST_OK);
    /// `ST_NA` import reply: negative proof that no device was created.
    pub(crate) const IMPORT_REJECTED: Self = Self::new(OpCode::RepImport, ST_NA);

    pub(crate) const fn new(code: OpCode, status: u32) -> Self {
        Self { code, status }
    }

    pub(crate) const fn encode(self) -> [u8; HEADER_BYTES] {
        let [v0, v1] = VERSION.to_be_bytes();
        let [c0, c1] = self.code.code().to_be_bytes();
        let [s0, s1, s2, s3] = self.status.to_be_bytes();
        [v0, v1, c0, c1, s0, s1, s2, s3]
    }

    pub(crate) const fn parse(bytes: [u8; HEADER_BYTES]) -> Option<Self> {
        let [v0, v1, c0, c1, s0, s1, s2, s3] = bytes;
        if u16::from_be_bytes([v0, v1]) != VERSION {
            return None;
        }
        match OpCode::from_code(u16::from_be_bytes([c0, c1])) {
            Some(code) => Some(Self::new(code, u32::from_be_bytes([s0, s1, s2, s3]))),
            None => None,
        }
    }

    /// Only a negative `OP_REP_IMPORT` within `ST_NA..=ST_ERROR` proves the
    /// exporter rejected the import before any device was created.
    pub(crate) const fn proves_rejected_import(self) -> bool {
        matches!(self.code, OpCode::RepImport) && matches!(self.status, ST_NA..=ST_ERROR)
    }
}

/// A USB/IP BUSID: 1..=31 ASCII alphanumerics or `-` `.` `_`, which leaves
/// room for the wire field's NUL terminator and excludes path separators,
/// whitespace and terminal controls wherever a BUSID becomes a filename, lock,
/// command argument or display. Stored as its zero-padded wire field.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct BusId {
    // Invariant: `field[..len]` is a valid BUSID; the rest is zero. Zero sorts
    // below every BUSID byte, so the derived order equals string order.
    field: [u8; BUSID_BYTES],
    len: u8,
}

impl BusId {
    /// Decode a NUL-terminated, zero-padded wire field.
    pub(crate) fn decode(field: &[u8; BUSID_BYTES]) -> io::Result<Self> {
        let end = field
            .iter()
            .position(|byte| *byte == 0)
            .ok_or_else(|| invalid_data("unterminated USB/IP BUSID"))?;
        if field[end..].iter().any(|byte| *byte != 0) {
            return Err(invalid_data("nonzero USB/IP BUSID padding"));
        }
        std::str::from_utf8(&field[..end])
            .map_err(|_| invalid_data("invalid USB/IP BUSID"))?
            .parse()
    }

    /// The zero-padded wire field.
    pub(crate) const fn field(&self) -> &[u8; BUSID_BYTES] {
        &self.field
    }

    pub(crate) fn as_str(&self) -> &str {
        std::str::from_utf8(&self.field[..usize::from(self.len)])
            .expect("validated BUSIDs are ASCII")
    }
}

impl FromStr for BusId {
    type Err = io::Error;

    fn from_str(busid: &str) -> io::Result<Self> {
        let len = u8::try_from(busid.len())
            .ok()
            .filter(|len| (1..BUSID_BYTES).contains(&usize::from(*len)));
        let valid = busid
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_'));
        let (Some(len), true) = (len, valid) else {
            return Err(invalid_data("invalid USB BUSID"));
        };
        let mut field = [0; BUSID_BYTES];
        field[..busid.len()].copy_from_slice(busid.as_bytes());
        Ok(Self { field, len })
    }
}

impl AsRef<str> for BusId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for BusId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl fmt::Debug for BusId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self.as_str(), formatter)
    }
}

impl Serialize for BusId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for BusId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

/// View of one exported-device record.
#[derive(Clone, Copy)]
pub(crate) struct DeviceRecord<'a>(&'a [u8; DEVICE_BYTES]);

impl<'a> DeviceRecord<'a> {
    pub(crate) const fn new(bytes: &'a [u8; DEVICE_BYTES]) -> Self {
        Self(bytes)
    }

    pub(crate) fn busid(self) -> io::Result<BusId> {
        BusId::decode(
            self.0[RECORD_BUSID]
                .try_into()
                .expect("device records contain a BUSID field"),
        )
    }

    /// Length of the interface records following a device-list record.
    pub(crate) fn interface_bytes(self) -> usize {
        usize::from(self.0[RECORD_INTERFACES]) * INTERFACE_BYTES
    }
}

/// Zero-padded BUSID field, deliberately unvalidated so tests can send
/// hostile identifiers. Panics if `busid` exceeds the field.
#[cfg(test)]
pub(crate) fn raw_busid_field(busid: &str) -> [u8; BUSID_BYTES] {
    let mut field = [0; BUSID_BYTES];
    field[..busid.len()].copy_from_slice(busid.as_bytes());
    field
}

/// Device record carrying only a raw BUSID, vendor/product and interface
/// count; every other descriptor byte is zero.
#[cfg(test)]
pub(crate) fn test_record(
    busid: &str,
    vendor: u16,
    product: u16,
    interfaces: u8,
) -> [u8; DEVICE_BYTES] {
    let mut bytes = [0; DEVICE_BYTES];
    bytes[RECORD_BUSID].copy_from_slice(&raw_busid_field(busid));
    let [v0, v1] = vendor.to_be_bytes();
    let [p0, p1] = product.to_be_bytes();
    bytes[RECORD_IDS].copy_from_slice(&[v0, v1, p0, p1]);
    bytes[RECORD_INTERFACES] = interfaces;
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn headers_match_the_usbip_wire_format() {
        assert_eq!(
            OpHeader::DEVLIST_REQUEST.encode(),
            [1, 0x11, 0x80, 5, 0, 0, 0, 0]
        );
        assert_eq!(
            OpHeader::IMPORT_REQUEST.encode(),
            [1, 0x11, 0x80, 3, 0, 0, 0, 0]
        );
        assert_eq!(
            OpHeader::IMPORT_REJECTED.encode(),
            [1, 0x11, 0, 3, 0, 0, 0, 1]
        );
        assert_eq!(
            OpHeader::parse([1, 0x11, 0, 5, 0, 0, 0, 3]),
            Some(OpHeader::new(OpCode::RepDevlist, 3))
        );
        assert_eq!(OpHeader::parse([1, 0x10, 0, 5, 0, 0, 0, 0]), None);
        assert_eq!(OpHeader::parse([1, 0x11, 0x80, 2, 0, 0, 0, 0]), None);
    }

    #[test]
    fn only_a_valid_negative_import_header_proves_rejection() {
        let proves =
            |bytes: [u8; 8]| OpHeader::parse(bytes).is_some_and(OpHeader::proves_rejected_import);
        assert!(proves([0x01, 0x11, 0x00, 0x03, 0, 0, 0, 1]));
        assert!(proves([0x01, 0x11, 0x00, 0x03, 0, 0, 0, 5]));
        for header in [
            [0x01, 0x11, 0x00, 0x03, 0, 0, 0, 0],
            [0x01, 0x11, 0x00, 0x03, 0, 0, 0, 6],
            [0x01, 0x10, 0x00, 0x03, 0, 0, 0, 1],
            [0x01, 0x11, 0x00, 0x05, 0, 0, 0, 1],
        ] {
            assert!(!proves(header));
        }
    }

    #[test]
    fn busids_follow_one_grammar_and_order_like_strings() {
        for id in [
            "1-2",
            "12-4.1",
            "device_1",
            "A",
            "1234567890123456789012345678901",
        ] {
            assert_eq!(id.parse::<BusId>().unwrap().as_str(), id);
        }
        for id in [
            "",
            "../device",
            "a/b",
            "a b",
            "\u{1b}[2J",
            "é",
            "12345678901234567890123456789012",
        ] {
            assert!(id.parse::<BusId>().is_err());
        }
        let short: BusId = "1-2".parse().unwrap();
        let long: BusId = "1-2.1".parse().unwrap();
        assert!(short < long);
        assert!(serde_json::from_str::<BusId>("\"../device\"").is_err());
        assert_eq!(serde_json::to_string(&short).unwrap(), "\"1-2\"");
    }

    #[test]
    fn busid_fields_require_a_single_valid_zero_padded_identifier() {
        for id in ["1-2", "12-4.1", "device_1", "A"] {
            let busid = BusId::decode(&raw_busid_field(id)).unwrap();
            assert_eq!(busid.as_str(), id);
            assert_eq!(busid.field(), &raw_busid_field(id));
        }
        for id in ["", "../device", "a/b", "a b", "\u{1b}[2J", "é"] {
            assert!(BusId::decode(&raw_busid_field(id)).is_err());
        }
        assert!(BusId::decode(&[b'1'; BUSID_BYTES]).is_err());
        let mut padded = raw_busid_field("1-2");
        padded[BUSID_BYTES - 1] = b'a';
        assert!(BusId::decode(&padded).is_err());
    }
}
