//! OS driver ownership stays in the CLI; a lease changes only newly created sharing.
//! Machine-scoped locks coordinate remoteusb exporters, not external admin tools.
//! Operators must not change sharing/driver state through other tools during a lease.

use std::io;

use crate::usbip::BusId;

#[cfg(any(windows, target_os = "linux"))]
mod command;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(any(windows, target_os = "linux"))]
mod lock;
#[cfg(windows)]
mod windows;

/// The managed exporter's host for this OS, selected in this one place.
#[cfg(windows)]
pub(super) type Host = windows::WindowsHost;
/// The managed exporter's host for this OS, selected in this one place.
#[cfg(target_os = "linux")]
pub(super) type Host = linux::LinuxHost;
/// The managed exporter's host for this OS, selected in this one place.
#[cfg(not(any(windows, target_os = "linux")))]
pub(super) type Host = Unsupported;

/// OS sharing control: device inventory and lock-guarded binding.
pub(super) trait DeviceHost: Clone + Send + Sync + 'static {
    /// Ownership of one bound device, released through [`Lease::restore`].
    type Lease: Lease;

    /// This OS's host; fails where managed exporting is unsupported.
    fn new() -> io::Result<Self>;

    /// Exportable devices, sorted by BUSID.
    fn inventory(&self) -> impl Future<Output = io::Result<Vec<crate::inventory::Device>>> + Send;

    /// Lock and share `busid`; the returned lease owns restoring prior state.
    fn bind(&self, busid: BusId) -> impl Future<Output = Result<Self::Lease, BindError>> + Send;
}

/// A device bound by [`DeviceHost::bind`], holding its ownership locks.
pub(super) trait Lease: Send + 'static {
    /// Restore pre-bind state, then release ownership locks.
    fn restore(self) -> impl Future<Output = io::Result<()>> + Send;
}

#[derive(Debug)]
pub(super) struct BindError {
    pub(super) error: io::Error,
    pub(super) cleanup_failed: bool,
}

impl From<io::Error> for BindError {
    fn from(error: io::Error) -> Self {
        Self {
            error,
            cleanup_failed: false,
        }
    }
}

#[cfg(any(windows, target_os = "linux"))]
impl BindError {
    fn unreconciled(error: io::Error) -> Self {
        Self {
            error,
            cleanup_failed: true,
        }
    }
}

#[cfg(any(windows, target_os = "linux"))]
fn device_name(value: &str) -> String {
    let mut name = String::new();
    for character in value.chars() {
        let character = if character.is_control() {
            ' '
        } else {
            character
        };
        if name.len() + character.len_utf8() > 4096 {
            break;
        }
        name.push(character);
    }
    name
}

/// No managed exporting host exists on this OS: [`DeviceHost::new`] always
/// fails, so no value, inventory or lease of this type can exist.
#[cfg(not(any(windows, target_os = "linux")))]
#[derive(Clone, Copy, Debug)]
pub(super) enum Unsupported {}

#[cfg(not(any(windows, target_os = "linux")))]
impl DeviceHost for Unsupported {
    type Lease = Self;

    fn new() -> io::Result<Self> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "managed USB exporting requires Windows usbipd-win or Linux usbip-host",
        ))
    }

    fn inventory(&self) -> impl Future<Output = io::Result<Vec<crate::inventory::Device>>> + Send {
        async move { match *self {} }
    }

    fn bind(&self, _busid: BusId) -> impl Future<Output = Result<Self, BindError>> + Send {
        async move { match *self {} }
    }
}

#[cfg(not(any(windows, target_os = "linux")))]
impl Lease for Unsupported {
    fn restore(self) -> impl Future<Output = io::Result<()>> + Send {
        async move { match self {} }
    }
}

#[cfg(all(test, any(windows, target_os = "linux")))]
mod tests {
    #[test]
    fn inventory_names_strip_terminal_controls_and_bound_unicode_bytes() {
        assert_eq!(super::device_name("USB\u{1b}[2J\nDevice"), "USB [2J Device");
        let name = super::device_name(&"界".repeat(2000));
        assert_eq!(name.len(), 4095);
        assert!(!name.chars().any(char::is_control));
    }
}
