//! OS driver ownership stays in the CLI; a lease changes only newly created sharing.
//! Machine-scoped locks coordinate remoteusb exporters, not external admin tools.
//! Operators must not change sharing/driver state through other tools during a lease.

use std::io;

#[cfg(any(windows, target_os = "linux"))]
mod command;
#[cfg(target_os = "linux")]
#[path = "platform/linux.rs"]
mod implementation;
#[cfg(windows)]
#[path = "platform/windows.rs"]
mod implementation;
#[cfg(any(windows, target_os = "linux"))]
mod lock;

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
pub(super) struct Lease {
    #[cfg(any(windows, target_os = "linux"))]
    inner: implementation::Lease,
    #[cfg(any(windows, target_os = "linux"))]
    lock: std::fs::File,
    #[cfg(windows)]
    identity_lock: std::fs::File,
}

impl Lease {
    pub(super) async fn restore(self) -> io::Result<()> {
        #[cfg(any(windows, target_os = "linux"))]
        {
            let result = self.inner.restore().await;
            drop(self.lock);
            #[cfg(windows)]
            drop(self.identity_lock);
            result
        }
        #[cfg(not(any(windows, target_os = "linux")))]
        Err(unsupported())
    }
}

pub(super) async fn inventory() -> io::Result<Vec<crate::inventory::Device>> {
    #[cfg(any(windows, target_os = "linux"))]
    return implementation::inventory().await;
    #[cfg(not(any(windows, target_os = "linux")))]
    Err(unsupported())
}

pub(super) async fn bind(busid: &str) -> Result<Lease, BindError> {
    crate::inventory::validate_busid(busid)?;
    #[cfg(any(windows, target_os = "linux"))]
    {
        let candidate = implementation::candidate(busid).await?;
        let lock = lock::acquire(busid)?;
        #[cfg(windows)]
        let identity_lock = lock::acquire_identity(candidate.identity())?;
        implementation::bind(busid, candidate)
            .await
            .map(|inner| Lease {
                inner,
                lock,
                #[cfg(windows)]
                identity_lock,
            })
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    Err(unsupported().into())
}

#[cfg(not(any(windows, target_os = "linux")))]
fn unsupported() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "managed USB exporting requires Windows usbipd-win or Linux usbip-host",
    )
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
