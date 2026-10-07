//! Explicit hardware integration against a volume already mounted through remoteusb.
//! Set `REMOTEUSB_TEST_DRIVE` to a drive letter, Windows volume GUID path, or mounted
//! directory and run this ignored test. Only a unique temporary directory is changed;
//! the operator owns USB attachment, mount selection, and tunnel lifetime.

#[path = "support/drive.rs"]
mod drive;

use std::ffi::OsString;
use std::io;

use drive::VolumeCheck;

#[test]
#[ignore = "writes a test file to REMOTEUSB_TEST_DRIVE; explicitly select a volume mounted through remoteusb"]
fn selected_usb_drive_preserves_flushed_writes_and_random_access() -> io::Result<()> {
    let volume = VolumeCheck::from_env()?.ok_or_else(|| {
        io::Error::other("set REMOTEUSB_TEST_DRIVE, for example D: or a Windows volume GUID path")
    })?;
    let report = volume.run()?;
    eprintln!("{}: {report}", volume.root().display());
    Ok(())
}

#[test]
fn relative_paths_cannot_silently_select_the_working_directory() {
    assert!(VolumeCheck::parse("relative/path".into()).is_err());
    assert!(VolumeCheck::parse(OsString::new()).is_err());
}

#[cfg(windows)]
#[test]
fn drive_letters_select_the_root_not_the_drive_current_directory() -> io::Result<()> {
    use std::path::Path;

    for input in ["D", "D:", "D:\\"] {
        assert_eq!(VolumeCheck::parse(input.into())?.root(), Path::new("D:\\"));
    }
    let volume = r"\\?\Volume{12345678-1234-1234-1234-123456789abc}\";
    assert_eq!(VolumeCheck::parse(volume.into())?.root(), Path::new(volume));
    Ok(())
}
