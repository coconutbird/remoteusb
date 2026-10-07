use std::fs::{self, File, OpenOptions, TryLockError};
use std::io;
use std::path::Path;

pub(super) fn acquire(busid: &str) -> io::Result<File> {
    crate::inventory::validate_busid(busid)?;
    open_lock(&machine_directory()?, busid)
}

#[cfg(windows)]
pub(super) fn acquire_identity(instance: &str) -> io::Result<File> {
    let root = identity_directory(&machine_directory()?, instance)?;
    fs::create_dir_all(&root)?;
    open_lock(&root, "lease")
}

#[cfg(windows)]
fn identity_directory(root: &Path, instance: &str) -> io::Result<std::path::PathBuf> {
    if instance.is_empty() || instance.len() > 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows USB instance identity exceeds its ownership-lock bound",
        ));
    }
    // Exact byte encoding avoids hash collisions and algorithm changes across
    // builds. Chunked components stay below filesystem filename limits.
    let instance = instance.to_ascii_uppercase();
    let mut path = root.join("identities");
    for chunk in instance.as_bytes().chunks(40) {
        let mut encoded = String::with_capacity(chunk.len() * 2);
        for byte in chunk {
            use std::fmt::Write;
            write!(&mut encoded, "{byte:02x}").map_err(io::Error::other)?;
        }
        path.push(encoded);
    }
    Ok(path)
}

fn machine_directory() -> io::Result<std::path::PathBuf> {
    #[cfg(windows)]
    let root = std::env::var_os("ProgramData")
        .map(std::path::PathBuf::from)
        .filter(|path| path.is_absolute())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "absolute ProgramData directory is required for machine-wide USB ownership locks",
            )
        })?
        .join("remoteusb/locks");
    #[cfg(target_os = "linux")]
    let root = std::path::PathBuf::from("/run/lock/remoteusb");
    fs::create_dir_all(&root).map_err(|error| io::Error::new(error.kind(), format!("cannot create USB ownership lock directory {}: {error}; driver-management and directory write permission are required", root.display())))?;
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = fs::symlink_metadata(&root)?;
        if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "USB ownership lock directory must be root-owned and not group/world-writable",
            ));
        }
    }
    Ok(root)
}

fn open_lock(root: &Path, busid: &str) -> io::Result<File> {
    crate::inventory::validate_busid(busid)?;
    if !fs::symlink_metadata(root)?.file_type().is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "USB ownership lock directory must be a real directory, not a symlink",
        ));
    }
    let path = root.join(format!("device-{busid}.lock"));
    match fs::symlink_metadata(&path) {
        Ok(metadata) if !metadata.file_type().is_file() => {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "USB ownership lock must be a regular file, not a symlink",
            ));
        }
        Ok(_) => (),
        Err(error) if error.kind() == io::ErrorKind::NotFound => (),
        Err(error) => return Err(error),
    }
    // Keep the file permanently: unlinking after unlock lets a third process
    // lock a new inode while another waiter still owns the original inode.
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "USB ownership lock is not a regular file",
        ));
    }
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(TryLockError::WouldBlock) => Err(io::Error::new(
            io::ErrorKind::ResourceBusy,
            format!("USB {busid} is reserved by another remoteusb exporter"),
        )),
        Err(TryLockError::Error(error)) => Err(io::Error::new(
            error.kind(),
            format!("cannot lock USB {busid}: {error}"),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_is_exclusive_and_reusable_without_unlinking() {
        let root = tempfile::tempdir().unwrap();
        let first = open_lock(root.path(), "1-2").unwrap();
        assert_eq!(
            open_lock(root.path(), "1-2").unwrap_err().kind(),
            io::ErrorKind::ResourceBusy
        );
        let independent = open_lock(root.path(), "1-3").unwrap();
        drop(first);
        assert!(root.path().join("device-1-2.lock").is_file());
        let reacquired = open_lock(root.path(), "1-2").unwrap();
        drop((independent, reacquired));
    }

    #[cfg(windows)]
    #[test]
    fn stable_identity_lock_cannot_be_bypassed_by_moving_between_busids() {
        let root = tempfile::tempdir().unwrap();
        let identity = "USB\\VID_1234&PID_5678\\serial";
        let first_path = identity_directory(root.path(), identity).unwrap();
        let moved_path = identity_directory(root.path(), &identity.to_ascii_lowercase()).unwrap();
        assert_eq!(first_path, moved_path);
        fs::create_dir_all(&first_path).unwrap();
        let old_busid = open_lock(root.path(), "1-2").unwrap();
        let identity_lease = open_lock(&first_path, "lease").unwrap();
        let new_busid = open_lock(root.path(), "1-3").unwrap();
        assert_eq!(
            open_lock(&moved_path, "lease").unwrap_err().kind(),
            io::ErrorKind::ResourceBusy
        );
        drop(identity_lease);
        assert!(open_lock(&moved_path, "lease").is_ok());
        drop((old_busid, new_busid));
    }

    #[cfg(windows)]
    #[test]
    fn exact_identity_encoding_has_no_path_or_prefix_aliases() {
        let root = tempfile::tempdir().unwrap();
        let short = identity_directory(root.path(), &"A".repeat(40)).unwrap();
        let long = identity_directory(root.path(), &"A".repeat(41)).unwrap();
        assert_ne!(short, long);
        let unusual = identity_directory(root.path(), "USB\\VID_1234&PID_5678\\../serial").unwrap();
        assert!(unusual.starts_with(root.path().join("identities")));
        assert!(identity_directory(root.path(), &"x".repeat(1025)).is_err());
    }

    #[test]
    fn invalid_busid_cannot_escape_lock_directory() {
        let root = tempfile::tempdir().unwrap();
        for invalid in ["../escape", ".", "", "1-2/other"] {
            // The wire BUSID grammar permits a lone '.', but its filename is
            // prefixed and suffixed, so it is not a path component escape.
            if invalid == "." {
                continue;
            }
            assert!(open_lock(root.path(), invalid).is_err());
        }
        assert!(open_lock(root.path(), ".").is_ok());
    }
}
