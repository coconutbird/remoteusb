//! Explicit hardware integration against a volume already mounted through remoteusb.
//! Set `REMOTEUSB_TEST_DRIVE` to a drive letter, Windows volume GUID path, or mounted
//! directory and run this ignored test. Only a unique temporary directory is changed;
//! the operator owns USB attachment, mount selection, and tunnel lifetime.

use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;

const BLOCK_BYTES: usize = 16 * 1024;
const BLOCKS: usize = 1024;

fn selected_root(value: OsString) -> io::Result<PathBuf> {
    #[cfg(windows)]
    let value = match value.to_str() {
        Some(letter) if letter.len() == 1 && letter.as_bytes()[0].is_ascii_alphabetic() => {
            OsString::from(format!("{letter}:\\"))
        }
        Some(drive)
            if drive.len() == 2
                && drive.as_bytes()[0].is_ascii_alphabetic()
                && drive.as_bytes()[1] == b':' =>
        {
            OsString::from(format!("{drive}\\"))
        }
        _ => value,
    };
    let root = PathBuf::from(value);
    if !root.is_absolute() {
        return Err(io::Error::other(
            "select a drive letter or absolute mounted-volume path",
        ));
    }
    Ok(root)
}

fn pattern(buffer: &mut [u8], seed: &[u8; 32], block: usize) {
    for (offset, byte) in buffer.iter_mut().enumerate() {
        *byte = seed[offset % seed.len()]
            .wrapping_add(u8::try_from((offset + block * 73) % 251).expect("bounded remainder"));
    }
    buffer[..8].copy_from_slice(&u64::try_from(block).unwrap().to_le_bytes());
}

fn verify_block(
    file: &mut File,
    seed: &[u8; 32],
    block: usize,
    expected_block: usize,
) -> io::Result<()> {
    let mut actual = [0; BLOCK_BYTES];
    let mut expected = [0; BLOCK_BYTES];
    file.seek(SeekFrom::Start(u64::try_from(block * BLOCK_BYTES).unwrap()))?;
    file.read_exact(&mut actual)?;
    pattern(&mut expected, seed, expected_block);
    // Report the offset, not an entire generated block, on corruption.
    if let Some(offset) = actual.iter().zip(&expected).position(|(a, b)| a != b) {
        return Err(io::Error::other(format!(
            "data mismatch at byte {}",
            block * BLOCK_BYTES + offset
        )));
    }
    Ok(())
}

#[test]
#[ignore = "writes a test file to REMOTEUSB_TEST_DRIVE; explicitly select a volume mounted through remoteusb"]
fn selected_usb_drive_preserves_flushed_writes_and_random_access() -> io::Result<()> {
    let root = selected_root(std::env::var_os("REMOTEUSB_TEST_DRIVE").ok_or_else(|| {
        io::Error::other("set REMOTEUSB_TEST_DRIVE, for example D: or a Windows volume GUID path")
    })?)?;
    if !root.is_dir() {
        return Err(io::Error::other(
            "selected volume is not mounted or accessible",
        ));
    }
    let temporary = tempfile::Builder::new()
        .prefix("remoteusb-io-test-")
        .tempdir_in(&root)?;
    let path = temporary.path().join("payload.bin");
    eprintln!(
        "Testing selected mounted volume {}; writing 16 MiB to {}",
        root.display(),
        path.display()
    );
    let mut seed = [0; 32];
    getrandom::fill(&mut seed).map_err(io::Error::other)?;
    let mut buffer = [0; BLOCK_BYTES];
    {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)?;
        for block in 0..BLOCKS {
            pattern(&mut buffer, &seed, block);
            file.write_all(&buffer)?;
        }
        file.sync_all()?;
    }
    {
        let mut file = File::open(&path)?;
        for block in 0..BLOCKS {
            verify_block(&mut file, &seed, block, block)?;
        }
        assert_eq!(file.read(&mut buffer[..1])?, 0, "unexpected trailing bytes");
    }
    eprintln!("PASS: all 16 MiB match after flush, close, and reopen");
    let changed = BLOCKS / 2;
    {
        let mut file = OpenOptions::new().write(true).open(&path)?;
        file.seek(SeekFrom::Start(
            u64::try_from(changed * BLOCK_BYTES).unwrap(),
        ))?;
        pattern(&mut buffer, &seed, BLOCKS);
        file.write_all(&buffer)?;
        file.sync_all()?;
    }
    {
        let mut file = File::open(&path)?;
        for block in [changed + 1, changed, changed - 1, 0, BLOCKS - 1] {
            verify_block(
                &mut file,
                &seed,
                block,
                if block == changed { BLOCKS } else { block },
            )?;
        }
        assert_eq!(
            file.metadata()?.len(),
            u64::try_from(BLOCKS * BLOCK_BYTES).unwrap()
        );
    }
    temporary.close()?;
    eprintln!("PASS: random overwrite persisted, neighboring blocks unchanged, test files removed");
    Ok(())
}

#[test]
fn relative_paths_cannot_silently_select_the_working_directory() {
    assert!(selected_root("relative/path".into()).is_err());
    assert!(selected_root(OsString::new()).is_err());
}

#[cfg(windows)]
#[test]
fn drive_letters_select_the_root_not_the_drive_current_directory() -> io::Result<()> {
    for input in ["D", "D:", "D:\\"] {
        assert_eq!(selected_root(input.into())?, PathBuf::from("D:\\"));
    }
    let volume = r"\\?\Volume{12345678-1234-1234-1234-123456789abc}\";
    assert_eq!(selected_root(volume.into())?, PathBuf::from(volume));
    Ok(())
}
