//! Write/read integrity check of a receiving-side volume mounted through remoteusb.
//! Only a uniquely named temporary directory on the selected volume is changed.

use std::ffi::OsString;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const DRIVE_VARIABLE: &str = "REMOTEUSB_TEST_DRIVE";
const BLOCK_BYTES: usize = 16 * 1024;
const BLOCKS: usize = 1024;

/// Selected volume root: a drive letter, Windows volume GUID path, or absolute
/// mounted directory. Relative paths are rejected so the working directory is
/// never selected by accident.
#[derive(Debug)]
pub struct VolumeCheck {
    root: PathBuf,
}

/// Bytes written plus read back by one [`VolumeCheck::run`], and its duration.
pub struct VolumeReport {
    pub bytes: u64,
    pub elapsed: Duration,
}

/// Decimal megabytes per second, kept in hundredths to avoid lossy float casts.
pub struct Megabytes {
    hundredths: u128,
}

impl VolumeCheck {
    /// Reads `REMOTEUSB_TEST_DRIVE`; `None` when unset.
    pub fn from_env() -> io::Result<Option<Self>> {
        std::env::var_os(DRIVE_VARIABLE)
            .map(Self::parse)
            .transpose()
    }

    pub fn parse(value: OsString) -> io::Result<Self> {
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
        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Writes 16 MiB, verifies it after flush/close/reopen, overwrites one block
    /// and verifies random access around it, then removes the test directory.
    pub fn run(&self) -> io::Result<VolumeReport> {
        let started = Instant::now();
        if !self.root.is_dir() {
            return Err(io::Error::other(
                "selected volume is not mounted or accessible",
            ));
        }
        let temporary = tempfile::Builder::new()
            .prefix("remoteusb-io-test-")
            .tempdir_in(&self.root)?;
        let path = temporary.path().join("payload.bin");
        eprintln!(
            "Testing selected mounted volume {}; writing 16 MiB to {}",
            self.root.display(),
            path.display()
        );
        let mut seed = [0; 32];
        getrandom::fill(&mut seed).map_err(io::Error::other)?;
        let mut buffer = [0; BLOCK_BYTES];
        let mut blocks_moved = 0;
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
            blocks_moved += BLOCKS;
        }
        {
            let mut file = File::open(&path)?;
            for block in 0..BLOCKS {
                verify_block(&mut file, &seed, block, block)?;
            }
            assert_eq!(file.read(&mut buffer[..1])?, 0, "unexpected trailing bytes");
            blocks_moved += BLOCKS;
        }
        eprintln!("PASS: all 16 MiB match after flush, close, and reopen");
        let changed = BLOCKS / 2;
        {
            let mut file = OpenOptions::new().write(true).open(&path)?;
            file.seek(SeekFrom::Start(offset(changed)))?;
            pattern(&mut buffer, &seed, BLOCKS);
            file.write_all(&buffer)?;
            file.sync_all()?;
            blocks_moved += 1;
        }
        {
            let mut file = File::open(&path)?;
            let probes = [changed + 1, changed, changed - 1, 0, BLOCKS - 1];
            for block in probes {
                verify_block(
                    &mut file,
                    &seed,
                    block,
                    if block == changed { BLOCKS } else { block },
                )?;
            }
            assert_eq!(file.metadata()?.len(), offset(BLOCKS));
            blocks_moved += probes.len();
        }
        temporary.close()?;
        eprintln!(
            "PASS: random overwrite persisted, neighboring blocks unchanged, test files removed"
        );
        Ok(VolumeReport {
            bytes: offset(blocks_moved),
            elapsed: started.elapsed(),
        })
    }
}

impl VolumeReport {
    pub fn throughput(&self) -> Megabytes {
        // Bytes per microsecond are decimal megabytes per second.
        Megabytes {
            hundredths: u128::from(self.bytes) * 100 / self.elapsed.as_micros().max(1),
        }
    }
}

impl fmt::Display for VolumeReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} bytes written and read back in {} ms ({} MB/s)",
            self.bytes,
            self.elapsed.as_millis(),
            self.throughput()
        )
    }
}

impl fmt::Display for Megabytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}.{:02}",
            self.hundredths / 100,
            self.hundredths % 100
        )
    }
}

fn offset(blocks: usize) -> u64 {
    u64::try_from(blocks * BLOCK_BYTES).expect("test file offsets fit u64")
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
    file.seek(SeekFrom::Start(offset(block)))?;
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
