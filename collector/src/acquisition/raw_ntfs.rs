//! Raw NTFS reader using the `ntfs` crate.
//!
//! Pipeline:
//!   1. Open `\\.\C:` (or whichever drive the file is on) as a block device
//!      with `FILE_FLAG_BACKUP_SEMANTICS`. Requires admin (`SeBackupPrivilege`).
//!   2. Hand the handle to the `ntfs` crate as a `Read + Seek` source.
//!   3. Resolve the requested path component-by-component starting from the
//!      root directory, doing case-insensitive name matches.
//!   4. Open the file's default `$DATA` attribute and stream its bytes to
//!      the destination.
//!
//! This bypasses the file-system layer entirely, so file sharing locks
//! (the `os error 32` we hit on registry hives) don't apply. It's the
//! same approach Velociraptor uses for its `ntfs` accessor and what
//! KAPE's RawCopy.exe does.

use anyhow::{anyhow, bail, Context, Result};
use ntfs::Ntfs;
use ntfs::NtfsReadSeek;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, Read, Seek, Write};
use std::path::Path;

#[cfg(windows)]
use std::os::windows::fs::OpenOptionsExt;

/// Buffer size when streaming file data out.
const COPY_BUF: usize = 1024 * 1024;

/// Open a raw volume by drive letter (e.g. "C") with backup semantics.
fn open_volume(drive_letter: char) -> Result<BufReader<File>> {
    let path = format!(r"\\.\{drive_letter}:");
    #[cfg(windows)]
    {
        const BACKUP_SEMANTICS: u32 = 0x02000000;
        const SHARE_ALL: u32 = 7; // FILE_SHARE_READ | _WRITE | _DELETE
        let f = OpenOptions::new()
            .read(true)
            .share_mode(SHARE_ALL)
            .custom_flags(BACKUP_SEMANTICS)
            .open(&path)
            .with_context(|| format!("opening raw volume {path} (admin required)"))?;
        Ok(BufReader::with_capacity(64 * 1024, f))
    }
    #[cfg(not(windows))]
    {
        let f = File::open(&path).with_context(|| format!("opening {path}"))?;
        Ok(BufReader::with_capacity(64 * 1024, f))
    }
}

/// Parse a Windows-style path into (drive_letter, components).
fn parse_path(input: &str) -> Result<(char, Vec<String>)> {
    let normalized = input.replace('\\', "/");
    let (drive, rest) = if normalized.len() >= 2 && normalized.chars().nth(1) == Some(':') {
        let d = normalized.chars().next().unwrap().to_ascii_uppercase();
        let rest = &normalized[2..];
        (d, rest.trim_start_matches('/').to_string())
    } else {
        ('C', normalized.trim_start_matches('/').to_string())
    };
    if rest.is_empty() {
        bail!("empty path component list");
    }
    let comps: Vec<String> = rest
        .split('/')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect();
    Ok((drive, comps))
}

/// Extract a file from the NTFS volume to `dst`. Returns bytes written.
pub fn extract(src_windows_path: &str, dst: &Path) -> Result<u64> {
    let (drive, components) = parse_path(src_windows_path)?;
    let mut volume = open_volume(drive)?;
    let mut ntfs = Ntfs::new(&mut volume).context("opening NTFS structures on volume")?;
    // Try to populate the upcase table — needed for proper case-insensitive
    // matching against unicode filenames. Best-effort.
    let _ = ntfs.read_upcase_table(&mut volume);

    // Walk the path components from the root.
    let root = ntfs.root_directory(&mut volume).context("opening NTFS root directory")?;
    let mut current = root;
    for (i, comp) in components.iter().enumerate() {
        let is_last = i + 1 == components.len();

        let index = current
            .directory_index(&mut volume)
            .with_context(|| format!("opening directory index for component {comp:?}"))?;
        let mut iter = index.entries();

        let mut found: Option<ntfs::NtfsFile<'_>> = None;
        while let Some(entry_res) = iter.next(&mut volume) {
            let entry = match entry_res {
                Ok(e) => e,
                Err(_) => continue,
            };
            let key = match entry.key() {
                Some(Ok(k)) => k,
                _ => continue,
            };
            let entry_name = key.name().to_string_lossy();
            if entry_name.eq_ignore_ascii_case(comp) {
                let file = entry
                    .to_file(&ntfs, &mut volume)
                    .with_context(|| format!("resolving entry {comp:?} to file"))?;
                found = Some(file);
                break;
            }
        }
        let file = found.ok_or_else(|| anyhow!("path component not found: {comp}"))?;
        if is_last {
            return write_file_data(&ntfs, &mut volume, &file, dst);
        }
        current = file;
    }
    bail!("walked all components but never reached final file (logic bug)")
}

fn write_file_data<T: Read + Seek>(
    ntfs: &Ntfs,
    volume: &mut T,
    file: &ntfs::NtfsFile<'_>,
    dst: &Path,
) -> Result<u64> {
    // Default unnamed $DATA attribute (most files; ADS streams have names).
    let data_item = file
        .data(volume, "")
        .ok_or_else(|| anyhow!("file has no default $DATA attribute"))?
        .context("opening $DATA attribute")?;
    let attr = data_item.to_attribute().context("$DATA to_attribute")?;
    let mut value = attr.value(volume).context("$DATA value reader")?;

    if let Some(parent) = dst.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let mut out = File::create(dst).with_context(|| format!("creating {}", dst.display()))?;

    let mut total: u64 = 0;
    let mut buf = vec![0u8; COPY_BUF];
    loop {
        let n = value
            .read(volume, &mut buf)
            .map_err(|e| anyhow!("reading NTFS data run: {e}"))?;
        if n == 0 {
            break;
        }
        out.write_all(&buf[..n]).context("writing dst")?;
        total += n as u64;
    }
    out.flush().ok();

    let _ = ntfs; // keep ntfs alive for the lifetime of the value reader
    Ok(total)
}
