//! Raw NTFS file acquisition.
//!
//! This is the universal lock bypass that mirrors what Velociraptor's
//! `ntfs` accessor and KAPE's RawCopy.exe do: open the raw volume
//! (`\\.\C:`) as a block device, parse the NTFS structures, and reconstruct
//! the requested file from MFT extents — without ever going through the
//! Windows file-system layer that enforces sharing locks.
//!
//! This works for ALL files including:
//!   - Registry hives (SAM, SECURITY, SOFTWARE, SYSTEM)
//!   - NTUSER.DAT for users not currently logged on
//!   - $MFT, $LogFile, $Extend\$UsnJrnl
//!   - Pagefile.sys (for memory forensics)
//!   - In-use database files
//!
//! Requires: admin (`SeBackupPrivilege` is enough to open `\\.\C:`).
//!
//! NOT in scope for this module:
//!   - File system parsing for FAT, ReFS, etc. — NTFS only. (For our
//!     Windows-collector use case, system volumes are always NTFS.)
//!   - Sparse file reconstruction beyond zero-fill.

pub mod raw_ntfs;

use anyhow::Result;
use std::path::Path;

/// Best-effort raw NTFS read of a Windows path. Returns the number of bytes
/// written. The path may begin with a drive letter ("C:\Windows\...") or
/// be a forward-slash relative path under the system drive ("Windows/...").
pub fn read_locked_file(src_windows_path: &str, dst: &Path) -> Result<u64> {
    raw_ntfs::extract(src_windows_path, dst)
}
