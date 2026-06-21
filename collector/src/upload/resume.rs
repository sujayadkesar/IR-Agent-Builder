//! Pending-upload state for resuming an S3 upload across a process interruption
//! (crash / reboot / kill mid-upload, followed by a re-run of the same build).
//!
//! Persisted to a fixed temp path. It holds NO credentials — a resume reuses the
//! re-run's own vault-decrypted credentials, so a wrong/old state can never leak
//! secrets. The container's filename embeds the run UUID + timestamp, so
//! `container_path + file_size + build_id` is a sufficient fingerprint to confirm
//! "this is the same file" without re-hashing gigabytes on every boot.
//!
//! Resume is strictly best-effort: any mismatch or permanent error discards the
//! state and the collector proceeds with a fresh collection (never a hard gate —
//! otherwise a lifecycle-reaped multipart would wedge every future run).

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PendingUpload {
    pub object_key: String,
    pub container_path: String,
    pub file_size: u64,
    pub part_size: u64,
    /// `None` = single-shot PutObject (a resume re-PUTs the whole file).
    pub upload_id: Option<String>,
    /// (part_number, etag) for parts S3 has already accepted.
    pub completed_parts: Vec<(u32, String)>,
    pub build_id: String,
    pub created_at: String,
}

pub fn state_path() -> PathBuf {
    std::env::temp_dir().join("dfir-pending-upload.json")
}

/// Persist state (best-effort — a failure here must not abort the upload).
pub fn save(p: &PendingUpload) {
    match serde_json::to_vec_pretty(p) {
        Ok(bytes) => {
            if let Err(e) = std::fs::write(state_path(), bytes) {
                log::warn!("[resume] could not persist upload state: {e}");
            }
        }
        Err(e) => log::warn!("[resume] could not serialize upload state: {e}"),
    }
}

pub fn load() -> Option<PendingUpload> {
    let bytes = std::fs::read(state_path()).ok()?;
    serde_json::from_slice(&bytes).ok()
}

pub fn clear() {
    let _ = std::fs::remove_file(state_path());
}

/// Part numbers (1-based) that still need uploading for a file of `file_size`
/// split into `part_size` chunks, given the parts already completed.
pub fn missing_parts(file_size: u64, part_size: u64, completed: &[(u32, String)]) -> Vec<u32> {
    if part_size == 0 {
        return Vec::new();
    }
    let total = file_size.div_ceil(part_size) as u32;
    let done: HashSet<u32> = completed.iter().map(|(n, _)| *n).collect();
    (1..=total).filter(|n| !done.contains(n)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> PendingUpload {
        PendingUpload {
            object_key: "SITE/HOST/c.zip.enc".into(),
            container_path: r"C:\tmp\c.zip.enc".into(),
            file_size: 100,
            part_size: 16,
            upload_id: Some("uid".into()),
            completed_parts: vec![(1, "e1".into()), (2, "e2".into())],
            build_id: "b1".into(),
            created_at: "2026-06-21T00:00:00Z".into(),
        }
    }

    #[test]
    fn serde_round_trips() {
        let p = sample();
        let bytes = serde_json::to_vec(&p).unwrap();
        let back: PendingUpload = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(p, back);
    }

    #[test]
    fn missing_parts_skips_completed() {
        // 100 bytes / 16 = 7 parts (ceil). Parts 1,2 done -> 3..=7 remain.
        let done = vec![(1u32, "e1".to_string()), (2, "e2".to_string())];
        assert_eq!(missing_parts(100, 16, &done), vec![3, 4, 5, 6, 7]);
        // none done -> all parts
        assert_eq!(missing_parts(100, 16, &[]), vec![1, 2, 3, 4, 5, 6, 7]);
        // all done -> empty
        let all: Vec<(u32, String)> = (1..=7).map(|n| (n, format!("e{n}"))).collect();
        assert!(missing_parts(100, 16, &all).is_empty());
    }
}
