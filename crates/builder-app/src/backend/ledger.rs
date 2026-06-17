//! Audit ledger — every successful build is recorded with metadata (never
//! secrets) in a single SQLite file. Append-only.

use anyhow::{Context, Result};
use rusqlite::{params, Connection};
use std::path::{Path, PathBuf};

pub struct Ledger {
    conn: Connection,
}

#[derive(Debug, Clone)]
pub struct BuildRecord {
    pub build_id: String,
    pub build_timestamp: String,
    pub target_platform: String,
    pub site_code: String,
    pub artifact_count: i64,
    pub artifacts: Vec<String>,
    pub kape_targets: Vec<String>,
    pub encryption_scheme: String,
    pub upload_kind: String,
    pub credential_vault_used: bool,
    pub chunk_upload_enabled: bool,
    pub s3_bucket: Option<String>,
    pub s3_region: Option<String>,
    pub binary_size_bytes: i64,
    pub binary_sha256: String,
    pub exe_path: String,
}

impl Ledger {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let conn = Connection::open(path)
            .with_context(|| format!("opening ledger at {}", path.display()))?;
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS builds (
                build_id              TEXT PRIMARY KEY,
                build_timestamp       TEXT NOT NULL,
                target_platform       TEXT NOT NULL,
                site_code             TEXT NOT NULL,
                artifact_count        INTEGER NOT NULL,
                artifacts_json        TEXT NOT NULL,
                kape_targets_json     TEXT NOT NULL,
                encryption_scheme     TEXT NOT NULL,
                upload_kind           TEXT NOT NULL,
                credential_vault_used INTEGER NOT NULL DEFAULT 0,
                chunk_upload_enabled  INTEGER NOT NULL DEFAULT 0,
                s3_bucket             TEXT,
                s3_region             TEXT,
                binary_size_bytes     INTEGER NOT NULL,
                binary_sha256         TEXT NOT NULL,
                exe_path              TEXT NOT NULL,
                created_at            TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE INDEX IF NOT EXISTS idx_builds_created_at ON builds(created_at DESC);
            "#,
        )?;
        Ok(Self { conn })
    }

    pub fn record(&self, r: &BuildRecord) -> Result<()> {
        self.conn.execute(
            r#"
            INSERT INTO builds (
                build_id, build_timestamp, target_platform, site_code,
                artifact_count, artifacts_json, kape_targets_json,
                encryption_scheme, upload_kind, credential_vault_used,
                chunk_upload_enabled, s3_bucket, s3_region,
                binary_size_bytes, binary_sha256, exe_path
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)
            "#,
            params![
                r.build_id,
                r.build_timestamp,
                r.target_platform,
                r.site_code,
                r.artifact_count,
                serde_json::to_string(&r.artifacts)?,
                serde_json::to_string(&r.kape_targets)?,
                r.encryption_scheme,
                r.upload_kind,
                r.credential_vault_used as i32,
                r.chunk_upload_enabled as i32,
                r.s3_bucket,
                r.s3_region,
                r.binary_size_bytes,
                r.binary_sha256,
                r.exe_path,
            ],
        )?;
        Ok(())
    }

    /// Reserved for a future "past builds" panel; the ledger records every
    /// build but no UI lists them yet.
    #[allow(dead_code)]
    pub fn list_recent(&self, limit: usize) -> Result<Vec<BuildSummary>> {
        let mut stmt = self.conn.prepare(
            "SELECT build_id, build_timestamp, target_platform, site_code, artifact_count, \
                    binary_sha256, exe_path \
             FROM builds ORDER BY created_at DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit as i64], |row| {
            Ok(BuildSummary {
                build_id: row.get(0)?,
                build_timestamp: row.get(1)?,
                target_platform: row.get(2)?,
                site_code: row.get(3)?,
                artifact_count: row.get(4)?,
                binary_sha256: row.get(5)?,
                exe_path: row.get::<_, String>(6)?.into(),
            })
        })?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }
}

/// Returned by `list_recent` (reserved for the future "past builds" panel).
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct BuildSummary {
    pub build_id: String,
    pub build_timestamp: String,
    pub target_platform: String,
    pub site_code: String,
    pub artifact_count: i64,
    pub binary_sha256: String,
    pub exe_path: PathBuf,
}
