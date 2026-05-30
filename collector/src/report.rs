use crate::artifacts::ArtifactStats;
use crate::config::Config;
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::time::Duration;
use uuid::Uuid;

#[derive(Debug, Serialize)]
pub struct RunReport {
    pub build_id: String,
    pub run_id: String,
    pub hostname: String,
    pub site_code: String,
    pub collection_name: String,
    pub started_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    pub artifacts: Vec<ArtifactRecord>,
    pub total_files: u64,
    pub total_bytes: u64,
    pub failures: u32,
}

#[derive(Debug, Serialize)]
pub struct ArtifactRecord {
    pub name: String,
    pub status: String,
    pub file_count: u64,
    pub bytes: u64,
    pub elapsed_ms: u128,
    pub error: Option<String>,
}

impl RunReport {
    pub fn new(cfg: &Config, hostname: &str, collection_name: &str, run_id: Uuid) -> Self {
        Self {
            build_id: cfg.build_id.clone(),
            run_id: run_id.to_string(),
            hostname: hostname.to_string(),
            site_code: cfg.site_code.clone(),
            collection_name: collection_name.to_string(),
            started_at: Utc::now(),
            finished_at: None,
            artifacts: Vec::new(),
            total_files: 0,
            total_bytes: 0,
            failures: 0,
        }
    }

    pub fn record_success(&mut self, name: &str, stats: ArtifactStats, elapsed: Duration) {
        self.total_files += stats.file_count;
        self.total_bytes += stats.bytes;
        self.artifacts.push(ArtifactRecord {
            name: name.to_string(),
            status: "ok".to_string(),
            file_count: stats.file_count,
            bytes: stats.bytes,
            elapsed_ms: elapsed.as_millis(),
            error: None,
        });
    }

    pub fn record_failure(&mut self, name: &str, err: String) {
        self.failures += 1;
        self.artifacts.push(ArtifactRecord {
            name: name.to_string(),
            status: "failed".to_string(),
            file_count: 0,
            bytes: 0,
            elapsed_ms: 0,
            error: Some(err),
        });
    }

    pub fn finalize(&mut self) {
        self.finished_at = Some(Utc::now());
    }
}
