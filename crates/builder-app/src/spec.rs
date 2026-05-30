//! BuildSpec — the entire wizard state, serialized to disk during dev so
//! restarts don't lose the form. Mirrors the v2 `BuildSpec` from the legacy
//! TypeScript UI but with stricter typing.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TargetPlatform {
    Windows,
    Linux,
}

impl Default for TargetPlatform {
    fn default() -> Self { TargetPlatform::Windows }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum UploadKind {
    Local,
    S3,
}

impl Default for UploadKind {
    fn default() -> Self { UploadKind::Local }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum EncryptionScheme {
    X509,
    None,
}

impl Default for EncryptionScheme {
    fn default() -> Self { EncryptionScheme::X509 }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum OutputFormat {
    Jsonl,
    Csv,
}

impl Default for OutputFormat {
    fn default() -> Self { OutputFormat::Jsonl }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UploadConfig {
    pub kind: UploadKind,
    pub local_path: String,
    pub bucket: String,
    pub region: String,
    pub access_key_id: String,
    pub secret_access_key: String,
    pub endpoint: String,
    pub sse_kms_key_id: String,
    pub verify_tls: bool,
    pub prefix_template: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EncryptionConfig {
    pub scheme: EncryptionScheme,
    pub public_key_pem: String,
    /// Shown once on Step 4. The user is expected to copy it elsewhere; this
    /// field is cleared after they confirm.
    pub private_key_pem: String,
    pub fingerprint_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkUploadConfig {
    pub enabled: bool,
    pub chunk_size_mb: u64,
    pub stream_mode: bool,
    pub low_disk_threshold_mb: u64,
}

impl Default for ChunkUploadConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            chunk_size_mb: 256,
            stream_mode: false,
            low_disk_threshold_mb: 2048,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildSpec {
    pub site_code: String,
    pub filename_template: String,
    pub target_platform: TargetPlatform,

    pub artifacts: Vec<String>,
    pub artifact_params: BTreeMap<String, BTreeMap<String, serde_json::Value>>,
    pub kape_targets: Vec<String>,
    pub use_vss: bool,

    pub upload: UploadConfig,
    pub chunk_upload: ChunkUploadConfig,

    pub encryption: EncryptionConfig,
    pub require_admin: bool,
    pub silent: bool,
    pub delete_after_upload: bool,

    pub cpu_limit_percent: u8,
    pub concurrency: u8,
    pub progress_timeout_seconds: u64,
    pub output_format: OutputFormat,
    pub max_collection_size_gb: u64,
}

impl Default for BuildSpec {
    fn default() -> Self {
        Self {
            site_code: "APAC-HYD".to_string(),
            filename_template: "%FQDN%-%TIMESTAMP%-%UUID%".to_string(),
            target_platform: TargetPlatform::Windows,
            artifacts: Vec::new(),
            artifact_params: BTreeMap::new(),
            kape_targets: Vec::new(),
            use_vss: true,
            upload: UploadConfig {
                kind: UploadKind::Local,
                local_path: "C:\\IR\\Output".to_string(),
                prefix_template: "%SITE%/%FQDN%".to_string(),
                verify_tls: true,
                ..Default::default()
            },
            chunk_upload: ChunkUploadConfig::default(),
            encryption: EncryptionConfig {
                scheme: EncryptionScheme::X509,
                ..Default::default()
            },
            require_admin: true,
            silent: true,
            delete_after_upload: true,
            cpu_limit_percent: 0,
            concurrency: 2,
            progress_timeout_seconds: 3600,
            output_format: OutputFormat::Jsonl,
            max_collection_size_gb: 0,
        }
    }
}
