use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub build_id: String,
    pub build_timestamp: String,
    pub site_code: String,
    pub filename_template: String,
    pub require_admin: bool,
    pub delete_after_upload: bool,
    pub silent: bool,
    pub use_vss: bool,
    pub max_collection_size_gb: u64,
    pub cpu_limit_percent: u8,
    pub concurrency: u8,
    pub progress_timeout_seconds: u64,
    pub output_format: String,
    pub artifacts: Vec<String>,
    #[serde(default)]
    pub artifact_params: HashMap<String, HashMap<String, Value>>,
    #[serde(default)]
    pub kape_targets: Vec<String>,
    pub encryption: EncryptionCfg,
    pub upload: UploadCfg,
    #[serde(default)]
    pub target_platform: String,
    #[serde(default)]
    pub embedded_sources: HashMap<String, EmbeddedArtifactSource>,
    #[serde(default)]
    pub chunk_upload: ChunkUploadCfg,
}

impl Config {
    pub fn artifact_param_str<'a>(
        &'a self,
        artifact_id: &str,
        key: &str,
        default: &'a str,
    ) -> &'a str {
        self.artifact_params
            .get(artifact_id)
            .and_then(|m| m.get(key))
            .and_then(|v| v.as_str())
            .unwrap_or(default)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionCfg {
    pub scheme: String,
    #[serde(default)]
    pub rsa_public_key_pem: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadCfg {
    pub kind: String,
    #[serde(default)]
    pub local_path: Option<String>,
    #[serde(default)]
    pub s3: Option<S3Cfg>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct S3Cfg {
    pub bucket: String,
    pub region: String,
    #[serde(default)]
    pub access_key_id: String,
    #[serde(default)]
    pub secret_access_key: String,
    #[serde(default)]
    pub endpoint: Option<String>,
    #[serde(default)]
    pub sse_kms_key_id: Option<String>,
    #[serde(default = "default_true")]
    pub verify_tls: bool,
    #[serde(default)]
    pub prefix_template: String,
    #[serde(default)]
    pub credential_vault: String,
    #[serde(default)]
    pub credential_vault_hmac: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ChunkUploadCfg {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_chunk_size")]
    pub chunk_size_mb: u64,
    #[serde(default = "default_true")]
    pub stream_mode: bool,
    #[serde(default)]
    pub low_disk_threshold_mb: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EmbeddedArtifactSource {
    #[serde(default)]
    pub r#type: String,
    #[serde(default)]
    pub platform: String,
    #[serde(default)]
    pub sources: Vec<Value>,
}

fn default_true() -> bool { true }
fn default_chunk_size() -> u64 { 64 }
