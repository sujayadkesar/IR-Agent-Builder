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
    /// Per-artifact parameter map. Outer key is the artifact id (e.g.
    /// "browser.chrome"); inner keys are param keys (e.g. "scope") with
    /// JSON-typed values (strings / numbers / booleans).
    #[serde(default)]
    pub artifact_params: HashMap<String, HashMap<String, Value>>,
    #[serde(default)]
    pub kape_targets: Vec<String>,
    pub encryption: EncryptionCfg,
    pub upload: UploadCfg,
}

impl Config {
    /// Get a string parameter for an artifact, or fall back to `default`.
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
    pub scheme: String,             // "x509" | "none"
    #[serde(default)]
    pub rsa_public_key_pem: String, // PEM-encoded RSA public key
}

/// Flat upload config — any unused fields are simply ignored.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadCfg {
    pub kind: String, // "local" | "s3"
    #[serde(default)]
    pub local_path: Option<String>,
    #[serde(default)]
    pub s3: Option<S3Cfg>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct S3Cfg {
    pub bucket: String,
    pub region: String,
    pub access_key_id: String,
    pub secret_access_key: String,
    #[serde(default)]
    pub endpoint: Option<String>,
    #[serde(default)]
    pub sse_kms_key_id: Option<String>,
    #[serde(default = "default_true")]
    pub verify_tls: bool,
    #[serde(default)]
    pub prefix_template: String,
}

fn default_true() -> bool { true }
