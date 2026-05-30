//! Builds the JSON blob that gets `include_bytes!`'d into the collector at
//! compile time. The shape mirrors `collector/src/config.rs::Config`
//! exactly — this is the integration contract between builder and collector.

use anyhow::Result;
use serde_json::json;
use std::collections::HashMap;

use crate::spec::{BuildSpec, EncryptionScheme, OutputFormat, TargetPlatform, UploadKind};
use shared_crypto::credential_vault::{self, Credentials};

/// Placeholder config written back after every build so the collector source
/// tree is never left with real credentials checked in.
pub fn placeholder() -> serde_json::Value {
    json!({
        "build_id": "placeholder",
        "build_timestamp": "1970-01-01T00:00:00Z",
        "site_code": "PLACEHOLDER",
        "filename_template": "%FQDN%-%TIMESTAMP%-%UUID%",
        "require_admin": true,
        "delete_after_upload": true,
        "silent": true,
        "use_vss": true,
        "max_collection_size_gb": 0,
        "cpu_limit_percent": 0,
        "concurrency": 2,
        "progress_timeout_seconds": 3600,
        "output_format": "jsonl",
        "target_platform": "windows",
        "artifacts": [],
        "artifact_params": {},
        "kape_targets": [],
        "embedded_sources": {},
        "chunk_upload": {
            "enabled": false,
            "chunk_size_mb": 64,
            "stream_mode": false,
            "low_disk_threshold_mb": 0
        },
        "encryption": { "scheme": "none", "rsa_public_key_pem": "" },
        "upload": { "kind": "local", "local_path": "C:\\IR\\Output", "s3": null }
    })
}

pub struct BuiltConfig {
    pub json: serde_json::Value,
    pub credential_vault_used: bool,
}

/// Produce the embedded config from the UI spec. AWS credentials, if any,
/// are AES-GCM-encrypted into a credential vault blob — the resulting JSON
/// has no plaintext access key.
pub fn build_from_spec(
    spec: &BuildSpec,
    build_id: &str,
    build_timestamp: &str,
    embedded_sources: HashMap<String, serde_json::Value>,
) -> Result<BuiltConfig> {
    let target_platform = match spec.target_platform {
        TargetPlatform::Windows => "windows",
        TargetPlatform::Linux => "linux",
    };

    let mut upload = match spec.upload.kind {
        UploadKind::S3 => json!({
            "kind": "s3",
            "local_path": null,
            "s3": {
                "bucket": spec.upload.bucket,
                "region": spec.upload.region,
                "access_key_id": spec.upload.access_key_id,
                "secret_access_key": spec.upload.secret_access_key,
                "endpoint": opt_str(&spec.upload.endpoint),
                "sse_kms_key_id": opt_str(&spec.upload.sse_kms_key_id),
                "verify_tls": spec.upload.verify_tls,
                "prefix_template": spec.upload.prefix_template,
                "credential_vault": "",
                "credential_vault_hmac": "",
            }
        }),
        UploadKind::Local => json!({
            "kind": "local",
            "local_path": if spec.upload.local_path.is_empty() {
                default_local_path(target_platform).to_string()
            } else {
                spec.upload.local_path.clone()
            },
            "s3": null,
        }),
    };

    let mut credential_vault_used = false;
    if spec.upload.kind == UploadKind::S3
        && !spec.upload.access_key_id.is_empty()
        && !spec.upload.secret_access_key.is_empty()
    {
        let vault = credential_vault::encrypt(
            &Credentials {
                access_key_id: spec.upload.access_key_id.clone(),
                secret_access_key: spec.upload.secret_access_key.clone(),
            },
            build_id,
            build_timestamp,
        )?;
        let s3 = upload.get_mut("s3").and_then(|v| v.as_object_mut()).unwrap();
        s3.insert("access_key_id".into(), json!(""));
        s3.insert("secret_access_key".into(), json!(""));
        s3.insert("credential_vault".into(), json!(vault.blob_base64));
        s3.insert("credential_vault_hmac".into(), json!(vault.hmac_hex));
        credential_vault_used = true;
    }

    let cfg = json!({
        "build_id": build_id,
        "build_timestamp": build_timestamp,
        "site_code": spec.site_code,
        "filename_template": spec.filename_template,
        "require_admin": spec.require_admin,
        "delete_after_upload": spec.delete_after_upload,
        "silent": spec.silent,
        "use_vss": matches!(spec.target_platform, TargetPlatform::Windows) && spec.use_vss,
        "max_collection_size_gb": spec.max_collection_size_gb,
        "cpu_limit_percent": spec.cpu_limit_percent,
        "concurrency": spec.concurrency,
        "progress_timeout_seconds": spec.progress_timeout_seconds,
        "output_format": match spec.output_format {
            OutputFormat::Jsonl => "jsonl",
            OutputFormat::Csv => "csv",
        },
        "target_platform": target_platform,
        "artifacts": spec.artifacts,
        "artifact_params": spec.artifact_params,
        "kape_targets": if matches!(spec.target_platform, TargetPlatform::Windows) {
            spec.kape_targets.clone()
        } else {
            Vec::new()
        },
        "embedded_sources": embedded_sources,
        "chunk_upload": {
            "enabled": spec.chunk_upload.enabled,
            "chunk_size_mb": spec.chunk_upload.chunk_size_mb,
            "stream_mode": spec.chunk_upload.stream_mode,
            "low_disk_threshold_mb": spec.chunk_upload.low_disk_threshold_mb,
        },
        "encryption": {
            "scheme": match spec.encryption.scheme {
                EncryptionScheme::X509 => "x509",
                EncryptionScheme::None => "none",
            },
            "rsa_public_key_pem": spec.encryption.public_key_pem,
        },
        "upload": upload,
    });

    Ok(BuiltConfig {
        json: cfg,
        credential_vault_used,
    })
}

fn opt_str(s: &str) -> serde_json::Value {
    if s.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::Value::String(s.to_string())
    }
}

fn default_local_path(target_platform: &str) -> &'static str {
    if target_platform == "windows" {
        "C:\\IR\\Output"
    } else {
        "/tmp/dfir-output"
    }
}
