//! AWS IAM policy generator + S3 PutObject validator.

use anyhow::Result;
use chrono::Utc;
use serde_json::json;

use super::sigv4::{sign, SignParams};

/// Generate the write-only IAM policy JSON. The user pastes this into the
/// IAM console after setting up the AWS account.
pub fn generate_iam_policy(
    bucket: &str,
    kms_key_arn: Option<&str>,
    access_key_id: Option<&str>,
) -> serde_json::Value {
    let arn_base = format!("arn:aws:s3:::{bucket}");
    let user_prefix = access_key_id
        .map(|id| format!("{id}/*"))
        .unwrap_or_else(|| "${aws:username}/*".to_string());

    let mut put_cond = json!({
        "StringEquals": { "s3:x-amz-server-side-encryption": "aws:kms" },
        "Bool": { "aws:SecureTransport": "true" },
    });
    if let Some(kms) = kms_key_arn {
        put_cond["StringEqualsIfExists"] = json!({
            "s3:x-amz-server-side-encryption-aws-kms-key-id": kms,
        });
    }

    let mut statements = vec![json!({
        "Sid": "CollectorPutObjectOnly",
        "Effect": "Allow",
        "Action": ["s3:PutObject"],
        "Resource": format!("{arn_base}/{user_prefix}"),
        "Condition": put_cond,
    })];

    if let Some(kms) = kms_key_arn {
        statements.push(json!({
            "Sid": "CollectorKMSEncryptOnly",
            "Effect": "Allow",
            "Action": ["kms:GenerateDataKey"],
            "Resource": kms,
        }));
    }

    json!({
        "Version": "2012-10-17",
        "Statement": statements,
    })
}

pub struct ValidateInput<'a> {
    pub bucket: &'a str,
    pub region: &'a str,
    pub access_key_id: &'a str,
    pub secret_access_key: &'a str,
    pub endpoint: Option<&'a str>,
    pub sse_kms_key_id: Option<&'a str>,
}

pub struct ValidateResult {
    pub ok: bool,
    /// HTTP status from the sentinel PutObject — retained for diagnostics; the
    /// UI currently shows `message` instead.
    #[allow(dead_code)]
    pub status: u16,
    pub message: String,
    pub test_key: String,
}

/// Send a small (30 byte) PutObject to a sentinel key to confirm
/// credentials/bucket policy/encryption settings are correct.
pub fn validate_s3(input: ValidateInput<'_>) -> Result<ValidateResult> {
    let test_key = format!(
        "_dfir-validate/{}-{}.txt",
        Utc::now().timestamp_millis(),
        rand_suffix()
    );
    let body = b"dfir-agentbuilder-validate-ok\n";

    let host: String = if let Some(ep) = input.endpoint {
        ep.trim_start_matches("https://")
            .trim_start_matches("http://")
            .to_string()
    } else {
        format!("{}.s3.{}.amazonaws.com", input.bucket, input.region)
    };
    let scheme = if input.endpoint.map(|e| e.starts_with("http://")).unwrap_or(false) {
        "http"
    } else {
        "https"
    };
    let (url, canonical_uri) = if input.endpoint.is_some() {
        (
            format!("{scheme}://{host}/{}/{}", input.bucket, uri_encode_path(&test_key)),
            format!("/{}/{}", input.bucket, uri_encode_path(&test_key)),
        )
    } else {
        (
            format!("{scheme}://{host}/{}", uri_encode_path(&test_key)),
            format!("/{}", uri_encode_path(&test_key)),
        )
    };

    let mut extra: Vec<(&str, &str)> = Vec::new();
    if let Some(kms) = input.sse_kms_key_id {
        extra.push(("x-amz-server-side-encryption", "aws:kms"));
        extra.push(("x-amz-server-side-encryption-aws-kms-key-id", kms));
    }
    let signed = sign(&SignParams {
        method: "PUT",
        host: &host,
        canonical_uri: &canonical_uri,
        canonical_query: "",
        extra_headers: &extra,
        body,
        region: input.region,
        service: "s3",
        access_key_id: input.access_key_id,
        secret_access_key: input.secret_access_key,
        now: Utc::now(),
    });

    let agent = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(30))
        .build();
    let mut req = agent
        .request("PUT", &url)
        .set("Authorization", &signed.authorization)
        .set("x-amz-date", &signed.x_amz_date)
        .set("x-amz-content-sha256", &signed.x_amz_content_sha256);
    for (k, v) in &extra {
        req = req.set(k, v);
    }

    match req.send_bytes(body) {
        Ok(r) => Ok(ValidateResult {
            status: r.status(),
            ok: r.status() / 100 == 2,
            message: format!(
                "PutObject succeeded ({}). Production collector keys should NOT have DeleteObject; we did not attempt delete.",
                r.status()
            ),
            test_key,
        }),
        Err(ureq::Error::Status(code, r)) => {
            let body = r.into_string().unwrap_or_default();
            Ok(ValidateResult {
                ok: false,
                status: code,
                message: format!("HTTP {code}: {}", body.chars().take(500).collect::<String>()),
                test_key,
            })
        }
        Err(e) => Ok(ValidateResult {
            ok: false,
            status: 0,
            message: format!("Network error: {e}"),
            test_key,
        }),
    }
}

fn uri_encode_path(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.as_bytes() {
        match *b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' => {
                out.push(*b as char)
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

fn rand_suffix() -> String {
    use rand::Rng;
    let charset: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::thread_rng();
    (0..8)
        .map(|_| charset[rng.gen_range(0..charset.len())] as char)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iam_policy_includes_kms_when_provided() {
        let p = generate_iam_policy("my-bucket", Some("arn:aws:kms:us-east-1:111:key/abc"), None);
        let stmts = p["Statement"].as_array().unwrap();
        assert_eq!(stmts.len(), 2);
        assert_eq!(stmts[1]["Sid"], "CollectorKMSEncryptOnly");
    }

    #[test]
    fn iam_policy_omits_kms_when_absent() {
        let p = generate_iam_policy("my-bucket", None, None);
        let stmts = p["Statement"].as_array().unwrap();
        assert_eq!(stmts.len(), 1);
    }
}
