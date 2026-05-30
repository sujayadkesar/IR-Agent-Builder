//! AWS Signature Version 4 signer — slim version, used only by the Step 3
//! "Validate S3 connection" button. The collector has its own copy (in
//! `collector/src/upload/s3.rs`); they don't interfere.

use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone)]
pub struct SignedHeaders {
    pub authorization: String,
    pub x_amz_date: String,
    pub x_amz_content_sha256: String,
}

pub struct SignParams<'a> {
    pub method: &'a str,
    pub host: &'a str,
    pub canonical_uri: &'a str,
    pub canonical_query: &'a str,
    pub extra_headers: &'a [(&'a str, &'a str)],
    pub body: &'a [u8],
    pub region: &'a str,
    pub service: &'a str,
    pub access_key_id: &'a str,
    pub secret_access_key: &'a str,
    pub now: DateTime<Utc>,
}

pub fn sign(p: &SignParams<'_>) -> SignedHeaders {
    let amz_date = p.now.format("%Y%m%dT%H%M%SZ").to_string();
    let date_stamp = p.now.format("%Y%m%d").to_string();
    let payload_hash = hex::encode(Sha256::digest(p.body));

    // Build the full header set (host + x-amz-* + caller extras)
    let mut headers: Vec<(String, String)> = vec![
        ("host".into(), p.host.into()),
        ("x-amz-content-sha256".into(), payload_hash.clone()),
        ("x-amz-date".into(), amz_date.clone()),
    ];
    for (k, v) in p.extra_headers {
        headers.push((k.to_lowercase(), (*v).to_string()));
    }
    headers.sort_by(|a, b| a.0.cmp(&b.0));

    let canonical_headers: String = headers
        .iter()
        .map(|(k, v)| format!("{k}:{}\n", v.trim()))
        .collect();
    let signed_headers: String = headers
        .iter()
        .map(|(k, _)| k.as_str())
        .collect::<Vec<_>>()
        .join(";");

    let canonical_request = format!(
        "{}\n{}\n{}\n{canonical_headers}\n{signed_headers}\n{payload_hash}",
        p.method, p.canonical_uri, p.canonical_query
    );

    let credential_scope = format!("{date_stamp}/{}/{}/aws4_request", p.region, p.service);
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n{}",
        hex::encode(Sha256::digest(canonical_request.as_bytes()))
    );

    let k_date = hmac_bytes(
        format!("AWS4{}", p.secret_access_key).as_bytes(),
        date_stamp.as_bytes(),
    );
    let k_region = hmac_bytes(&k_date, p.region.as_bytes());
    let k_service = hmac_bytes(&k_region, p.service.as_bytes());
    let k_signing = hmac_bytes(&k_service, b"aws4_request");
    let signature = hex::encode(hmac_bytes(&k_signing, string_to_sign.as_bytes()));

    SignedHeaders {
        authorization: format!(
            "AWS4-HMAC-SHA256 Credential={}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}",
            p.access_key_id
        ),
        x_amz_date: amz_date,
        x_amz_content_sha256: payload_hash,
    }
}

fn hmac_bytes(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut m = HmacSha256::new_from_slice(key).expect("HMAC key");
    m.update(msg);
    m.finalize().into_bytes().to_vec()
}
