//! Minimal AWS S3 SigV4 PutObject + multipart implementation.
//!
//! Designed for the *write-only embedded credential* use case (§3.3). The
//! collector's IAM user has only `s3:PutObject` and `kms:GenerateDataKey`,
//! so the only API calls we ever make are:
//!   - PUT /{key}                              (single PutObject)
//!   - POST /{key}?uploads                     (CreateMultipartUpload)
//!   - PUT  /{key}?partNumber=N&uploadId=...   (UploadPart)
//!   - POST /{key}?uploadId=...                (CompleteMultipartUpload)
//!
//! All requests sign with AWS Signature Version 4. SSE-KMS is requested via
//! `x-amz-server-side-encryption: aws:kms` plus optional
//! `x-amz-server-side-encryption-aws-kms-key-id` headers, matching §3.4.
//!
//! Addressing style:
//!   - AWS (no custom endpoint): virtual-hosted — `{bucket}.s3.{region}.amazonaws.com`,
//!     bucket lives in the host, request path is just `/{key}`.
//!   - Custom endpoint (MinIO/Ceph/etc.): path-style — host is the endpoint,
//!     the bucket is the FIRST path segment: `/{bucket}/{key}`.
//! Both the request URL and the SigV4 canonical URI use the same path, and the
//! signed `host` header includes the port when the endpoint specifies one.
//!
//! Threshold for multipart: 100MB single-shot, 16MB parts above that.

use anyhow::{anyhow, bail, Context, Result};
use chrono::Utc;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use crate::config::S3Cfg;

const SINGLE_SHOT_LIMIT: u64 = 100 * 1024 * 1024;
const MULTIPART_PART_SIZE: u64 = 16 * 1024 * 1024;

type HmacSha256 = Hmac<Sha256>;

pub fn upload(cfg: &S3Cfg, file: &Path, object_key: &str) -> Result<()> {
    // The caller (main.rs) has already resolved the prefix template, so we
    // use the key as-is (just strip any leading slash — S3 keys are relative).
    let key = object_key.trim_start_matches('/').to_string();

    let size = std::fs::metadata(file)?.len();
    // NB: we do NOT log the access key id here. Even truncated forms can be
    // matched against AWS's credential exposure detector; never put them in
    // a log artifact that may be packaged into evidence.
    log::info!(
        "S3 upload start: bucket={} region={} endpoint={} key={} size_bytes={} ({}MB)",
        cfg.bucket,
        cfg.region,
        cfg.endpoint.as_deref().unwrap_or("(AWS default)"),
        key,
        size,
        size / 1024 / 1024
    );
    log::info!("S3 SSE-KMS: {}", if cfg.sse_kms_key_id.is_some() { "ENABLED" } else { "(not set)" });

    if size <= SINGLE_SHOT_LIMIT {
        put_object_single(cfg, file, &key)
    } else {
        put_object_multipart(cfg, file, &key, size)
    }
}

fn endpoint_host(cfg: &S3Cfg) -> String {
    if let Some(ep) = &cfg.endpoint {
        // Custom endpoint (MinIO, etc.). Strip scheme and any trailing slash.
        return ep
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .trim_end_matches('/')
            .to_string();
    }
    // AWS S3 virtual-hosted style.
    format!("{}.s3.{}.amazonaws.com", cfg.bucket, cfg.region)
}

fn endpoint_scheme(cfg: &S3Cfg) -> &str {
    if let Some(ep) = &cfg.endpoint {
        if ep.starts_with("http://") {
            return "http";
        }
    }
    "https"
}

/// The request path (leading slash, key percent-encoded). For AWS this is just
/// `/{key}` (the bucket is in the virtual-hosted host); for a custom endpoint
/// it is path-style `/{bucket}/{key}`. The SigV4 canonical URI is derived from
/// the same URL, so this keeps the signature and the request in lock-step.
fn object_path(cfg: &S3Cfg, key: &str) -> String {
    if cfg.endpoint.is_some() {
        format!("/{}/{}", cfg.bucket, urlencode_path(key))
    } else {
        format!("/{}", urlencode_path(key))
    }
}

/// Base object URL (no query string).
fn object_url(cfg: &S3Cfg, key: &str) -> String {
    format!("{}://{}{}", endpoint_scheme(cfg), endpoint_host(cfg), object_path(cfg, key))
}

fn put_object_single(cfg: &S3Cfg, file: &Path, key: &str) -> Result<()> {
    let mut f = File::open(file).context("open file for upload")?;
    let mut body = Vec::new();
    f.read_to_end(&mut body)?;
    let url = object_url(cfg, key);
    log::info!("S3 PutObject -> {}", url);
    let resp = signed_request(cfg, "PUT", &url, &[], &kms_headers(cfg), &body)?;
    if resp.status() / 100 != 2 {
        // AWS returns XML errors with <Code> and <Message> elements — surface them.
        let aws_code = parse_xml_tag(&resp.body, "Code").unwrap_or_else(|| "?".to_string());
        let aws_msg = parse_xml_tag(&resp.body, "Message").unwrap_or_else(|| resp.body.clone());
        log::error!(
            "S3 PutObject FAILED status={} aws_code={} aws_msg={}",
            resp.status(),
            aws_code,
            aws_msg
        );
        bail!(
            "S3 PutObject failed: HTTP {} ({}: {}). URL was: {}",
            resp.status(),
            aws_code,
            aws_msg,
            url
        );
    }
    log::info!("S3 PutObject {}: {}", resp.status(), url);
    Ok(())
}

fn put_object_multipart(cfg: &S3Cfg, file: &Path, key: &str, size: u64) -> Result<()> {
    // 1. CreateMultipartUpload — POST /{key}?uploads
    let url = format!("{}?uploads", object_url(cfg, key));
    let resp = signed_request(cfg, "POST", &url, &[("uploads", "")], &kms_headers(cfg), &[])?;
    if resp.status() / 100 != 2 {
        bail!("CreateMultipartUpload failed: status={} body={}", resp.status(), resp.body);
    }
    let upload_id = parse_xml_tag(&resp.body, "UploadId")
        .ok_or_else(|| anyhow!("no UploadId in response: {}", resp.body))?;
    log::info!("Multipart upload started: id={}", upload_id);

    // 2. UploadPart loop
    let mut f = File::open(file)?;
    let total_parts = size.div_ceil(MULTIPART_PART_SIZE) as usize;
    let mut etags: Vec<(usize, String)> = Vec::with_capacity(total_parts);

    for part_num in 1..=total_parts {
        let offset = (part_num as u64 - 1) * MULTIPART_PART_SIZE;
        let to_read = std::cmp::min(MULTIPART_PART_SIZE, size - offset);
        f.seek(SeekFrom::Start(offset))?;
        let mut buf = vec![0u8; to_read as usize];
        f.read_exact(&mut buf)?;

        let part_url = format!(
            "{}?partNumber={}&uploadId={}",
            object_url(cfg, key),
            part_num,
            urlencode_query(&upload_id),
        );
        let q = [
            ("partNumber", part_num.to_string()),
            ("uploadId", upload_id.clone()),
        ];
        let q_pairs: Vec<(&str, &str)> = q.iter().map(|(a, b)| (*a, b.as_str())).collect();

        // Retry up to 3 times on transient failure.
        let mut attempts = 0;
        loop {
            attempts += 1;
            match signed_request(cfg, "PUT", &part_url, &q_pairs, &[], &buf) {
                Ok(r) if r.status() / 100 == 2 => {
                    let etag = r
                        .header("etag")
                        .map(|s| s.trim_matches('"').to_string())
                        .ok_or_else(|| anyhow!("no ETag on UploadPart response"))?;
                    log::info!("Part {}/{} OK ({} bytes) etag={}", part_num, total_parts, to_read, etag);
                    etags.push((part_num, etag));
                    break;
                }
                Ok(r) => {
                    if attempts >= 3 {
                        // Best-effort abort
                        let _ = abort_multipart(cfg, key, &upload_id);
                        bail!("UploadPart {} failed: status={} body={}", part_num, r.status(), r.body);
                    }
                    log::warn!("UploadPart {} retry {} (status={})", part_num, attempts, r.status());
                }
                Err(e) => {
                    if attempts >= 3 {
                        let _ = abort_multipart(cfg, key, &upload_id);
                        bail!("UploadPart {} error: {e:#}", part_num);
                    }
                    log::warn!("UploadPart {} retry {} ({e:#})", part_num, attempts);
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(500 * attempts as u64));
        }
    }

    // 3. CompleteMultipartUpload — POST /{key}?uploadId=...
    let body = complete_body(&etags.iter().map(|(n, e)| (*n as u32, e.clone())).collect::<Vec<_>>());
    let cu = format!(
        "{}?uploadId={}",
        object_url(cfg, key),
        urlencode_query(&upload_id),
    );
    let resp = signed_request(cfg, "POST", &cu, &[("uploadId", &upload_id)], &[], body.as_bytes())?;
    if resp.status() / 100 != 2 {
        bail!("CompleteMultipartUpload failed: status={} body={}", resp.status(), resp.body);
    }
    log::info!("Multipart upload completed: key={} parts={}", key, etags.len());
    Ok(())
}

fn abort_multipart(cfg: &S3Cfg, key: &str, upload_id: &str) -> Result<()> {
    let url = format!(
        "{}?uploadId={}",
        object_url(cfg, key),
        urlencode_query(upload_id),
    );
    let _ = signed_request(cfg, "DELETE", &url, &[("uploadId", upload_id)], &[], &[]);
    Ok(())
}

/// Build the CompleteMultipartUpload XML body from (part_number, etag) pairs.
fn complete_body(etags: &[(u32, String)]) -> String {
    let mut body = String::new();
    body.push_str("<CompleteMultipartUpload>");
    for (n, e) in etags {
        body.push_str(&format!("<Part><PartNumber>{n}</PartNumber><ETag>\"{e}\"</ETag></Part>"));
    }
    body.push_str("</CompleteMultipartUpload>");
    body
}

// ---- Public API for chunked uploader ----

pub fn create_multipart_upload(cfg: &S3Cfg, key: &str) -> Result<String> {
    let key = key.trim_start_matches('/');
    let url = format!("{}?uploads", object_url(cfg, key));
    let resp = signed_request(cfg, "POST", &url, &[("uploads", "")], &kms_headers(cfg), &[])?;
    if resp.status() / 100 != 2 {
        bail!("CreateMultipartUpload failed: status={} body={}", resp.status(), resp.body);
    }
    parse_xml_tag(&resp.body, "UploadId")
        .ok_or_else(|| anyhow!("no UploadId in response: {}", resp.body))
}

pub fn upload_part(cfg: &S3Cfg, key: &str, upload_id: &str, part_number: u32, data: &[u8]) -> Result<String> {
    let key = key.trim_start_matches('/');
    let part_url = format!(
        "{}?partNumber={}&uploadId={}",
        object_url(cfg, key),
        part_number,
        urlencode_query(upload_id),
    );
    let pn_str = part_number.to_string();
    let q: Vec<(&str, &str)> = vec![("partNumber", pn_str.as_str()), ("uploadId", upload_id)];
    let resp = signed_request(cfg, "PUT", &part_url, &q, &[], data)?;
    if resp.status() / 100 != 2 {
        bail!("UploadPart {} failed: status={} body={}", part_number, resp.status(), resp.body);
    }
    resp.header("etag")
        .map(|s| s.trim_matches('"').to_string())
        .ok_or_else(|| anyhow!("no ETag on UploadPart response"))
}

pub fn complete_multipart_upload(cfg: &S3Cfg, key: &str, upload_id: &str, etags: &[(u32, String)]) -> Result<()> {
    let key = key.trim_start_matches('/');
    let body = complete_body(etags);
    let cu = format!(
        "{}?uploadId={}",
        object_url(cfg, key),
        urlencode_query(upload_id),
    );
    let resp = signed_request(cfg, "POST", &cu, &[("uploadId", upload_id)], &[], body.as_bytes())?;
    if resp.status() / 100 != 2 {
        bail!("CompleteMultipartUpload failed: status={} body={}", resp.status(), resp.body);
    }
    Ok(())
}

pub fn abort_multipart_upload(cfg: &S3Cfg, key: &str, upload_id: &str) -> Result<()> {
    abort_multipart(cfg, key, upload_id)
}

fn kms_headers(cfg: &S3Cfg) -> Vec<(String, String)> {
    let mut h = Vec::new();
    if cfg.sse_kms_key_id.is_some() {
        h.push(("x-amz-server-side-encryption".to_string(), "aws:kms".to_string()));
        if let Some(k) = &cfg.sse_kms_key_id {
            h.push((
                "x-amz-server-side-encryption-aws-kms-key-id".to_string(),
                k.clone(),
            ));
        }
    }
    h
}

// ---------------- SigV4 implementation ----------------

struct SignedResp {
    status_u16: u16,
    body: String,
    headers: Vec<(String, String)>,
}

impl SignedResp {
    fn status(&self) -> u16 { self.status_u16 }
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// The `host` value to sign — MUST match the `Host` header the HTTP client
/// actually sends. ureq derives `Host` from the URL and INCLUDES a non-default
/// port (e.g. MinIO on :9000), so the signed host must include it too; the
/// `url` crate normalizes away default ports (:443/:80), matching ureq.
fn header_host(parsed: &url::Url) -> Option<String> {
    let h = parsed.host_str()?;
    Some(match parsed.port() {
        Some(p) => format!("{h}:{p}"),
        None => h.to_string(),
    })
}

/// Sign and execute a request. Returns the response (does not stream large bodies).
fn signed_request(
    cfg: &S3Cfg,
    method: &str,
    url: &str,
    query_pairs: &[(&str, &str)],
    extra_headers: &[(String, String)],
    body: &[u8],
) -> Result<SignedResp> {
    let parsed = url::Url::parse(url).context("parse url")?;
    let host = header_host(&parsed).ok_or_else(|| anyhow!("no host in url"))?;
    let canonical_uri = if parsed.path().is_empty() { "/" } else { parsed.path() };
    let now = Utc::now();
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
    let date_stamp = now.format("%Y%m%d").to_string();

    // Canonical query string — sort by key.
    let mut qp: Vec<(String, String)> = query_pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
    qp.sort_by(|a, b| a.0.cmp(&b.0));
    let canonical_query = qp
        .iter()
        .map(|(k, v)| format!("{}={}", uri_encode(k, true), uri_encode(v, true)))
        .collect::<Vec<_>>()
        .join("&");

    // Headers — host, x-amz-date, x-amz-content-sha256 are always required.
    let payload_hash = hex::encode(Sha256::digest(body));
    let mut headers: Vec<(String, String)> = vec![
        ("host".to_string(), host.clone()),
        ("x-amz-content-sha256".to_string(), payload_hash.clone()),
        ("x-amz-date".to_string(), amz_date.clone()),
    ];
    for (k, v) in extra_headers {
        headers.push((k.to_lowercase(), v.clone()));
    }
    headers.sort_by(|a, b| a.0.cmp(&b.0));

    let canonical_headers = headers
        .iter()
        .map(|(k, v)| format!("{}:{}\n", k, v.trim()))
        .collect::<String>();
    let signed_headers = headers
        .iter()
        .map(|(k, _)| k.as_str())
        .collect::<Vec<_>>()
        .join(";");

    let canonical_request = format!(
        "{method}\n{canonical_uri}\n{canonical_query}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
    );

    let credential_scope = format!("{date_stamp}/{}/s3/aws4_request", cfg.region);
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n{}",
        hex::encode(Sha256::digest(canonical_request.as_bytes()))
    );

    let k_date = hmac(format!("AWS4{}", cfg.secret_access_key).as_bytes(), date_stamp.as_bytes());
    let k_region = hmac(&k_date, cfg.region.as_bytes());
    let k_service = hmac(&k_region, b"s3");
    let k_signing = hmac(&k_service, b"aws4_request");
    let signature = hex::encode(hmac(&k_signing, string_to_sign.as_bytes()));

    let auth = format!(
        "AWS4-HMAC-SHA256 Credential={}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}",
        cfg.access_key_id
    );

    // Build the request via ureq.
    let agent = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(900))
        .build();
    let mut req = agent.request(method, url).set("Authorization", &auth);
    for (k, v) in &headers {
        if k != "host" {
            // ureq sets host automatically; setting it manually causes a duplicate header.
            req = req.set(k, v);
        }
    }

    let resp_result = if body.is_empty() {
        req.call()
    } else {
        req.send_bytes(body)
    };

    match resp_result {
        Ok(r) => {
            let status_u16 = r.status();
            let mut hs = Vec::new();
            for name in r.headers_names() {
                if let Some(v) = r.header(&name) {
                    hs.push((name.clone(), v.to_string()));
                }
            }
            let body = r.into_string().unwrap_or_default();
            Ok(SignedResp { status_u16, body, headers: hs })
        }
        Err(ureq::Error::Status(code, r)) => {
            let body = r.into_string().unwrap_or_default();
            Ok(SignedResp { status_u16: code, body, headers: vec![] })
        }
        Err(e) => Err(anyhow!("ureq transport error: {e}")),
    }
}

fn hmac(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut m = HmacSha256::new_from_slice(key).expect("HMAC key");
    m.update(msg);
    m.finalize().into_bytes().to_vec()
}

/// Per-RFC-3986 unreserved + path slash handling for SigV4.
fn uri_encode(s: &str, encode_slash: bool) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.as_bytes() {
        match *b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*b as char)
            }
            b'/' if !encode_slash => out.push('/'),
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

fn urlencode_path(p: &str) -> String { uri_encode(p, false) }
fn urlencode_query(p: &str) -> String { uri_encode(p, true) }

fn parse_xml_tag(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)? + start;
    Some(xml[start..end].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(endpoint: Option<&str>) -> S3Cfg {
        S3Cfg {
            bucket: "ir-evidence".to_string(),
            region: "ap-south-1".to_string(),
            access_key_id: "AKIA".to_string(),
            secret_access_key: "secret".to_string(),
            endpoint: endpoint.map(|s| s.to_string()),
            sse_kms_key_id: None,
            verify_tls: true,
            prefix_template: String::new(),
            credential_vault: String::new(),
            credential_vault_hmac: String::new(),
        }
    }

    #[test]
    fn aws_uses_virtual_hosted_no_bucket_in_path() {
        let c = cfg(None);
        assert_eq!(endpoint_host(&c), "ir-evidence.s3.ap-south-1.amazonaws.com");
        assert_eq!(object_path(&c, "SITE/HOST/file.zip"), "/SITE/HOST/file.zip");
        assert_eq!(
            object_url(&c, "SITE/HOST/file.zip"),
            "https://ir-evidence.s3.ap-south-1.amazonaws.com/SITE/HOST/file.zip"
        );
    }

    #[test]
    fn custom_endpoint_uses_path_style_with_bucket() {
        let c = cfg(Some("http://minio:9000"));
        assert_eq!(endpoint_host(&c), "minio:9000");
        assert_eq!(endpoint_scheme(&c), "http");
        // The bucket MUST be the first path segment for path-style requests.
        assert_eq!(object_path(&c, "SITE/HOST/file.zip"), "/ir-evidence/SITE/HOST/file.zip");
        assert_eq!(
            object_url(&c, "SITE/HOST/file.zip"),
            "http://minio:9000/ir-evidence/SITE/HOST/file.zip"
        );
    }

    #[test]
    fn endpoint_trailing_slash_is_trimmed() {
        let c = cfg(Some("https://s3.example.com/"));
        assert_eq!(endpoint_host(&c), "s3.example.com");
        assert_eq!(object_url(&c, "k"), "https://s3.example.com/ir-evidence/k");
    }

    #[test]
    fn signed_host_includes_nondefault_port_but_not_default() {
        // Custom port must be in the signed host (matches ureq's Host header).
        let u = url::Url::parse("http://minio:9000/ir-evidence/k").unwrap();
        assert_eq!(header_host(&u).unwrap(), "minio:9000");
        // Default ports are normalized away by both the url crate and ureq.
        let u2 = url::Url::parse("https://ir-evidence.s3.ap-south-1.amazonaws.com/k").unwrap();
        assert_eq!(header_host(&u2).unwrap(), "ir-evidence.s3.ap-south-1.amazonaws.com");
    }

    #[test]
    fn complete_body_is_well_formed() {
        let b = complete_body(&[(1, "etag1".into()), (2, "etag2".into())]);
        assert_eq!(
            b,
            "<CompleteMultipartUpload>\
             <Part><PartNumber>1</PartNumber><ETag>\"etag1\"</ETag></Part>\
             <Part><PartNumber>2</PartNumber><ETag>\"etag2\"</ETag></Part>\
             </CompleteMultipartUpload>"
        );
    }
}
