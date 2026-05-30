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
    // use the key as-is. Defensive: if the legacy `${aws:username}` token
    // somehow slips through, swap it out — but never with the access key,
    // since the access key in S3 paths leaks credentials to anyone with
    // ListBucket. Use the IAM username at AWS evaluation time instead.
    let key = object_key
        .trim_start_matches('/')
        .replace("${aws:username}", "${aws:username}");

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
        // Custom endpoint (MinIO, etc.). Strip scheme.
        return ep
            .trim_start_matches("https://")
            .trim_start_matches("http://")
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

fn put_object_single(cfg: &S3Cfg, file: &Path, key: &str) -> Result<()> {
    let mut f = File::open(file).context("open file for upload")?;
    let mut body = Vec::new();
    f.read_to_end(&mut body)?;
    let url = format!("{}://{}/{}", endpoint_scheme(cfg), endpoint_host(cfg), urlencode_path(key));
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
    let url = format!("{}://{}/{}?uploads", endpoint_scheme(cfg), endpoint_host(cfg), urlencode_path(key));
    let resp = signed_request(cfg, "POST", &url, &[("uploads", "")], &kms_headers(cfg), &[])?;
    if resp.status() / 100 != 2 {
        bail!("CreateMultipartUpload failed: status={} body={}", resp.status(), resp.body);
    }
    let upload_id = parse_xml_tag(&resp.body, "UploadId")
        .ok_or_else(|| anyhow!("no UploadId in response: {}", resp.body))?;
    log::info!("Multipart upload started: id={}", upload_id);

    // 2. UploadPart loop
    let mut f = File::open(file)?;
    let total_parts = ((size + MULTIPART_PART_SIZE - 1) / MULTIPART_PART_SIZE) as usize;
    let mut etags: Vec<(usize, String)> = Vec::with_capacity(total_parts);

    for part_num in 1..=total_parts {
        let offset = (part_num as u64 - 1) * MULTIPART_PART_SIZE;
        let to_read = std::cmp::min(MULTIPART_PART_SIZE, size - offset);
        f.seek(SeekFrom::Start(offset))?;
        let mut buf = vec![0u8; to_read as usize];
        f.read_exact(&mut buf)?;

        let part_url = format!(
            "{}://{}/{}?partNumber={}&uploadId={}",
            endpoint_scheme(cfg),
            endpoint_host(cfg),
            urlencode_path(key),
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
    let mut body = String::new();
    body.push_str("<CompleteMultipartUpload>");
    for (n, e) in &etags {
        body.push_str(&format!("<Part><PartNumber>{n}</PartNumber><ETag>\"{e}\"</ETag></Part>"));
    }
    body.push_str("</CompleteMultipartUpload>");
    let cu = format!(
        "{}://{}/{}?uploadId={}",
        endpoint_scheme(cfg),
        endpoint_host(cfg),
        urlencode_path(key),
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
        "{}://{}/{}?uploadId={}",
        endpoint_scheme(cfg),
        endpoint_host(cfg),
        urlencode_path(key),
        urlencode_query(upload_id),
    );
    let _ = signed_request(cfg, "DELETE", &url, &[("uploadId", upload_id)], &[], &[]);
    Ok(())
}

// ---- Public API for chunked uploader ----

pub fn create_multipart_upload(cfg: &S3Cfg, key: &str) -> Result<String> {
    let key = key.trim_start_matches('/');
    let url = format!("{}://{}/{}?uploads", endpoint_scheme(cfg), endpoint_host(cfg), urlencode_path(key));
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
        "{}://{}/{}?partNumber={}&uploadId={}",
        endpoint_scheme(cfg), endpoint_host(cfg), urlencode_path(key),
        part_number, urlencode_query(upload_id),
    );
    let q_pairs: Vec<(&str, &str)> = vec![
        ("partNumber", &part_number.to_string()),
        ("uploadId", upload_id),
    ];
    // Workaround: build owned strings for the borrow checker
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
    let mut body = String::new();
    body.push_str("<CompleteMultipartUpload>");
    for (n, e) in etags {
        body.push_str(&format!("<Part><PartNumber>{n}</PartNumber><ETag>\"{e}\"</ETag></Part>"));
    }
    body.push_str("</CompleteMultipartUpload>");
    let cu = format!(
        "{}://{}/{}?uploadId={}",
        endpoint_scheme(cfg), endpoint_host(cfg), urlencode_path(key), urlencode_query(upload_id),
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
    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow!("no host in url"))?
        .to_string();
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
