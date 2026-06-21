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
//!   - AWS (no custom endpoint): virtual-hosted `{bucket}.s3.{region}.amazonaws.com`, path `/{key}`.
//!   - Custom endpoint (MinIO/Ceph/etc.): path-style, bucket is the first path segment `/{bucket}/{key}`.
//!
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
use crate::upload::resume::{self, PendingUpload};

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
    let resp = with_retry("PutObject", || {
        signed_request(cfg, "PUT", &url, &[], &kms_headers(cfg), &body)
    });
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
    let resp = with_retry("CreateMultipartUpload", || {
        signed_request(cfg, "POST", &url, &[("uploads", "")], &kms_headers(cfg), &[])
    });
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

        // Transient failures (network down, 5xx, throttling) retry forever via
        // with_retry — a network outage pauses the part, it does not fail it.
        // Only a permanent error (4xx) aborts the whole multipart.
        let r = with_retry(&format!("UploadPart {part_num}/{total_parts}"), || {
            signed_request(cfg, "PUT", &part_url, &q_pairs, &[], &buf)
        });
        if r.status() / 100 != 2 {
            let _ = abort_multipart(cfg, key, &upload_id);
            bail!("UploadPart {} failed (permanent): status={} body={}", part_num, r.status(), r.body);
        }
        let etag = r
            .header("etag")
            .map(|s| s.trim_matches('"').to_string())
            .ok_or_else(|| anyhow!("no ETag on UploadPart response"))?;
        log::info!("Part {}/{} OK ({} bytes) etag={}", part_num, total_parts, to_read, etag);
        etags.push((part_num, etag));
    }

    // 3. CompleteMultipartUpload — POST /{key}?uploadId=...
    let body = complete_body(&etags.iter().map(|(n, e)| (*n as u32, e.clone())).collect::<Vec<_>>());
    let cu = format!(
        "{}?uploadId={}",
        object_url(cfg, key),
        urlencode_query(&upload_id),
    );
    let resp = with_retry("CompleteMultipartUpload", || {
        signed_request(cfg, "POST", &cu, &[("uploadId", &upload_id)], &[], body.as_bytes())
    });
    if resp.status() / 100 != 2 {
        bail!("CompleteMultipartUpload failed: status={} body={}", resp.status(), resp.body);
    }
    log::info!("Multipart upload completed: key={} parts={}", key, etags.len());
    Ok(())
}

// ---- Resumable container upload (survives a crash/reboot mid-upload) ----

/// Upload the evidence container, recording progress to a local state file so a
/// re-run of the same build can finish it after an interruption. Small files use
/// single-shot (re-PUT on resume); large files use multipart (skip parts S3 has
/// already accepted). The state file holds NO credentials.
pub fn upload_resumable(cfg: &S3Cfg, file: &Path, object_key: &str, build_id: &str) -> Result<()> {
    let key = object_key.trim_start_matches('/').to_string();
    let size = std::fs::metadata(file)?.len();
    log::info!(
        "S3 upload (resumable) -> bucket={} key={} size_bytes={} ({}MB)",
        cfg.bucket, key, size, size / 1024 / 1024
    );
    log::info!("S3 SSE-KMS: {}", if cfg.sse_kms_key_id.is_some() { "ENABLED" } else { "(not set)" });

    let part_size = if size <= SINGLE_SHOT_LIMIT { SINGLE_SHOT_LIMIT } else { MULTIPART_PART_SIZE };
    let state = PendingUpload {
        object_key: key.clone(),
        container_path: file.to_string_lossy().to_string(),
        file_size: size,
        part_size,
        upload_id: None,
        completed_parts: Vec::new(),
        build_id: build_id.to_string(),
        created_at: Utc::now().to_rfc3339(),
    };

    if size <= SINGLE_SHOT_LIMIT {
        // Record intent so a crash mid-PUT lets a re-run re-PUT the whole file.
        resume::save(&state);
        put_object_single(cfg, file, &key)?;
        resume::clear();
        Ok(())
    } else {
        multipart_with_state(cfg, file, &key, size, state)
    }
}

/// Drive a multipart upload from `state`. If `state.upload_id` is `None` a new
/// upload is created; otherwise the existing one is resumed. Only parts NOT in
/// `state.completed_parts` are uploaded, and the state is persisted AFTER each
/// part's 2xx — so a crash between the part landing and the state write merely
/// re-uploads that part (re-PUT of the same part number is idempotent in S3).
fn multipart_with_state(
    cfg: &S3Cfg,
    file: &Path,
    key: &str,
    size: u64,
    mut state: PendingUpload,
) -> Result<()> {
    let upload_id = match state.upload_id.clone() {
        Some(id) => {
            log::info!(
                "Resuming multipart id={} ({} of ~{} parts already done)",
                id,
                state.completed_parts.len(),
                size.div_ceil(state.part_size)
            );
            id
        }
        None => {
            let url = format!("{}?uploads", object_url(cfg, key));
            let resp = with_retry("CreateMultipartUpload", || {
                signed_request(cfg, "POST", &url, &[("uploads", "")], &kms_headers(cfg), &[])
            });
            if resp.status() / 100 != 2 {
                bail!("CreateMultipartUpload failed: status={} body={}", resp.status(), resp.body);
            }
            let id = parse_xml_tag(&resp.body, "UploadId")
                .ok_or_else(|| anyhow!("no UploadId in response: {}", resp.body))?;
            log::info!("Multipart upload started: id={}", id);
            state.upload_id = Some(id.clone());
            resume::save(&state);
            id
        }
    };

    let part_size = state.part_size;
    let total = size.div_ceil(part_size) as u32;
    let mut f = File::open(file)?;
    for part_num in resume::missing_parts(size, part_size, &state.completed_parts) {
        let offset = (part_num as u64 - 1) * part_size;
        let to_read = std::cmp::min(part_size, size - offset);
        f.seek(SeekFrom::Start(offset))?;
        let mut buf = vec![0u8; to_read as usize];
        f.read_exact(&mut buf)?;

        let part_url = format!(
            "{}?partNumber={}&uploadId={}",
            object_url(cfg, key),
            part_num,
            urlencode_query(&upload_id),
        );
        let q = [("partNumber", part_num.to_string()), ("uploadId", upload_id.clone())];
        let q_pairs: Vec<(&str, &str)> = q.iter().map(|(a, b)| (*a, b.as_str())).collect();

        let r = with_retry(&format!("UploadPart {part_num}/{total}"), || {
            signed_request(cfg, "PUT", &part_url, &q_pairs, &[], &buf)
        });
        if r.status() / 100 != 2 {
            // Permanent (e.g. NoSuchUpload after a lifecycle-reaped upload):
            // abort and bail. try_resume then discards state and collects fresh
            // rather than wedging forever on a dead upload id.
            let _ = abort_multipart(cfg, key, &upload_id);
            bail!("UploadPart {} failed (permanent): status={} body={}", part_num, r.status(), r.body);
        }
        let etag = r
            .header("etag")
            .map(|s| s.trim_matches('"').to_string())
            .ok_or_else(|| anyhow!("no ETag on UploadPart response"))?;
        log::info!("Part {}/{} OK ({} bytes) etag={}", part_num, total, to_read, etag);
        state.completed_parts.push((part_num, etag)); // persist AFTER the 2xx
        resume::save(&state);
    }

    state.completed_parts.sort_by_key(|(n, _)| *n);
    let body = complete_body(&state.completed_parts);
    let cu = format!("{}?uploadId={}", object_url(cfg, key), urlencode_query(&upload_id));
    let resp = with_retry("CompleteMultipartUpload", || {
        signed_request(cfg, "POST", &cu, &[("uploadId", &upload_id)], &[], body.as_bytes())
    });
    if resp.status() / 100 != 2 {
        bail!("CompleteMultipartUpload failed: status={} body={}", resp.status(), resp.body);
    }
    log::info!("Multipart upload completed: key={} parts={}", key, state.completed_parts.len());
    resume::clear();
    Ok(())
}

/// Finish a pending upload from saved state. The caller (`upload::try_resume`)
/// has already confirmed the container exists and its size/build match.
pub fn resume_pending(cfg: &S3Cfg, state: PendingUpload) -> Result<()> {
    let file = std::path::PathBuf::from(&state.container_path);
    let size = state.file_size;
    let key = state.object_key.clone();
    if state.upload_id.is_some() {
        multipart_with_state(cfg, &file, &key, size, state)
    } else {
        put_object_single(cfg, &file, &key)?;
        resume::clear();
        Ok(())
    }
}

/// HTTP statuses worth retrying: server-side / throttling / request-timeout.
/// Other 4xx (bad creds, missing bucket, signature) are permanent config errors
/// — retrying them forever would just hide the real problem.
fn is_transient_status(code: u16) -> bool {
    code >= 500 || code == 429 || code == 408
}

/// Run one signed S3 request, retrying *transient* failures indefinitely with
/// capped exponential backoff (2s → 30s). A network outage therefore pauses the
/// upload instead of failing it: each attempt re-issues the real request (which
/// doubles as the connectivity probe) and re-signs with a fresh timestamp (SigV4
/// signatures expire after ~15 min, so a cached one would be rejected after a
/// long wait). Returns on the first 2xx, or immediately on a permanent 4xx so the
/// caller can surface a real error.
fn with_retry<F>(label: &str, f: F) -> SignedResp
where
    F: Fn() -> Result<SignedResp>,
{
    let start = std::time::Instant::now();
    let mut backoff = std::time::Duration::from_secs(2);
    let max_backoff = std::time::Duration::from_secs(30);
    let mut attempt: u64 = 0;
    loop {
        attempt += 1;
        match f() {
            Ok(r) if r.status() / 100 == 2 => {
                if attempt > 1 {
                    log::info!(
                        "[s3] {label}: recovered after {attempt} attempts ({}s waiting for connectivity)",
                        start.elapsed().as_secs()
                    );
                }
                return r;
            }
            Ok(r) if !is_transient_status(r.status()) => return r, // permanent — caller surfaces it
            Ok(r) => log::warn!(
                "[s3] {label}: transient HTTP {} (attempt {attempt}, {}s elapsed); retrying in {}s",
                r.status(), start.elapsed().as_secs(), backoff.as_secs()
            ),
            Err(e) => log::warn!(
                "[s3] {label}: network error (attempt {attempt}, {}s elapsed): {e:#}; retrying in {}s",
                start.elapsed().as_secs(), backoff.as_secs()
            ),
        }
        std::thread::sleep(backoff);
        backoff = std::cmp::min(backoff.saturating_mul(2), max_backoff);
    }
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
    fn transient_status_classification() {
        for c in [500u16, 502, 503, 504, 429, 408] {
            assert!(is_transient_status(c), "{c} should be transient");
        }
        for c in [400u16, 401, 403, 404] {
            assert!(!is_transient_status(c), "{c} should be permanent");
        }
    }

    #[test]
    fn with_retry_recovers_after_transient_then_succeeds() {
        use std::cell::Cell;
        // Fail once with a 503 (one ~2s backoff), then succeed — with_retry must
        // loop and return the 2xx.
        let calls = Cell::new(0u32);
        let r = with_retry("test", || {
            let n = calls.get() + 1;
            calls.set(n);
            let status = if n < 2 { 503 } else { 200 };
            Ok(SignedResp { status_u16: status, body: String::new(), headers: vec![] })
        });
        assert_eq!(r.status(), 200);
        assert_eq!(calls.get(), 2);
    }

    #[test]
    fn with_retry_returns_permanent_4xx_immediately() {
        use std::cell::Cell;
        let calls = Cell::new(0u32);
        let r = with_retry("test", || {
            calls.set(calls.get() + 1);
            Ok(SignedResp { status_u16: 403, body: "AccessDenied".into(), headers: vec![] })
        });
        assert_eq!(r.status(), 403);
        assert_eq!(calls.get(), 1, "permanent error must not retry");
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
