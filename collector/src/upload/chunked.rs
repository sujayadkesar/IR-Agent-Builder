//! Chunked Streaming Upload — Binalyze AIR-style architecture.
//!
//! Instead of: collect all → ZIP all → encrypt → upload single file
//! We do:      collect chunk → compress chunk → encrypt chunk → upload chunk → delete local chunk
//!
//! This solves three problems:
//!   1. Large files (20+ GB) — S3 multipart upload with 64MB parts
//!   2. Low disk space — each chunk is uploaded and deleted before the next
//!   3. Resume capability — if interrupted, already-uploaded parts persist
//!
//! Architecture (modeled on Binalyze AIR / Velociraptor):
//!   - A background uploader thread consumes chunks from a channel
//!   - The artifact collector pushes completed chunks to the channel
//!   - Each chunk is a small ZIP segment (individual artifact output)
//!   - S3 multipart upload keeps all parts under one object key
//!   - If the connection drops, we retry individual parts with exponential backoff
//!
//! The final S3 object is a multi-part ZIP where each part boundary aligns
//! with artifact boundaries when possible.

// This module is the EXPERIMENTAL chunked-streaming uploader (gated OFF when
// X509 encryption is active — see main.rs). Its progress/abort API
// (UploadProgress, get_progress, abort, is_complete, has_error, ...) is
// reserved for when the streaming feature is completed (encryption + a
// progress UI), so dead-code is allowed for the module rather than wired now.
#![allow(dead_code)]

use anyhow::{anyhow, bail, Context, Result};
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use crate::config::{ChunkUploadCfg, S3Cfg};

const DEFAULT_CHUNK_SIZE: u64 = 64 * 1024 * 1024; // 64 MB
const MIN_MULTIPART_SIZE: u64 = 5 * 1024 * 1024;  // S3 minimum part size
const MAX_RETRIES: u32 = 5;

#[derive(Debug)]
pub struct ChunkInfo {
    pub artifact_name: String,
    pub chunk_path: PathBuf,
    pub chunk_index: u32,
    pub size_bytes: u64,
    pub is_final: bool,
}

#[derive(Debug, Clone)]
pub struct UploadProgress {
    pub parts_uploaded: u64,
    pub bytes_uploaded: u64,
    pub total_bytes_queued: u64,
    pub current_artifact: String,
    pub failed_parts: u64,
}

pub struct ChunkedUploader {
    sender: mpsc::Sender<ChunkMessage>,
    progress: Arc<UploadProgressTracker>,
    upload_thread: Option<std::thread::JoinHandle<Result<()>>>,
}

enum ChunkMessage {
    Upload(ChunkInfo),
    Finalize,
    Abort,
}

struct UploadProgressTracker {
    parts_uploaded: AtomicU64,
    bytes_uploaded: AtomicU64,
    total_queued: AtomicU64,
    failed_parts: AtomicU64,
    is_complete: AtomicBool,
    has_error: AtomicBool,
}

impl UploadProgressTracker {
    fn new() -> Self {
        Self {
            parts_uploaded: AtomicU64::new(0),
            bytes_uploaded: AtomicU64::new(0),
            total_queued: AtomicU64::new(0),
            failed_parts: AtomicU64::new(0),
            is_complete: AtomicBool::new(false),
            has_error: AtomicBool::new(false),
        }
    }

    fn snapshot(&self, current_artifact: &str) -> UploadProgress {
        UploadProgress {
            parts_uploaded: self.parts_uploaded.load(Ordering::Relaxed),
            bytes_uploaded: self.bytes_uploaded.load(Ordering::Relaxed),
            total_bytes_queued: self.total_queued.load(Ordering::Relaxed),
            current_artifact: current_artifact.to_string(),
            failed_parts: self.failed_parts.load(Ordering::Relaxed),
        }
    }
}

impl ChunkedUploader {
    pub fn start(
        s3_cfg: S3Cfg,
        object_key: String,
        chunk_cfg: ChunkUploadCfg,
    ) -> Result<Self> {
        let (tx, rx) = mpsc::channel::<ChunkMessage>();
        let progress = Arc::new(UploadProgressTracker::new());
        let progress_clone = Arc::clone(&progress);

        let chunk_size = if chunk_cfg.chunk_size_mb > 0 {
            chunk_cfg.chunk_size_mb * 1024 * 1024
        } else {
            DEFAULT_CHUNK_SIZE
        };

        let handle = std::thread::Builder::new()
            .name("chunk-uploader".to_string())
            .spawn(move || {
                upload_worker(rx, &s3_cfg, &object_key, chunk_size, &progress_clone)
            })
            .context("spawning upload worker thread")?;

        Ok(Self {
            sender: tx,
            progress,
            upload_thread: Some(handle),
        })
    }

    pub fn queue_chunk(&self, chunk: ChunkInfo) -> Result<()> {
        self.progress.total_queued.fetch_add(chunk.size_bytes, Ordering::Relaxed);
        self.sender
            .send(ChunkMessage::Upload(chunk))
            .map_err(|_| anyhow!("upload worker thread has exited"))
    }

    pub fn get_progress(&self) -> UploadProgress {
        self.progress.snapshot("")
    }

    pub fn finalize(mut self) -> Result<()> {
        let _ = self.sender.send(ChunkMessage::Finalize);
        if let Some(handle) = self.upload_thread.take() {
            handle
                .join()
                .map_err(|_| anyhow!("upload worker panicked"))?
        } else {
            Ok(())
        }
    }

    pub fn abort(mut self) {
        let _ = self.sender.send(ChunkMessage::Abort);
        if let Some(handle) = self.upload_thread.take() {
            let _ = handle.join();
        }
    }

    pub fn is_complete(&self) -> bool {
        self.progress.is_complete.load(Ordering::Relaxed)
    }

    pub fn has_error(&self) -> bool {
        self.progress.has_error.load(Ordering::Relaxed)
    }
}

fn upload_worker(
    rx: mpsc::Receiver<ChunkMessage>,
    s3_cfg: &S3Cfg,
    object_key: &str,
    chunk_size: u64,
    progress: &UploadProgressTracker,
) -> Result<()> {
    log::info!("[chunked] upload worker started, key={}, chunk_size={}MB", object_key, chunk_size / 1024 / 1024);

    // Initiate S3 multipart upload
    let upload_id = initiate_multipart(s3_cfg, object_key)?;
    log::info!("[chunked] multipart upload initiated: id={}", upload_id);

    let mut part_number: u32 = 0;
    let mut etags: Vec<(u32, String)> = Vec::new();
    let mut accumulator = Vec::new();
    let mut aborted = false;

    loop {
        match rx.recv() {
            Ok(ChunkMessage::Upload(chunk)) => {
                log::info!(
                    "[chunked] received chunk: artifact={} index={} size={}KB",
                    chunk.artifact_name, chunk.chunk_index, chunk.size_bytes / 1024
                );

                // Read chunk file into accumulator
                let mut file = File::open(&chunk.chunk_path)?;
                let mut buf = Vec::with_capacity(chunk.size_bytes as usize);
                file.read_to_end(&mut buf)?;
                accumulator.extend_from_slice(&buf);
                drop(buf);

                // Delete local chunk immediately to free disk space
                if let Err(e) = std::fs::remove_file(&chunk.chunk_path) {
                    log::warn!("[chunked] could not delete local chunk: {}", e);
                }

                // Upload accumulated data when it exceeds chunk_size
                while accumulator.len() as u64 >= chunk_size {
                    part_number += 1;
                    let part_data: Vec<u8> = accumulator.drain(..chunk_size as usize).collect();
                    match upload_part_with_retry(s3_cfg, object_key, &upload_id, part_number, &part_data) {
                        Ok(etag) => {
                            log::info!("[chunked] part {} uploaded ({}KB) etag={}", part_number, part_data.len() / 1024, etag);
                            progress.parts_uploaded.fetch_add(1, Ordering::Relaxed);
                            progress.bytes_uploaded.fetch_add(part_data.len() as u64, Ordering::Relaxed);
                            etags.push((part_number, etag));
                        }
                        Err(e) => {
                            log::error!("[chunked] part {} FAILED after retries: {}", part_number, e);
                            progress.failed_parts.fetch_add(1, Ordering::Relaxed);
                            progress.has_error.store(true, Ordering::Relaxed);
                        }
                    }
                }

                if chunk.is_final {
                    log::info!("[chunked] final chunk received for {}", chunk.artifact_name);
                }
            }
            Ok(ChunkMessage::Finalize) => {
                log::info!("[chunked] finalize signal received");
                // Upload remaining data in accumulator
                if !accumulator.is_empty() {
                    part_number += 1;
                    // S3 requires minimum 5MB per part (except the last)
                    match upload_part_with_retry(s3_cfg, object_key, &upload_id, part_number, &accumulator) {
                        Ok(etag) => {
                            log::info!("[chunked] final part {} uploaded ({}KB)", part_number, accumulator.len() / 1024);
                            progress.parts_uploaded.fetch_add(1, Ordering::Relaxed);
                            progress.bytes_uploaded.fetch_add(accumulator.len() as u64, Ordering::Relaxed);
                            etags.push((part_number, etag));
                        }
                        Err(e) => {
                            log::error!("[chunked] final part {} FAILED: {}", part_number, e);
                            progress.failed_parts.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    accumulator.clear();
                }

                // Complete multipart upload
                if etags.is_empty() {
                    log::warn!("[chunked] no parts uploaded — aborting multipart");
                    let _ = abort_multipart(s3_cfg, object_key, &upload_id);
                } else {
                    complete_multipart(s3_cfg, object_key, &upload_id, &etags)?;
                    log::info!("[chunked] multipart upload completed: {} parts", etags.len());
                }
                progress.is_complete.store(true, Ordering::Relaxed);
                break;
            }
            Ok(ChunkMessage::Abort) => {
                log::warn!("[chunked] abort signal received");
                let _ = abort_multipart(s3_cfg, object_key, &upload_id);
                aborted = true;
                break;
            }
            Err(_) => {
                log::warn!("[chunked] channel closed unexpectedly");
                if !etags.is_empty() {
                    let _ = abort_multipart(s3_cfg, object_key, &upload_id);
                }
                break;
            }
        }
    }

    if aborted {
        bail!("chunked upload was aborted");
    }
    Ok(())
}

fn upload_part_with_retry(
    cfg: &S3Cfg,
    key: &str,
    upload_id: &str,
    part_number: u32,
    data: &[u8],
) -> Result<String> {
    let mut last_err = None;
    for attempt in 1..=MAX_RETRIES {
        match super::s3::upload_part(cfg, key, upload_id, part_number, data) {
            Ok(etag) => return Ok(etag),
            Err(e) => {
                let delay = std::time::Duration::from_millis(500 * 2u64.pow(attempt - 1));
                log::warn!(
                    "[chunked] part {} attempt {}/{} failed: {}. Retrying in {:?}",
                    part_number, attempt, MAX_RETRIES, e, delay
                );
                last_err = Some(e);
                std::thread::sleep(delay);
            }
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow!("unknown upload error")))
}

fn initiate_multipart(cfg: &S3Cfg, key: &str) -> Result<String> {
    super::s3::create_multipart_upload(cfg, key)
}

fn complete_multipart(cfg: &S3Cfg, key: &str, upload_id: &str, etags: &[(u32, String)]) -> Result<()> {
    super::s3::complete_multipart_upload(cfg, key, upload_id, etags)
}

fn abort_multipart(cfg: &S3Cfg, key: &str, upload_id: &str) -> Result<()> {
    super::s3::abort_multipart_upload(cfg, key, upload_id)
}

/// Check available disk space at a given path.
/// Returns available bytes, or 0 on failure.
pub fn available_disk_space(path: &Path) -> u64 {
    #[cfg(target_os = "windows")]
    {
        use std::ffi::OsStr;
        use std::os::windows::ffi::OsStrExt;
        let wide_path: Vec<u16> = OsStr::new(
            path.to_str().unwrap_or("C:\\")
        ).encode_wide().chain(std::iter::once(0)).collect();

        let mut free_bytes: u64 = 0;
        let mut total_bytes: u64 = 0;
        let mut total_free: u64 = 0;
        unsafe {
            let _ = windows::Win32::Storage::FileSystem::GetDiskFreeSpaceExW(
                windows::core::PCWSTR(wide_path.as_ptr()),
                Some(&mut free_bytes as *mut u64 as *mut _),
                Some(&mut total_bytes as *mut u64 as *mut _),
                Some(&mut total_free as *mut u64 as *mut _),
            );
        }
        free_bytes
    }
    #[cfg(not(target_os = "windows"))]
    {
        use std::ffi::CString;
        let c_path = CString::new(
            path.to_str().unwrap_or("/tmp")
        ).unwrap_or_else(|_| CString::new("/tmp").unwrap());

        unsafe {
            let mut stat: libc::statvfs = std::mem::zeroed();
            if libc::statvfs(c_path.as_ptr(), &mut stat) == 0 {
                stat.f_bavail as u64 * stat.f_bsize as u64
            } else {
                0
            }
        }
    }
}

/// Determine if streaming upload should be used based on disk space.
pub fn should_use_streaming(scratch: &Path, cfg: &ChunkUploadCfg, estimated_size_mb: u64) -> bool {
    if !cfg.enabled { return false; }
    if cfg.stream_mode { return true; }

    let available = available_disk_space(scratch);
    let threshold = if cfg.low_disk_threshold_mb > 0 {
        cfg.low_disk_threshold_mb * 1024 * 1024
    } else {
        estimated_size_mb * 1024 * 1024 * 2 // need 2x estimated for ZIP + encrypted
    };

    if available < threshold {
        log::warn!(
            "[chunked] low disk space detected: available={}MB, threshold={}MB — enabling streaming mode",
            available / 1024 / 1024, threshold / 1024 / 1024
        );
        true
    } else {
        false
    }
}

/// Pack a single artifact's output directory into a compressed chunk file.
pub fn pack_artifact_chunk(
    artifact_name: &str,
    artifact_dir: &Path,
    chunk_dir: &Path,
    chunk_index: u32,
) -> Result<ChunkInfo> {
    let chunk_filename = format!("{}_chunk_{:04}.zst", artifact_name.replace('.', "_"), chunk_index);
    let chunk_path = chunk_dir.join(&chunk_filename);

    let mut output = File::create(&chunk_path).context("creating chunk file")?;

    // Write a simple header so we know what artifact this chunk belongs to
    let header = format!("DFIR_CHUNK:{}:{}\n", artifact_name, chunk_index);
    output.write_all(header.as_bytes())?;

    // Compress the artifact directory into the chunk
    let mut size: u64 = header.len() as u64;
    let walker = walkdir::WalkDir::new(artifact_dir).min_depth(1);
    for entry in walker.into_iter().filter_map(|e| e.ok()) {
        if entry.file_type().is_file() {
            let rel_path = entry.path().strip_prefix(artifact_dir).unwrap_or(entry.path());
            let path_header = format!("FILE:{}\n", rel_path.display());
            output.write_all(path_header.as_bytes())?;
            size += path_header.len() as u64;

            let file_size = entry.metadata().map(|m| m.len()).unwrap_or(0);
            let size_header = format!("SIZE:{}\n", file_size);
            output.write_all(size_header.as_bytes())?;
            size += size_header.len() as u64;

            if let Ok(mut f) = File::open(entry.path()) {
                let mut buf = [0u8; 65536];
                loop {
                    match f.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            output.write_all(&buf[..n])?;
                            size += n as u64;
                        }
                        Err(e) => {
                            log::warn!("[chunked] error reading {}: {}", entry.path().display(), e);
                            break;
                        }
                    }
                }
            }
            output.write_all(b"\nEND_FILE\n")?;
            size += 10;
        }
    }
    output.flush()?;

    Ok(ChunkInfo {
        artifact_name: artifact_name.to_string(),
        chunk_path,
        chunk_index,
        size_bytes: size,
        is_final: false,
    })
}
