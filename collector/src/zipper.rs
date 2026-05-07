//! Recursive directory → ZIP packer (DEFLATE compression).
//!
//! We don't use ZIP-native AES because (a) library support is patchy and
//! (b) the X509 hybrid scheme (in `crypto::x509`) gives stronger semantics:
//! the entire ZIP becomes an opaque AES-256-GCM ciphertext blob whose key is
//! RSA-OAEP-wrapped to a public key. So this packer just needs to produce a
//! plain ZIP — encryption happens one layer up.

use anyhow::{Context, Result};
use std::fs::File;
use std::io::{BufReader, Read, Write};
use std::path::Path;
use walkdir::WalkDir;
use zip::write::FileOptions;
use zip::CompressionMethod;

pub fn write_directory_as_zip(src_dir: &Path, dest_zip: &Path) -> Result<()> {
    let file = File::create(dest_zip)
        .with_context(|| format!("creating zip {}", dest_zip.display()))?;
    let mut zip = zip::ZipWriter::new(file);
    let opts = FileOptions::default()
        .compression_method(CompressionMethod::Deflated)
        .unix_permissions(0o644);

    let mut buf = vec![0u8; 1024 * 1024];
    let walk = WalkDir::new(src_dir).into_iter().filter_map(|e| e.ok());
    for entry in walk {
        let path = entry.path();
        let rel = path.strip_prefix(src_dir).unwrap();
        let rel_str = rel.to_string_lossy().replace('\\', "/");
        if rel_str.is_empty() {
            continue;
        }
        if entry.file_type().is_dir() {
            // ZipWriter::add_directory takes &str
            let _ = zip.add_directory(format!("{rel_str}/"), opts);
            continue;
        }
        if !entry.file_type().is_file() {
            continue;
        }
        zip.start_file(rel_str.clone(), opts)
            .with_context(|| format!("starting zip entry {rel_str}"))?;
        let f = match File::open(path) {
            Ok(f) => f,
            Err(e) => {
                log::warn!("zip skip {} (open failed: {e})", path.display());
                continue;
            }
        };
        let mut reader = BufReader::new(f);
        loop {
            let n = reader.read(&mut buf).context("reading file for zip")?;
            if n == 0 { break; }
            zip.write_all(&buf[..n]).context("writing zip body")?;
        }
    }
    zip.finish().context("finalizing zip")?;
    Ok(())
}
