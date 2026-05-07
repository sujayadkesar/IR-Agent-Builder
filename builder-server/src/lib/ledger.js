// Audit ledger — every build is logged with metadata (no secrets) so an IR
// engineering team can answer questions like:
//   - Which collectors went out last quarter?
//   - When does this build's IAM key expire?
//   - Which build produced the binary with SHA256 = ...?
//
// Storage: a single SQLite file. Schema is intentionally append-only;
// we never UPDATE or DELETE rows.

import Database from 'better-sqlite3';
import fs from 'node:fs';
import path from 'node:path';

export function openLedger(dbPath) {
  fs.mkdirSync(path.dirname(dbPath), { recursive: true });
  const db = new Database(dbPath);
  db.exec(`
    CREATE TABLE IF NOT EXISTS builds (
      build_id TEXT PRIMARY KEY,
      build_timestamp TEXT NOT NULL,
      site_code TEXT NOT NULL,
      artifact_count INTEGER NOT NULL,
      artifacts_json TEXT NOT NULL,
      kape_targets_json TEXT NOT NULL,
      encryption_scheme TEXT NOT NULL,
      upload_kind TEXT NOT NULL,
      s3_bucket TEXT,
      s3_region TEXT,
      binary_size_bytes INTEGER NOT NULL,
      binary_sha256 TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    )
  `);
  return {
    recordBuild(meta) {
      const stmt = db.prepare(`
        INSERT INTO builds (
          build_id, build_timestamp, site_code, artifact_count,
          artifacts_json, kape_targets_json, encryption_scheme, upload_kind,
          s3_bucket, s3_region, binary_size_bytes, binary_sha256
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);
      stmt.run(
        meta.build_id,
        meta.build_timestamp,
        meta.site_code,
        meta.artifact_count,
        JSON.stringify(meta.artifacts),
        JSON.stringify(meta.kape_targets),
        meta.encryption_scheme,
        meta.upload_kind,
        meta.s3_bucket,
        meta.s3_region,
        meta.binary_size_bytes,
        meta.binary_sha256,
      );
    },
    listBuilds() {
      return db.prepare('SELECT * FROM builds ORDER BY created_at DESC LIMIT 200').all();
    },
    findBuild(buildId) {
      return db.prepare('SELECT * FROM builds WHERE build_id = ?').get(buildId);
    },
  };
}
