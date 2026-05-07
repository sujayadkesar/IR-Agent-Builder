// DFIR AgentBuilder — build orchestration server.
//
// Endpoints:
//   GET  /api/artifacts              List the artifact catalog (UI side).
//   GET  /api/bundles                List bundle presets (QuickTriage, etc.)
//   POST /api/aws/iam-policy         Generate the IAM write-only policy JSON for a given config.
//   POST /api/aws/validate           Test PutObject/DeleteObject on the configured S3 bucket.
//   POST /api/keypair/generate       Generate an RSA-4096 keypair, return both halves.
//   POST /api/build                  Kick off a collector build. Returns build_id + SSE log stream.
//   GET  /api/build/:id/stream       Server-Sent Events log stream for a build.
//   GET  /api/build/:id/download     Download the resulting Collector.exe.
//   GET  /api/builds                 Audit ledger — list all past builds.

import express from 'express';
import cors from 'cors';
import morgan from 'morgan';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';
import { spawn } from 'node:child_process';
import { randomUUID, createHash } from 'node:crypto';
import forge from 'node-forge';

import { ARTIFACT_CATALOG, BUNDLES } from './lib/catalog.js';
import { generateIamPolicy, validateS3Connection } from './lib/aws.js';
import { openLedger } from './lib/ledger.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT = path.resolve(__dirname, '..', '..');
const COLLECTOR_DIR = path.join(ROOT, 'collector');
const BUILDS_DIR = path.join(ROOT, 'builds');
fs.mkdirSync(BUILDS_DIR, { recursive: true });

const app = express();
const PORT = Number(process.env.PORT || 8787);

// morgan('dev') logs URL + status only — never the request body, so AWS
// secrets posted to /api/build don't end up in stdout. We deliberately do
// not enable a verbose morgan format here.
app.use(morgan('dev'));
app.use(cors());
app.use(express.json({ limit: '4mb' }));

/**
 * Redact AWS-shaped secrets (Access Key IDs and Secret Access Keys) from
 * any string before it's logged or returned. Defence in depth so that even
 * if a future change accidentally surfaces a config blob, the obvious
 * patterns are scrubbed.
 *   - Access Key IDs: 20-char uppercase prefixed AKIA/ASIA/AIDA/AGPA/etc.
 *   - Secret Access Keys: 40-char base64.
 */
function redactSecrets(str) {
  if (typeof str !== 'string') return str;
  return str
    .replace(/\b(?:AKIA|ASIA|AIDA|AGPA|AROA|AIPA|ANPA|ANVA|AIDB|ABIA|ACCA)[A-Z0-9]{16}\b/g, 'AKIA****REDACTED')
    .replace(/(?<![A-Za-z0-9+/])[A-Za-z0-9+/=]{40}(?![A-Za-z0-9+/])/g, '****REDACTED-40****');
}

/**
 * Placeholder embedded_config.json content. After every cargo build the
 * server writes this back over the real config so AWS credentials never
 * sit on disk longer than the compilation window. Cargo's incremental
 * build still works because we mark `src/embedded_config.json` as a
 * `cargo:rerun-if-changed` source — every build is fresh.
 */
const PLACEHOLDER_EMBEDDED_CONFIG = {
  build_id: 'placeholder',
  build_timestamp: '1970-01-01T00:00:00Z',
  site_code: 'PLACEHOLDER',
  filename_template: '%FQDN%-%TIMESTAMP%-%UUID%',
  require_admin: true, delete_after_upload: true, silent: true, use_vss: true,
  max_collection_size_gb: 0, cpu_limit_percent: 0, concurrency: 2,
  progress_timeout_seconds: 3600, output_format: 'jsonl',
  artifacts: [], artifact_params: {}, kape_targets: [],
  encryption: { scheme: 'none', rsa_public_key_pem: '' },
  upload: { kind: 'local', local_path: 'C:\\IR\\Output', s3: null },
};

/**
 * Validate and normalize the per-artifact parameter map. Drops anything
 * that isn't a plain object of {string,number,boolean} values so the Rust
 * collector's serde_json parse doesn't choke on a stray array or null.
 */
function sanitizeArtifactParams(input) {
  if (!input || typeof input !== 'object') return {};
  const out = {};
  for (const [artifactId, params] of Object.entries(input)) {
    if (!params || typeof params !== 'object') continue;
    const safe = {};
    for (const [k, v] of Object.entries(params)) {
      if (typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean') {
        safe[k] = v;
      }
    }
    if (Object.keys(safe).length > 0) out[artifactId] = safe;
  }
  return out;
}

const ledger = openLedger(path.join(BUILDS_DIR, 'ledger.sqlite'));
const buildStreams = new Map();      // build_id -> { logs: [], status, listeners: Set<res> }

// -------------------------- Artifact catalog --------------------------
app.get('/api/artifacts', (_req, res) => res.json(ARTIFACT_CATALOG));
app.get('/api/bundles',   (_req, res) => res.json(BUNDLES));

// -------------------------- AWS helpers --------------------------
app.post('/api/aws/iam-policy', (req, res) => {
  const { bucket, kmsKeyArn, accessKeyId } = req.body;
  if (!bucket) return res.status(400).json({ error: 'bucket required' });
  res.json(generateIamPolicy({ bucket, kmsKeyArn, accessKeyId }));
});

app.post('/api/aws/validate', async (req, res) => {
  const { bucket, region, accessKeyId, secretAccessKey, endpoint, sseKmsKeyId } = req.body;
  try {
    const result = await validateS3Connection({
      bucket, region, accessKeyId, secretAccessKey, endpoint, sseKmsKeyId,
    });
    res.json(result);
  } catch (e) {
    res.status(400).json({ ok: false, error: String(e?.message || e) });
  }
});

// -------------------------- Keypair generation --------------------------
app.post('/api/keypair/generate', (req, res) => {
  const bits = Number(req.body?.bits || 4096);
  if (![2048, 3072, 4096].includes(bits)) {
    return res.status(400).json({ error: 'bits must be 2048, 3072, or 4096' });
  }
  console.log(`[keypair] generating RSA-${bits} pair...`);
  const t0 = Date.now();
  const kp = forge.pki.rsa.generateKeyPair({ bits });
  const elapsed = Date.now() - t0;
  const publicPem = forge.pki.publicKeyToPem(kp.publicKey);
  const privatePem = forge.pki.privateKeyToPem(kp.privateKey);
  // Fingerprint of public key DER (SHA256 hex).
  const pubAsn1 = forge.pki.publicKeyToAsn1(kp.publicKey);
  const pubDer = forge.asn1.toDer(pubAsn1).getBytes();
  const md = forge.md.sha256.create();
  md.update(pubDer);
  const fingerprint = md.digest().toHex();
  console.log(`[keypair] done in ${elapsed}ms fp=${fingerprint.slice(0,16)}...`);
  res.json({
    bits,
    publicKeyPem: publicPem,
    privateKeyPem: privatePem,
    fingerprintSha256: fingerprint,
    generatedAtMs: elapsed,
  });
});

// -------------------------- Build orchestration --------------------------
app.post('/api/build', async (req, res) => {
  const cfg = req.body || {};
  if (!Array.isArray(cfg.artifacts) || cfg.artifacts.length === 0) {
    return res.status(400).json({ error: 'at least one artifact required' });
  }

  const buildId = randomUUID();
  const buildTimestamp = new Date().toISOString();
  const stream = { logs: [], status: 'starting', listeners: new Set(), exePath: null };
  buildStreams.set(buildId, stream);

  const log = (line) => {
    const safe = redactSecrets(String(line));
    const stamped = `[${new Date().toISOString().slice(11, 23)}] ${safe}`;
    stream.logs.push(stamped);
    for (const r of stream.listeners) r.write(`data: ${stamped}\n\n`);
  };

  res.json({ buildId, statusUrl: `/api/build/${buildId}/stream`, downloadUrl: `/api/build/${buildId}/download` });

  // Kick off async build.
  (async () => {
    try {
      stream.status = 'building';
      log(`Build ${buildId} starting`);

      // 1. Compose embedded_config.json from UI cfg.
      const embeddedCfg = {
        build_id: buildId,
        build_timestamp: buildTimestamp,
        site_code: cfg.siteCode || 'DEV',
        filename_template: cfg.filenameTemplate || '%FQDN%-%TIMESTAMP%-%UUID%',
        require_admin: cfg.requireAdmin !== false,
        delete_after_upload: cfg.deleteAfterUpload !== false,
        silent: cfg.silent !== false,
        use_vss: cfg.useVss !== false,
        max_collection_size_gb: Number(cfg.maxCollectionSizeGb || 0),
        cpu_limit_percent: Number(cfg.cpuLimitPercent || 0),
        concurrency: Number(cfg.concurrency || 2),
        progress_timeout_seconds: Number(cfg.progressTimeoutSeconds || 3600),
        output_format: cfg.outputFormat || 'jsonl',
        artifacts: cfg.artifacts,
        // Per-artifact parameter selections (browser scope, evtx time range, etc).
        // Sanitized to a plain map of strings/numbers/bools so the Rust collector's
        // serde_json parse doesn't trip on unexpected types.
        artifact_params: sanitizeArtifactParams(cfg.artifactParams),
        kape_targets: cfg.kapeTargets || [],
        encryption: {
          scheme: cfg.encryption?.scheme || 'x509',
          rsa_public_key_pem: cfg.encryption?.publicKeyPem || '',
        },
        upload: cfg.upload?.kind === 's3'
          ? {
              kind: 's3',
              local_path: null,
              s3: {
                bucket: cfg.upload.bucket,
                region: cfg.upload.region,
                access_key_id: cfg.upload.accessKeyId,
                secret_access_key: cfg.upload.secretAccessKey,
                endpoint: cfg.upload.endpoint || null,
                sse_kms_key_id: cfg.upload.sseKmsKeyId || null,
                verify_tls: cfg.upload.verifyTls !== false,
                prefix_template: cfg.upload.prefixTemplate || '',
              },
            }
          : { kind: 'local', local_path: cfg.upload?.localPath || 'C:\\IR\\Output', s3: null },
      };

      const cfgPath = path.join(COLLECTOR_DIR, 'src', 'embedded_config.json');
      // Restrict file mode so the secrets-bearing config isn't world-readable
      // for the brief window it lives on disk during compilation.
      fs.writeFileSync(cfgPath, JSON.stringify(embeddedCfg, null, 2), { mode: 0o600 });
      log(`Wrote embedded_config.json (${cfg.artifacts.length} artifacts, encryption=${embeddedCfg.encryption.scheme}, upload=${embeddedCfg.upload.kind})`);

      // 2. Invoke `cargo build --release`. Wrap so we ALWAYS restore a
      // clean placeholder afterwards — secrets must not sit on disk past
      // the moment cargo finishes reading the file.
      log('Running: cargo build --release --bin Collector');
      try {
        await runCommand('cargo', ['build', '--release', '--bin', 'Collector'], COLLECTOR_DIR, log);
      } finally {
        try {
          fs.writeFileSync(cfgPath, JSON.stringify(PLACEHOLDER_EMBEDDED_CONFIG, null, 2));
        } catch (e) {
          log(`WARN: could not restore placeholder embedded_config.json: ${e.message}`);
        }
      }

      // 3. Locate output binary, copy to builds/{buildId}/Collector.exe.
      const targetExe = path.join(COLLECTOR_DIR, 'target', 'release', os.platform() === 'win32' ? 'Collector.exe' : 'Collector');
      if (!fs.existsSync(targetExe)) throw new Error(`build output not found: ${targetExe}`);
      const outDir = path.join(BUILDS_DIR, buildId);
      fs.mkdirSync(outDir, { recursive: true });
      const outExe = path.join(outDir, `Collector_${buildId.slice(0,8)}.exe`);
      fs.copyFileSync(targetExe, outExe);
      stream.exePath = outExe;
      log(`Output: ${outExe} (${(fs.statSync(outExe).size / 1024 / 1024).toFixed(2)} MB)`);

      // 4. Write build metadata (no secrets).
      const meta = {
        build_id: buildId,
        build_timestamp: buildTimestamp,
        site_code: embeddedCfg.site_code,
        artifact_count: cfg.artifacts.length,
        artifacts: cfg.artifacts,
        kape_targets: embeddedCfg.kape_targets,
        encryption_scheme: embeddedCfg.encryption.scheme,
        upload_kind: embeddedCfg.upload.kind,
        s3_bucket: embeddedCfg.upload.s3?.bucket || null,
        s3_region: embeddedCfg.upload.s3?.region || null,
        binary_size_bytes: fs.statSync(outExe).size,
        binary_sha256: null,  // filled in below
      };
      meta.binary_sha256 = sha256File(outExe);
      fs.writeFileSync(path.join(outDir, 'build_metadata.json'), JSON.stringify(meta, null, 2));
      ledger.recordBuild(meta);

      stream.status = 'complete';
      log('BUILD COMPLETE');
      log(`SHA256: ${meta.binary_sha256}`);
      for (const r of stream.listeners) {
        r.write(`event: complete\ndata: ${JSON.stringify({ buildId, sha256: meta.binary_sha256, size: meta.binary_size_bytes })}\n\n`);
        r.end();
      }
    } catch (e) {
      stream.status = 'failed';
      log(`BUILD FAILED: ${String(e?.message || e)}`);
      for (const r of stream.listeners) {
        r.write(`event: error\ndata: ${JSON.stringify({ message: String(e?.message || e) })}\n\n`);
        r.end();
      }
    }
  })();
});

app.get('/api/build/:id/stream', (req, res) => {
  const stream = buildStreams.get(req.params.id);
  if (!stream) return res.status(404).end();
  res.set({
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
  });
  res.flushHeaders();
  for (const line of stream.logs) res.write(`data: ${line}\n\n`);
  if (stream.status === 'complete' || stream.status === 'failed') {
    res.write(`event: ${stream.status}\ndata: {}\n\n`);
    return res.end();
  }
  stream.listeners.add(res);
  req.on('close', () => stream.listeners.delete(res));
});

app.get('/api/build/:id/download', (req, res) => {
  const stream = buildStreams.get(req.params.id);
  if (!stream || !stream.exePath) {
    // Try ledger fallback
    const lookup = ledger.findBuild(req.params.id);
    if (lookup?.exe_path && fs.existsSync(lookup.exe_path)) {
      return res.download(lookup.exe_path);
    }
    return res.status(404).json({ error: 'build not found or not yet complete' });
  }
  res.download(stream.exePath);
});

app.get('/api/builds', (_req, res) => res.json(ledger.listBuilds()));

// -------------------------- helpers --------------------------
function runCommand(cmd, args, cwd, log) {
  return new Promise((resolve, reject) => {
    const ps = spawn(cmd, args, { cwd, shell: true });
    ps.stdout.on('data', (b) => b.toString().split(/\r?\n/).forEach((line) => line && log(line)));
    ps.stderr.on('data', (b) => b.toString().split(/\r?\n/).forEach((line) => line && log(line)));
    ps.on('error', reject);
    ps.on('close', (code) => code === 0 ? resolve() : reject(new Error(`${cmd} exited with code ${code}`)));
  });
}

function sha256File(p) {
  return createHash('sha256').update(fs.readFileSync(p)).digest('hex');
}

app.listen(PORT, () => {
  console.log(`DFIR AgentBuilder backend listening on http://localhost:${PORT}`);
  console.log(`Collector source: ${COLLECTOR_DIR}`);
  console.log(`Build outputs:    ${BUILDS_DIR}`);
});
