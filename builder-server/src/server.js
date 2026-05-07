// DFIR AgentBuilder — build orchestration server (v2).
//
// Endpoints:
//   GET  /api/artifacts              List artifact catalog (supports ?platform=windows|linux|all)
//   GET  /api/bundles                List bundle presets (?platform=windows|linux)
//   POST /api/artifacts/custom       Create a custom artifact definition (YAML body)
//   PUT  /api/artifacts/custom/:name Update a custom artifact
//   DELETE /api/artifacts/custom/:name Delete a custom artifact
//   POST /api/artifacts/validate     Validate artifact YAML without saving
//   GET  /api/artifacts/:name/export Export artifact YAML source
//   POST /api/aws/iam-policy         Generate IAM write-only policy JSON
//   POST /api/aws/validate           Test PutObject/DeleteObject on S3 bucket
//   POST /api/keypair/generate       Generate RSA-4096 keypair
//   POST /api/build                  Kick off collector build (supports target_platform)
//   GET  /api/build/:id/stream       SSE log stream for a build
//   GET  /api/build/:id/download     Download resulting binary
//   GET  /api/builds                 Audit ledger — list all past builds

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
import yaml from 'js-yaml';

import { BUNDLES } from './lib/catalog.js';
import { generateIamPolicy, validateS3Connection } from './lib/aws.js';
import { openLedger } from './lib/ledger.js';
import { createRegistry } from './lib/artifact-loader.js';
import { vaultifyConfig } from './lib/credential-vault.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT = path.resolve(__dirname, '..', '..');
const COLLECTOR_DIR = path.join(ROOT, 'collector');
const BUILDS_DIR = path.join(ROOT, 'builds');
const ARTIFACTS_DIR = path.join(ROOT, 'artifacts');
fs.mkdirSync(BUILDS_DIR, { recursive: true });

const app = express();
const PORT = Number(process.env.PORT || 8787);

app.use(morgan('dev'));
app.use(cors());
app.use(express.json({ limit: '4mb' }));
app.use(express.text({ type: 'text/yaml', limit: '1mb' }));

function redactSecrets(str) {
  if (typeof str !== 'string') return str;
  return str
    .replace(/\b(?:AKIA|ASIA|AIDA|AGPA|AROA|AIPA|ANPA|ANVA|AIDB|ABIA|ACCA)[A-Z0-9]{16}\b/g, 'AKIA****REDACTED')
    .replace(/(?<![A-Za-z0-9+/])[A-Za-z0-9+/=]{40}(?![A-Za-z0-9+/])/g, '****REDACTED-40****');
}

const PLACEHOLDER_EMBEDDED_CONFIG = {
  build_id: 'placeholder',
  build_timestamp: '1970-01-01T00:00:00Z',
  site_code: 'PLACEHOLDER',
  filename_template: '%FQDN%-%TIMESTAMP%-%UUID%',
  require_admin: true, delete_after_upload: true, silent: true, use_vss: true,
  max_collection_size_gb: 0, cpu_limit_percent: 0, concurrency: 2,
  progress_timeout_seconds: 3600, output_format: 'jsonl',
  target_platform: 'windows',
  artifacts: [], artifact_params: {}, kape_targets: [],
  embedded_sources: {},
  chunk_upload: { enabled: false, chunk_size_mb: 64, stream_mode: false, low_disk_threshold_mb: 0 },
  encryption: { scheme: 'none', rsa_public_key_pem: '' },
  upload: { kind: 'local', local_path: 'C:\\IR\\Output', s3: null },
};

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
const buildStreams = new Map();
const registry = createRegistry();

// Load YAML bundles
let yamlBundles = [];
try {
  const bundlesPath = path.join(ARTIFACTS_DIR, 'bundles.yaml');
  if (fs.existsSync(bundlesPath)) {
    const bundlesYaml = yaml.load(fs.readFileSync(bundlesPath, 'utf8'));
    yamlBundles = bundlesYaml.bundles || [];
    console.log(`[bundles] loaded ${yamlBundles.length} bundles from YAML`);
  }
} catch (e) {
  console.warn('[bundles] failed to load YAML bundles:', e.message);
}

// ======================= Artifact catalog =======================
app.get('/api/artifacts', (req, res) => {
  const platform = req.query.platform || null;
  res.json(registry.getCatalog(platform));
});

app.get('/api/bundles', (req, res) => {
  const platform = req.query.platform || null;
  const allBundles = yamlBundles.length > 0 ? yamlBundles : BUNDLES;
  if (platform) {
    const filtered = allBundles.filter(b =>
      !b.platform || b.platform === platform || b.platform === 'all'
    );
    return res.json(filtered);
  }
  res.json(allBundles);
});

// ======================= Custom artifact CRUD =======================
app.post('/api/artifacts/validate', (req, res) => {
  const yamlContent = typeof req.body === 'string' ? req.body : req.body?.yaml;
  if (!yamlContent) return res.status(400).json({ error: 'YAML body required' });
  const result = registry.validateArtifactYaml(yamlContent);
  res.json(result);
});

app.post('/api/artifacts/custom', (req, res) => {
  const yamlContent = typeof req.body === 'string' ? req.body : req.body?.yaml;
  const filename = req.body?.filename || `custom_${Date.now()}`;
  if (!yamlContent) return res.status(400).json({ error: 'YAML body required' });

  const validation = registry.validateArtifactYaml(yamlContent);
  if (!validation.valid) {
    return res.status(400).json({ error: 'validation failed', errors: validation.errors });
  }

  try {
    const filePath = registry.saveCustomArtifact(yamlContent, filename);
    res.json({ ok: true, filePath, artifact: validation.parsed });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.put('/api/artifacts/custom/:name', (req, res) => {
  const yamlContent = typeof req.body === 'string' ? req.body : req.body?.yaml;
  if (!yamlContent) return res.status(400).json({ error: 'YAML body required' });

  const validation = registry.validateArtifactYaml(yamlContent);
  // For updates, the name will already exist — skip that check
  const realErrors = validation.errors.filter(e => !e.includes('already exists'));
  if (realErrors.length > 0) {
    return res.status(400).json({ error: 'validation failed', errors: realErrors });
  }

  try {
    registry.deleteCustomArtifact(req.params.name);
    const filePath = registry.saveCustomArtifact(yamlContent, req.params.name);
    res.json({ ok: true, filePath });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.delete('/api/artifacts/custom/:name', (req, res) => {
  try {
    const deleted = registry.deleteCustomArtifact(req.params.name);
    res.json({ ok: deleted });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

app.get('/api/artifacts/:name/export', (req, res) => {
  const yamlContent = registry.exportArtifact(req.params.name);
  if (!yamlContent) return res.status(404).json({ error: 'artifact not found' });
  res.type('text/yaml').send(yamlContent);
});

// Get the YAML template for creating new artifacts
app.get('/api/artifacts/template', (_req, res) => {
  const templatePath = path.join(ARTIFACTS_DIR, 'custom', 'TEMPLATE.yaml');
  if (fs.existsSync(templatePath)) {
    res.type('text/yaml').send(fs.readFileSync(templatePath, 'utf8'));
  } else {
    res.status(404).json({ error: 'template not found' });
  }
});

// ======================= AWS helpers =======================
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

// ======================= Keypair generation =======================
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

// ======================= Build orchestration =======================
app.post('/api/build', async (req, res) => {
  const cfg = req.body || {};
  if (!Array.isArray(cfg.artifacts) || cfg.artifacts.length === 0) {
    return res.status(400).json({ error: 'at least one artifact required' });
  }

  const buildId = randomUUID();
  const buildTimestamp = new Date().toISOString();
  const targetPlatform = cfg.targetPlatform || 'windows';
  const stream = { logs: [], status: 'starting', listeners: new Set(), exePath: null };
  buildStreams.set(buildId, stream);

  const log = (line) => {
    const safe = redactSecrets(String(line));
    const stamped = `[${new Date().toISOString().slice(11, 23)}] ${safe}`;
    stream.logs.push(stamped);
    for (const r of stream.listeners) r.write(`data: ${stamped}\n\n`);
  };

  res.json({
    buildId,
    targetPlatform,
    statusUrl: `/api/build/${buildId}/stream`,
    downloadUrl: `/api/build/${buildId}/download`,
  });

  // Async build
  (async () => {
    try {
      stream.status = 'building';
      log(`Build ${buildId} starting (target=${targetPlatform})`);

      // Get embedded artifact sources from YAML registry
      const { artifacts: resolvedArtifacts, embeddedSources } = registry.toEmbeddedFormat(
        cfg.artifacts, sanitizeArtifactParams(cfg.artifactParams)
      );

      let embeddedCfg = {
        build_id: buildId,
        build_timestamp: buildTimestamp,
        site_code: cfg.siteCode || 'DEV',
        filename_template: cfg.filenameTemplate || '%FQDN%-%TIMESTAMP%-%UUID%',
        require_admin: cfg.requireAdmin !== false,
        delete_after_upload: cfg.deleteAfterUpload !== false,
        silent: cfg.silent !== false,
        use_vss: targetPlatform === 'windows' ? (cfg.useVss !== false) : false,
        max_collection_size_gb: Number(cfg.maxCollectionSizeGb || 0),
        cpu_limit_percent: Number(cfg.cpuLimitPercent || 0),
        concurrency: Number(cfg.concurrency || 2),
        progress_timeout_seconds: Number(cfg.progressTimeoutSeconds || 3600),
        output_format: cfg.outputFormat || 'jsonl',
        target_platform: targetPlatform,
        artifacts: cfg.artifacts,
        artifact_params: sanitizeArtifactParams(cfg.artifactParams),
        kape_targets: targetPlatform === 'windows' ? (cfg.kapeTargets || []) : [],
        embedded_sources: embeddedSources,
        chunk_upload: {
          enabled: cfg.chunkUpload?.enabled !== false,
          chunk_size_mb: Number(cfg.chunkUpload?.chunkSizeMb || 64),
          stream_mode: cfg.chunkUpload?.streamMode || false,
          low_disk_threshold_mb: Number(cfg.chunkUpload?.lowDiskThresholdMb || 0),
        },
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
                credential_vault: '',
                credential_vault_hmac: '',
              },
            }
          : {
              kind: 'local',
              local_path: cfg.upload?.localPath || (targetPlatform === 'windows' ? 'C:\\IR\\Output' : '/tmp/dfir-output'),
              s3: null,
            },
      };

      // Vault the AWS credentials if using S3
      if (embeddedCfg.upload.kind === 's3' && embeddedCfg.upload.s3) {
        log('Encrypting AWS credentials into vault...');
        embeddedCfg = vaultifyConfig(embeddedCfg, buildId, buildTimestamp);
        log('Credential vault created (secrets protected against reverse engineering)');
      }

      const cfgPath = path.join(COLLECTOR_DIR, 'src', 'embedded_config.json');
      fs.writeFileSync(cfgPath, JSON.stringify(embeddedCfg, null, 2), { mode: 0o600 });
      log(`Wrote embedded_config.json (${cfg.artifacts.length} artifacts, platform=${targetPlatform}, encryption=${embeddedCfg.encryption.scheme}, upload=${embeddedCfg.upload.kind}, chunk_upload=${embeddedCfg.chunk_upload.enabled})`);

      // Determine build command based on target platform
      let cargoArgs = ['build', '--release', '--bin', 'Collector'];
      let targetTriple = null;
      let binaryExt = targetPlatform === 'windows' ? '.exe' : '';

      if (targetPlatform === 'linux' && os.platform() === 'win32') {
        targetTriple = 'x86_64-unknown-linux-gnu';
        cargoArgs.push('--target', targetTriple);
        log(`Cross-compiling for Linux (target=${targetTriple})`);
      } else if (targetPlatform === 'windows' && os.platform() !== 'win32') {
        targetTriple = 'x86_64-pc-windows-gnu';
        cargoArgs.push('--target', targetTriple);
        log(`Cross-compiling for Windows (target=${targetTriple})`);
      }

      log(`Running: cargo ${cargoArgs.join(' ')}`);
      try {
        await runCommand('cargo', cargoArgs, COLLECTOR_DIR, log);
      } finally {
        try {
          fs.writeFileSync(cfgPath, JSON.stringify(PLACEHOLDER_EMBEDDED_CONFIG, null, 2));
        } catch (e) {
          log(`WARN: could not restore placeholder embedded_config.json: ${e.message}`);
        }
      }

      // Locate output binary
      let targetExe;
      if (targetTriple) {
        targetExe = path.join(COLLECTOR_DIR, 'target', targetTriple, 'release', `Collector${binaryExt}`);
      } else {
        targetExe = path.join(COLLECTOR_DIR, 'target', 'release', `Collector${binaryExt}`);
      }
      if (!fs.existsSync(targetExe)) throw new Error(`build output not found: ${targetExe}`);

      const outDir = path.join(BUILDS_DIR, buildId);
      fs.mkdirSync(outDir, { recursive: true });
      const outName = targetPlatform === 'linux'
        ? `Collector_${buildId.slice(0,8)}_linux`
        : `Collector_${buildId.slice(0,8)}.exe`;
      const outExe = path.join(outDir, outName);
      fs.copyFileSync(targetExe, outExe);
      stream.exePath = outExe;
      log(`Output: ${outExe} (${(fs.statSync(outExe).size / 1024 / 1024).toFixed(2)} MB)`);

      // Build metadata
      const meta = {
        build_id: buildId,
        build_timestamp: buildTimestamp,
        target_platform: targetPlatform,
        site_code: embeddedCfg.site_code,
        artifact_count: cfg.artifacts.length,
        artifacts: cfg.artifacts,
        kape_targets: embeddedCfg.kape_targets,
        encryption_scheme: embeddedCfg.encryption.scheme,
        upload_kind: embeddedCfg.upload.kind,
        chunk_upload_enabled: embeddedCfg.chunk_upload.enabled,
        credential_vault_used: embeddedCfg.upload.kind === 's3',
        s3_bucket: embeddedCfg.upload.s3?.bucket || null,
        s3_region: embeddedCfg.upload.s3?.region || null,
        binary_size_bytes: fs.statSync(outExe).size,
        binary_sha256: null,
      };
      meta.binary_sha256 = sha256File(outExe);
      fs.writeFileSync(path.join(outDir, 'build_metadata.json'), JSON.stringify(meta, null, 2));
      ledger.recordBuild(meta);

      stream.status = 'complete';
      log('BUILD COMPLETE');
      log(`Platform: ${targetPlatform}`);
      log(`SHA256: ${meta.binary_sha256}`);
      log(`Credential vault: ${meta.credential_vault_used ? 'ENABLED' : 'DISABLED'}`);
      log(`Chunk upload: ${meta.chunk_upload_enabled ? 'ENABLED' : 'DISABLED'}`);
      for (const r of stream.listeners) {
        r.write(`event: complete\ndata: ${JSON.stringify({ buildId, sha256: meta.binary_sha256, size: meta.binary_size_bytes, platform: targetPlatform })}\n\n`);
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
    const lookup = ledger.findBuild(req.params.id);
    if (lookup?.exe_path && fs.existsSync(lookup.exe_path)) {
      return res.download(lookup.exe_path);
    }
    return res.status(404).json({ error: 'build not found or not yet complete' });
  }
  res.download(stream.exePath);
});

app.get('/api/builds', (_req, res) => res.json(ledger.listBuilds()));

// ======================= Helpers =======================
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
  console.log(`Artifact YAML:    ${ARTIFACTS_DIR}`);
  console.log(`Loaded artifacts: ${registry.artifacts.size}`);
  console.log(`Target platforms: windows, linux`);
});
