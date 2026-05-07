import { useState } from 'react';
import { Hammer, Download, CheckCircle2, AlertCircle, Loader2, Terminal } from 'lucide-react';

import type { ArtifactCategory, BuildSpec } from '../../lib/types';
import Card from '../ui/Card';
import { api } from '../../lib/api';

interface P { spec: BuildSpec; catalog: ArtifactCategory[] | null; }

type BuildStatus = 'idle' | 'building' | 'complete' | 'failed';

export default function Step6Review({ spec, catalog }: P) {
  const [status, setStatus] = useState<BuildStatus>('idle');
  const [logs, setLogs] = useState<string[]>([]);
  const [buildId, setBuildId] = useState<string | null>(null);
  const [downloadUrl, setDownloadUrl] = useState<string | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const yamlPreview = JSON.stringify({
    siteCode: spec.siteCode,
    filenameTemplate: spec.filenameTemplate,
    artifacts: spec.artifacts,
    kapeTargets: spec.kapeTargets,
    useVss: spec.useVss,
    upload: redactUpload(spec.upload),
    encryption: { scheme: spec.encryption.scheme, fingerprint: spec.encryption.fingerprintSha256 ?? null },
    requireAdmin: spec.requireAdmin,
    silent: spec.silent,
    deleteAfterUpload: spec.deleteAfterUpload,
    cpuLimitPercent: spec.cpuLimitPercent,
    concurrency: spec.concurrency,
    progressTimeoutSeconds: spec.progressTimeoutSeconds,
    outputFormat: spec.outputFormat,
    maxCollectionSizeGb: spec.maxCollectionSizeGb,
  }, null, 2);

  const validation = validateSpec(spec);

  const startBuild = async () => {
    setStatus('building');
    setLogs([]);
    setErrorMsg(null);
    try {
      const r = await api.startBuild(spec);
      setBuildId(r.buildId);
      setDownloadUrl(r.downloadUrl);
      const es = api.logStream(r.buildId);
      es.onmessage = (e) => setLogs((l) => [...l, e.data]);
      es.addEventListener('complete', () => { setStatus('complete'); es.close(); });
      es.addEventListener('error', (e: any) => {
        try {
          const data = JSON.parse(e.data);
          setErrorMsg(data.message ?? 'build failed');
        } catch { setErrorMsg('build failed'); }
        setStatus('failed');
        es.close();
      });
    } catch (e: any) {
      setErrorMsg(String(e?.message || e));
      setStatus('failed');
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <div className="text-[10px] tracking-[0.2em] font-mono mb-1" style={{ color: 'var(--accent)' }}>STEP 6 of 6</div>
        <h2 className="text-2xl font-semibold tracking-tight">Review & Build</h2>
        <p className="text-sm text-[var(--text-muted)] mt-1">Final review. Click Build to compile a fresh Collector.exe with this configuration baked in.</p>
      </div>

      {validation.length > 0 && (
        <Card title="Issues to resolve">
          <ul className="space-y-2">
            {validation.map((v, i) => (
              <li key={i} className="flex items-start gap-2 text-sm">
                <AlertCircle className="w-4 h-4 mt-0.5 flex-shrink-0" style={{ color: 'var(--warning)' }} />
                <span style={{ color: 'var(--warning)' }}>{v}</span>
              </li>
            ))}
          </ul>
        </Card>
      )}

      <div className="grid lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          <Card title="Configuration Preview" desc="Secrets redacted. This is what will be embedded into Collector.exe.">
            <pre
              className="text-xs font-mono rounded p-3 overflow-x-auto max-h-[420px] border"
              style={{
                backgroundColor: 'var(--code-bg)',
                borderColor: 'var(--border-default)',
                color: 'var(--accent)',
              }}
            >{yamlPreview}</pre>
          </Card>
        </div>

        <div className="space-y-3">
          <SummaryStat label="Artifacts" value={spec.artifacts.length} />
          <SummaryStat label="KAPE targets" value={spec.kapeTargets.length} />
          <SummaryStat label="Encryption" value={spec.encryption.scheme.toUpperCase()} />
          <SummaryStat label="Upload" value={spec.upload.kind === 's3' ? `S3: ${spec.upload.bucket || '(unset)'}` : `Local: ${spec.upload.localPath || '(unset)'}`} />
          <SummaryStat label="VSS snapshot" value={spec.useVss ? 'YES' : 'NO'} />
          <SummaryStat label="Requires admin" value={spec.requireAdmin ? 'YES' : 'NO'} />
        </div>
      </div>

      <Card title="Build" desc="Streams cargo build output. ~1-3 minutes the first time, ~10-30 seconds on subsequent rebuilds.">
        <div className="flex items-center gap-3 flex-wrap">
          <button
            onClick={startBuild}
            disabled={status === 'building' || validation.length > 0}
            className="btn-primary px-6 py-3 rounded-md flex items-center gap-2 font-semibold border-2"
            style={{
              fontSize: '15px',
              borderColor: 'var(--accent-border)',
            }}
          >
            {status === 'building'
              ? <><Loader2 className="w-5 h-5 animate-spin" /> Building...</>
              : <><Hammer className="w-5 h-5" /> BUILD COLLECTOR</>}
          </button>

          {status === 'complete' && downloadUrl && (
            <a
              href={downloadUrl}
              download
              className="btn-secondary px-6 py-3 rounded-md flex items-center gap-2 font-semibold border-2"
              style={{ borderColor: 'var(--accent-2-border)' }}
            >
              <Download className="w-5 h-5" /> Download Collector.exe
            </a>
          )}

          {status === 'complete' && (
            <span className="flex items-center gap-1 text-sm" style={{ color: 'var(--success)' }}>
              <CheckCircle2 className="w-4 h-4" /> Build complete
            </span>
          )}
          {status === 'failed' && (
            <span className="flex items-center gap-1 text-sm" style={{ color: 'var(--danger)' }}>
              <AlertCircle className="w-4 h-4" /> {errorMsg ?? 'Build failed'}
            </span>
          )}
        </div>

        {(status !== 'idle') && (
          <div
            className="mt-4 rounded border"
            style={{
              backgroundColor: 'var(--code-bg)',
              borderColor: 'var(--border-default)',
            }}
          >
            <div
              className="px-3 py-2 border-b flex items-center gap-2 text-xs"
              style={{
                borderColor: 'var(--border-subtle)',
                color: 'var(--text-muted)',
              }}
            >
              <Terminal className="w-3.5 h-3.5" /> Build log {buildId && <span className="font-mono opacity-50">· {buildId.slice(0, 8)}</span>}
            </div>
            <pre
              className="text-[11px] font-mono p-3 overflow-x-auto max-h-[320px] overflow-y-auto whitespace-pre-wrap"
              style={{ color: 'var(--success)' }}
            >
              {logs.length === 0 ? <span style={{ opacity: 0.4 }}>awaiting build start...</span> : logs.join('\n')}
            </pre>
          </div>
        )}
      </Card>
    </div>
  );
}

function SummaryStat({ label, value }: { label: string; value: string | number }) {
  return (
    <div
      className="p-3 rounded border"
      style={{
        backgroundColor: 'var(--bg-surface)',
        borderColor: 'var(--border-default)',
      }}
    >
      <div className="text-[10px] uppercase tracking-wider text-[var(--text-muted)]">{label}</div>
      <div className="font-mono text-sm mt-0.5 truncate" style={{ color: 'var(--accent)' }}>{value}</div>
    </div>
  );
}

function redactUpload(u: BuildSpec['upload']) {
  if (u.kind === 's3') {
    return {
      kind: 's3',
      bucket: u.bucket,
      region: u.region,
      accessKeyId: u.accessKeyId ? `${u.accessKeyId.slice(0, 4)}…${u.accessKeyId.slice(-4)}` : '(unset)',
      secretAccessKey: u.secretAccessKey ? '***REDACTED***' : '(unset)',
      sseKmsKeyId: u.sseKmsKeyId ?? null,
      endpoint: u.endpoint ?? '(AWS default)',
      prefixTemplate: u.prefixTemplate ?? '',
    };
  }
  return { kind: 'local', localPath: u.localPath };
}

function validateSpec(spec: BuildSpec): string[] {
  const issues: string[] = [];
  if (spec.artifacts.length === 0) issues.push('No artifacts selected — pick a bundle on Step 2.');
  if (spec.upload.kind === 's3') {
    if (!spec.upload.bucket) issues.push('S3 bucket name not set (Step 3).');
    if (!spec.upload.region) issues.push('S3 region not set (Step 3).');
    if (!spec.upload.accessKeyId) issues.push('AWS Access Key ID not set (Step 3).');
    if (!spec.upload.secretAccessKey) issues.push('AWS Secret Access Key not set (Step 3).');
  } else {
    if (!spec.upload.localPath) issues.push('Local output path not set (Step 3).');
  }
  if (spec.encryption.scheme === 'x509' && !spec.encryption.publicKeyPem) {
    issues.push('X509 encryption selected but no public key — generate or upload one on Step 4.');
  }
  return issues;
}
