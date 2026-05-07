import { useState } from 'react';
import { Cloud, HardDrive, CheckCircle2, XCircle, Loader2, FileJson } from 'lucide-react';

import type { BuildSpec } from '../../lib/types';
import Card from '../ui/Card';
import { Field, Input, Select, Toggle } from '../ui/Form';
import { api } from '../../lib/api';

interface P { spec: BuildSpec; update: <K extends keyof BuildSpec>(k: K, v: BuildSpec[K]) => void; }

export default function Step3Upload({ spec, update }: P) {
  const u = spec.upload;
  const setU = (patch: Partial<typeof u>) => update('upload', { ...u, ...patch });
  const [validating, setValidating] = useState(false);
  const [validationResult, setValidationResult] = useState<{ ok: boolean; msg: string } | null>(null);
  const [policyJson, setPolicyJson] = useState<string | null>(null);

  const onValidate = async () => {
    setValidating(true);
    setValidationResult(null);
    try {
      const r = await api.validateS3({
        bucket: u.bucket || '',
        region: u.region || '',
        accessKeyId: u.accessKeyId || '',
        secretAccessKey: u.secretAccessKey || '',
        endpoint: u.endpoint,
        sseKmsKeyId: u.sseKmsKeyId,
      });
      if (r.ok) setValidationResult({ ok: true, msg: r.note ?? `PutObject OK (${r.testKey})` });
      else setValidationResult({ ok: false, msg: r.error ?? `Status ${r.status}` });
    } catch (e: any) {
      setValidationResult({ ok: false, msg: String(e?.message || e) });
    } finally { setValidating(false); }
  };

  const onGenPolicy = async () => {
    const p = await api.generateIamPolicy({ bucket: u.bucket || '', kmsKeyArn: u.sseKmsKeyId, accessKeyId: u.accessKeyId });
    setPolicyJson(JSON.stringify(p, null, 2));
  };

  return (
    <div className="space-y-6">
      <div>
        <div className="text-[10px] tracking-[0.2em] font-mono mb-1" style={{ color: 'var(--accent)' }}>STEP 3 of 6</div>
        <h2 className="text-2xl font-semibold tracking-tight">Upload Target</h2>
        <p className="text-sm text-[var(--text-muted)] mt-1">Where the encrypted evidence container lands. AWS S3 is recommended for fleet deployments.</p>
      </div>

      <Card title="Destination">
        <div className="grid grid-cols-2 gap-3">
          <DestCard active={u.kind === 's3'} onClick={() => setU({ kind: 's3' })}
            icon={<Cloud className="w-5 h-5" />} title="AWS S3 Direct"
            desc="Multipart upload, SSE-KMS, write-only IAM. Recommended for production fleets." />
          <DestCard active={u.kind === 'local'} onClick={() => setU({ kind: 'local' })}
            icon={<HardDrive className="w-5 h-5" />} title="Local / UNC Path"
            desc="External drive, mapped network share, or air-gapped IR dropbox." />
        </div>
      </Card>

      {u.kind === 's3' && (
        <Card title="AWS S3 Configuration" desc="Credentials are embedded in the resulting EXE. Use a write-only IAM user — generate the minimum-required policy below.">
          <div className="grid md:grid-cols-2 gap-4">
            <Field label="Bucket name" required>
              <Input value={u.bucket || ''} onChange={(v) => setU({ bucket: v })} placeholder="ir-evidence-acmecorp-2026" />
            </Field>
            <Field label="Region" required>
              <Select value={u.region || ''} onChange={(v) => setU({ region: v })}>
                <option value="">Select region…</option>
                <option value="ap-south-1">ap-south-1 (Mumbai)</option>
                <option value="ap-southeast-1">ap-southeast-1 (Singapore)</option>
                <option value="us-east-1">us-east-1 (N. Virginia)</option>
                <option value="us-west-2">us-west-2 (Oregon)</option>
                <option value="eu-west-1">eu-west-1 (Ireland)</option>
                <option value="eu-central-1">eu-central-1 (Frankfurt)</option>
                <option value="ap-northeast-1">ap-northeast-1 (Tokyo)</option>
              </Select>
            </Field>
            <Field label="Access Key ID" required>
              <Input value={u.accessKeyId || ''} onChange={(v) => setU({ accessKeyId: v })} placeholder="AKIA…" className="font-mono" />
            </Field>
            <Field label="Secret Access Key" required>
              <Input type="password" value={u.secretAccessKey || ''} onChange={(v) => setU({ secretAccessKey: v })} placeholder="wJalrXUtnFEMI/…" className="font-mono" />
            </Field>
            <Field label="SSE-KMS Key ARN" desc="Required for SSE-KMS encryption (recommended).">
              <Input value={u.sseKmsKeyId || ''} onChange={(v) => setU({ sseKmsKeyId: v })} placeholder="arn:aws:kms:ap-south-1:…" className="font-mono text-xs" />
            </Field>
            <Field label="Custom endpoint" desc="Leave empty for AWS. Use http(s)://host:port for MinIO.">
              <Input value={u.endpoint || ''} onChange={(v) => setU({ endpoint: v })} placeholder="(AWS default)" className="font-mono" />
            </Field>
          </div>

          <div className="mt-4">
            <Field label="S3 object key prefix (folder layout)" required desc="Variables: %SITE% %FQDN% %TIMESTAMP% %UUID%. Each upload becomes <prefix>/<filename>. Default %SITE%/%FQDN% gives a clean per-host folder per site.">
              <Input value={u.prefixTemplate ?? '%SITE%/%FQDN%'} onChange={(v) => setU({ prefixTemplate: v })} placeholder="%SITE%/%FQDN%" className="font-mono" />
            </Field>
            <div
              className="mt-2 p-3 rounded border text-xs"
              style={{
                backgroundColor: 'var(--warning-bg)',
                borderColor: 'var(--warning)',
                color: 'var(--warning)',
              }}
            >
              <strong>Don't put the access key here.</strong> Folder names are visible to anyone with ListBucket. Keep keys out of object paths and use Object Lock + write-only IAM (see <code className="font-mono">docs/aws-setup.md</code>) for tamper-resistance.
            </div>
          </div>

          <div className="mt-4 flex gap-3 flex-wrap">
            <button
              onClick={onValidate}
              disabled={validating || !u.bucket || !u.region || !u.accessKeyId || !u.secretAccessKey}
              className="btn-primary px-4 py-2 rounded-md flex items-center gap-2 text-sm font-medium"
            >
              {validating ? <Loader2 className="w-4 h-4 animate-spin" /> : <CheckCircle2 className="w-4 h-4" />}
              Validate connection (test PutObject)
            </button>
            <button
              onClick={onGenPolicy}
              disabled={!u.bucket}
              className="btn-ghost px-4 py-2 rounded-md flex items-center gap-2 text-sm"
            >
              <FileJson className="w-4 h-4" /> Generate IAM policy
            </button>
          </div>

          {validationResult && (
            <div
              className="mt-3 p-3 rounded border text-sm flex items-start gap-2"
              style={
                validationResult.ok
                  ? { backgroundColor: 'var(--success-bg)', borderColor: 'var(--success)', color: 'var(--success)' }
                  : { backgroundColor: 'var(--danger-bg)',  borderColor: 'var(--danger)',  color: 'var(--danger)'  }
              }
            >
              {validationResult.ok ? <CheckCircle2 className="w-4 h-4 mt-0.5" /> : <XCircle className="w-4 h-4 mt-0.5" />}
              <span>{validationResult.msg}</span>
            </div>
          )}

          {policyJson && (
            <div className="mt-4">
              <div className="text-xs text-[var(--text-muted)] mb-1">Minimum IAM policy — paste into AWS Console → IAM → Policies → Create:</div>
              <pre
                className="p-3 rounded border text-xs overflow-x-auto font-mono"
                style={{
                  backgroundColor: 'var(--code-bg)',
                  borderColor: 'var(--border-default)',
                  color: 'var(--accent)',
                }}
              >{policyJson}</pre>
            </div>
          )}
        </Card>
      )}

      {u.kind === 'local' && (
        <Card title="Local / UNC Output" desc="The collector copies the encrypted container here at the end of its run.">
          <Field label="Output directory" required>
            <Input value={u.localPath || ''} onChange={(v) => setU({ localPath: v })} placeholder={`C:\\IR\\Output  or  \\\\IRSERVER\\IRShare\\Drop`} className="font-mono" />
          </Field>
          <Toggle
            className="mt-4"
            label="Verify TLS"
            desc="Always on for AWS; only relevant for HTTPS endpoints."
            value={u.verifyTls !== false}
            onChange={(v) => setU({ verifyTls: v })}
          />
        </Card>
      )}
    </div>
  );
}

function DestCard({ active, onClick, icon, title, desc }: { active: boolean; onClick: () => void; icon: React.ReactNode; title: string; desc: string }) {
  return (
    <button
      onClick={onClick}
      className="p-4 rounded-lg border text-left transition-all"
      style={
        active
          ? { borderColor: 'var(--accent)', backgroundColor: 'var(--accent-bg)', boxShadow: 'var(--accent-glow)' }
          : { borderColor: 'var(--border-default)', backgroundColor: 'var(--bg-surface)' }
      }
    >
      <div className="flex items-center gap-2 mb-2">
        <div
          className="w-8 h-8 rounded flex items-center justify-center"
          style={
            active
              ? { backgroundColor: 'var(--accent-bg-hover)', color: 'var(--accent)' }
              : { backgroundColor: 'var(--bg-elevated)', color: 'var(--text-muted)' }
          }
        >
          {icon}
        </div>
        <div className="font-semibold text-[var(--text-primary)]">{title}</div>
      </div>
      <p className="text-xs text-[var(--text-muted)]">{desc}</p>
    </button>
  );
}
