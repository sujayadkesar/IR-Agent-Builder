import { useState } from 'react';
import { KeyRound, Download, Loader2, ShieldAlert } from 'lucide-react';

import type { BuildSpec } from '../../lib/types';
import Card from '../ui/Card';
import { Toggle } from '../ui/Form';
import { api } from '../../lib/api';

interface P { spec: BuildSpec; update: <K extends keyof BuildSpec>(k: K, v: BuildSpec[K]) => void; }

export default function Step4Encryption({ spec, update }: P) {
  const enc = spec.encryption;
  const [generating, setGenerating] = useState(false);

  const generateKey = async () => {
    setGenerating(true);
    try {
      const kp = await api.generateKeypair(4096);
      update('encryption', {
        scheme: 'x509',
        publicKeyPem: kp.publicKeyPem,
        privateKeyPem: kp.privateKeyPem,
        fingerprintSha256: kp.fingerprintSha256,
      });
    } finally {
      setGenerating(false);
    }
  };

  const downloadPrivate = () => {
    if (!enc.privateKeyPem) return;
    const blob = new Blob([enc.privateKeyPem], { type: 'application/x-pem-file' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `dfir-private-${(enc.fingerprintSha256 || 'key').slice(0, 8)}.pem`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      <div>
        <div className="text-[10px] tracking-[0.2em] font-mono mb-1" style={{ color: 'var(--accent)' }}>STEP 4 of 6</div>
        <h2 className="text-2xl font-semibold tracking-tight">Encryption & Hardening</h2>
        <p className="text-sm text-[var(--text-muted)] mt-1">Hybrid X509 (RSA-OAEP wrap + AES-256-GCM) is the recommended scheme. Even full binary disassembly cannot decrypt evidence — only the private key holder can.</p>
      </div>

      <Card title="Encryption Scheme">
        <div className="grid md:grid-cols-2 gap-3">
          <SchemeCard
            active={enc.scheme === 'x509'}
            onClick={() => update('encryption', { ...enc, scheme: 'x509' })}
            title="X509 (Recommended)"
            desc="RSA-4096 wraps a per-run AES-256 key. Public key embedded in EXE; private key only on analyst side."
          />
          <SchemeCard
            active={enc.scheme === 'none'}
            onClick={() => update('encryption', { ...enc, scheme: 'none', publicKeyPem: '', privateKeyPem: '' })}
            title="None"
            desc="Container ships unencrypted. Acceptable if S3 SSE-KMS + write-only IAM are in place."
          />
        </div>
      </Card>

      {enc.scheme === 'x509' && (
        <Card title="Key Pair" desc="Generate a fresh RSA-4096 keypair. The PUBLIC key is embedded in the collector; the PRIVATE key must be stored securely.">
          <div className="flex flex-wrap items-center gap-3">
            <button
              onClick={generateKey}
              disabled={generating}
              className="btn-primary px-4 py-2 rounded-md flex items-center gap-2 text-sm font-medium"
            >
              {generating ? <Loader2 className="w-4 h-4 animate-spin" /> : <KeyRound className="w-4 h-4" />}
              {enc.publicKeyPem ? 'Regenerate' : 'Generate RSA-4096 keypair'}
            </button>
            {enc.privateKeyPem && (
              <button
                onClick={downloadPrivate}
                className="btn-secondary px-4 py-2 rounded-md flex items-center gap-2 text-sm font-medium"
              >
                <Download className="w-4 h-4" /> Download private key (one chance)
              </button>
            )}
          </div>

          {enc.fingerprintSha256 && (
            <div
              className="mt-4 p-3 rounded border text-xs"
              style={{
                backgroundColor: 'var(--success-bg)',
                borderColor: 'var(--success)',
                color: 'var(--success)',
              }}
            >
              <div className="font-medium mb-1">Public key fingerprint (SHA-256)</div>
              <div className="font-mono break-all">{enc.fingerprintSha256}</div>
            </div>
          )}

          {enc.privateKeyPem && (
            <div
              className="mt-4 p-3 rounded border text-xs flex items-start gap-2"
              style={{
                backgroundColor: 'var(--warning-bg)',
                borderColor: 'var(--warning)',
                color: 'var(--warning)',
              }}
            >
              <ShieldAlert className="w-4 h-4 mt-0.5 flex-shrink-0" />
              <div>
                <strong>Store this private key now.</strong> The backend does NOT persist it.
                Lose it and every collection from this build is unrecoverable. Recommended:
                AWS Secrets Manager (<code className="font-mono">dfir/{spec.siteCode}/build-XXXXXXXX/privkey</code>).
              </div>
            </div>
          )}
        </Card>
      )}

      <Card title="Runtime Hardening">
        <div className="space-y-2">
          <Toggle
            label={spec.targetPlatform === 'linux' ? 'Require root to run' : 'Require admin to run'}
            desc={spec.targetPlatform === 'linux'
              ? 'Refuses to run if not root. Most Linux artifacts need root for /proc, journald, and audit logs.'
              : 'Refuses to run if not elevated (the EXE manifest already requests UAC; this adds a defensive runtime check).'}
            value={spec.requireAdmin}
            onChange={(v) => update('requireAdmin', v)}
          />
          <Toggle
            label="Silent / no prompt"
            desc={spec.targetPlatform === 'linux'
              ? 'No interactive prompts. Required for cron/systemd-based deployment.'
              : 'Required for GPO startup-script deployment. Set OFF for interactive IR use.'}
            value={spec.silent}
            onChange={(v) => update('silent', v)}
          />
          <Toggle label="Delete local container after upload" desc="Reduces on-disk exposure. Strongly recommended for production." value={spec.deleteAfterUpload} onChange={(v) => update('deleteAfterUpload', v)} />
        </div>
      </Card>
    </div>
  );
}

function SchemeCard({ active, onClick, title, desc }: { active: boolean; onClick: () => void; title: string; desc: string }) {
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
      <div className="font-semibold text-[var(--text-primary)] mb-1">{title}</div>
      <p className="text-xs text-[var(--text-muted)]">{desc}</p>
    </button>
  );
}
