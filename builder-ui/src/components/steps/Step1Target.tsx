import type { BuildSpec } from '../../lib/types';
import Card from '../ui/Card';
import { Field, Input, Select, Toggle } from '../ui/Form';

interface P { spec: BuildSpec; update: <K extends keyof BuildSpec>(k: K, v: BuildSpec[K]) => void; }

export default function Step1Target({ spec, update }: P) {
  const preview = spec.filenameTemplate
    .replace('%FQDN%', 'LAPTOP-A1B2C3')
    .replace('%TIMESTAMP%', '2026-05-06T14-30-00Z')
    .replace('%UUID%', 'a3f9b221')
    .replace('%SITE%', spec.siteCode || 'SITE');

  return (
    <div className="space-y-6">
      <SectionHeader
        eyebrow="STEP 1 of 6"
        title="Target & Naming"
        subtitle="Pick the OS profile and how each endpoint's evidence file should be named in S3."
      />
      <div className="grid lg:grid-cols-2 gap-6">
        <Card title="Target OS" desc="Output binary architecture. win64 covers Windows 10/11 + Server 2016+">
          <Field label="OS profile">
            <Select value={spec.targetOs} onChange={(v) => update('targetOs', v as BuildSpec['targetOs'])}>
              <option value="win64">Windows x64 (default)</option>
              <option value="win32">Windows x86 (legacy 32-bit)</option>
            </Select>
          </Field>
        </Card>

        <Card title="Site Code" desc="Logical grouping prefix in S3 path (e.g. APAC-HYD, EU-LON, US-NYC)">
          <Field label="Site code">
            <Input value={spec.siteCode} onChange={(v) => update('siteCode', v.toUpperCase())} placeholder="APAC-HYD" />
          </Field>
        </Card>
      </div>

      <Card title="Filename Template" desc="Variables: %FQDN% %TIMESTAMP% %UUID% %SITE% — must be unique per endpoint to avoid S3 collisions.">
        <Field label="Template">
          <Input value={spec.filenameTemplate} onChange={(v) => update('filenameTemplate', v)} className="font-mono" />
        </Field>
        <div
          className="mt-3 p-3 rounded border font-mono text-sm"
          style={{
            backgroundColor: 'var(--code-bg)',
            borderColor: 'var(--border-default)',
            color: 'var(--accent)',
          }}
        >
          → {preview}.zip.enc
        </div>
        <Toggle
          className="mt-4"
          label="Append UUID suffix"
          desc="Prevents clock-skew collisions on the same host within the same second (recommended)"
          value={spec.uuidSuffix}
          onChange={(v) => update('uuidSuffix', v)}
        />
      </Card>
    </div>
  );
}

function SectionHeader({ eyebrow, title, subtitle }: { eyebrow: string; title: string; subtitle: string }) {
  return (
    <div>
      <div className="text-[10px] tracking-[0.2em] font-mono mb-1" style={{ color: 'var(--accent)' }}>{eyebrow}</div>
      <h2 className="text-2xl font-semibold tracking-tight text-[var(--text-primary)]">{title}</h2>
      <p className="text-sm text-[var(--text-muted)] mt-1">{subtitle}</p>
    </div>
  );
}
