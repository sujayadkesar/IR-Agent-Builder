import { Monitor, Terminal } from 'lucide-react';
import type { BuildSpec, TargetPlatform } from '../../lib/types';
import Card from '../ui/Card';
import { Field, Input, Toggle } from '../ui/Form';

interface P { spec: BuildSpec; update: <K extends keyof BuildSpec>(k: K, v: BuildSpec[K]) => void; }

export default function Step1Target({ spec, update }: P) {
  const isLinux = spec.targetPlatform === 'linux';
  const preview = spec.filenameTemplate
    .replace('%FQDN%', isLinux ? 'srv-prod-01' : 'LAPTOP-A1B2C3')
    .replace('%TIMESTAMP%', '2026-05-06T14-30-00Z')
    .replace('%UUID%', 'a3f9b221')
    .replace('%SITE%', spec.siteCode || 'SITE');

  const onPlatformChange = (p: TargetPlatform) => {
    update('targetPlatform', p);
    if (p === 'linux') {
      update('useVss', false);
      if (spec.upload.kind === 'local' && spec.upload.localPath?.startsWith('C:\\')) {
        update('upload', { ...spec.upload, localPath: '/tmp/ir-output' });
      }
    } else {
      update('useVss', true);
      if (spec.upload.kind === 'local' && spec.upload.localPath?.startsWith('/')) {
        update('upload', { ...spec.upload, localPath: 'C:\\IR\\Output' });
      }
    }
  };

  return (
    <div className="space-y-6">
      <SectionHeader
        eyebrow="STEP 1 of 6"
        title="Target & Naming"
        subtitle="Pick the target platform and how each endpoint's evidence file should be named."
      />

      <Card title="Target Platform" desc="Select the OS for the compiled collector binary. Artifacts and bundles will filter to match.">
        <div className="grid grid-cols-2 gap-4">
          <PlatformCard
            active={spec.targetPlatform === 'windows'}
            onClick={() => onPlatformChange('windows')}
            icon={<Monitor className="w-6 h-6" />}
            title="Windows"
            desc="Windows 10/11, Server 2016+. Supports VSS, raw NTFS, Registry hives, EVTX. Output: Collector.exe"
            badge="x86_64-pc-windows"
          />
          <PlatformCard
            active={spec.targetPlatform === 'linux'}
            onClick={() => onPlatformChange('linux')}
            icon={<Terminal className="w-6 h-6" />}
            title="Linux"
            desc="Ubuntu, RHEL, Debian, CentOS. Native commands, journald, /proc, containers. Output: Collector (ELF)"
            badge="x86_64-unknown-linux"
          />
        </div>
      </Card>

      <Card title="Site Code" desc="Logical grouping prefix in S3 path (e.g. APAC-HYD, EU-LON, US-NYC)">
        <Field label="Site code">
          <Input value={spec.siteCode} onChange={(v) => update('siteCode', v.toUpperCase())} placeholder="APAC-HYD" />
        </Field>
      </Card>

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
          → {preview}{isLinux ? '.tar.gz.enc' : '.zip.enc'}
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

function PlatformCard({ active, onClick, icon, title, desc, badge }: {
  active: boolean; onClick: () => void; icon: React.ReactNode; title: string; desc: string; badge: string;
}) {
  return (
    <button
      onClick={onClick}
      className="p-5 rounded-lg border text-left transition-all hover:scale-[1.01]"
      style={
        active
          ? { borderColor: 'var(--accent)', backgroundColor: 'var(--accent-bg)', boxShadow: 'var(--accent-glow)' }
          : { borderColor: 'var(--border-default)', backgroundColor: 'var(--bg-surface)' }
      }
    >
      <div className="flex items-center gap-3 mb-3">
        <div
          className="w-10 h-10 rounded-lg flex items-center justify-center"
          style={
            active
              ? { backgroundColor: 'var(--accent-bg-hover)', color: 'var(--accent)' }
              : { backgroundColor: 'var(--bg-elevated)', color: 'var(--text-muted)' }
          }
        >
          {icon}
        </div>
        <div>
          <div className="font-semibold text-[var(--text-primary)]">{title}</div>
          <span
            className="text-[10px] font-mono px-1.5 py-0.5 rounded"
            style={{
              backgroundColor: active ? 'var(--accent-bg-hover)' : 'var(--bg-elevated)',
              color: active ? 'var(--accent)' : 'var(--text-faint)',
            }}
          >
            {badge}
          </span>
        </div>
      </div>
      <p className="text-xs text-[var(--text-muted)] leading-relaxed">{desc}</p>
    </button>
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
