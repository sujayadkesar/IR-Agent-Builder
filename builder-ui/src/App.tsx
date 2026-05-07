import { useEffect, useMemo, useState } from 'react';
import { ShieldCheck, ChevronRight, ChevronLeft, Activity, Sun, Moon } from 'lucide-react';
import clsx from 'clsx';

import { api } from './lib/api';
import type { ArtifactCategory, Bundle, BuildSpec, TargetPlatform } from './lib/types';
import { FALLBACK_BUNDLES } from './lib/bundles';
import { useTheme } from './lib/theme';

import Step1Target       from './components/steps/Step1Target';
import Step2Artifacts    from './components/steps/Step2Artifacts';
import Step3Upload       from './components/steps/Step3Upload';
import Step4Encryption   from './components/steps/Step4Encryption';
import Step5Performance  from './components/steps/Step5Performance';
import Step6Review       from './components/steps/Step6Review';

const STEPS = [
  { id: 1, label: 'Target',     desc: 'OS + naming' },
  { id: 2, label: 'Artifacts',  desc: 'What to collect' },
  { id: 3, label: 'Upload',     desc: 'AWS S3 / Local' },
  { id: 4, label: 'Encryption', desc: 'X509 / Password' },
  { id: 5, label: 'Performance',desc: 'CPU / format' },
  { id: 6, label: 'Build',      desc: 'Review & compile' },
] as const;

const DEFAULT_SPEC: BuildSpec = {
  siteCode: 'APAC-HYD',
  filenameTemplate: '%FQDN%-%TIMESTAMP%-%UUID%',
  uuidSuffix: true,
  targetPlatform: 'windows',
  artifacts: [],
  artifactParams: {},
  kapeTargets: [],
  useVss: true,
  upload: { kind: 'local', localPath: 'C:\\IR\\Output', prefixTemplate: '%SITE%/%FQDN%' },
  chunkUpload: { enabled: false, chunkSizeMb: 256, streamMode: false, lowDiskThresholdMb: 2048 },
  encryption: { scheme: 'x509' },
  requireAdmin: true,
  silent: true,
  deleteAfterUpload: true,
  cpuLimitPercent: 0,
  concurrency: 2,
  progressTimeoutSeconds: 3600,
  outputFormat: 'jsonl',
  maxCollectionSizeGb: 0,
};

export default function App() {
  const [step, setStep] = useState(1);
  const [spec, setSpec] = useState<BuildSpec>(DEFAULT_SPEC);
  const [catalog, setCatalog] = useState<ArtifactCategory[] | null>(null);
  const [bundles, setBundles] = useState<Bundle[]>(FALLBACK_BUNDLES);
  const [loadError, setLoadError] = useState<string | null>(null);

  useEffect(() => {
    const platform = spec.targetPlatform;
    Promise.all([api.artifacts(platform), api.bundles(platform)])
      .then(([cat, bun]) => { setCatalog(cat); setBundles(bun); })
      .catch((e) => setLoadError(String(e?.message || e)));
  }, [spec.targetPlatform]);

  const totals = useMemo(() => {
    if (!catalog) return { sizeMb: 0, timeSec: 0, count: 0 };
    let sizeMb = 0, timeSec = 0;
    const flat = catalog.flatMap((c) => c.items);
    for (const id of spec.artifacts) {
      const it = flat.find((x) => x.id === id);
      if (!it) continue;
      // Apply the cumulative size multiplier from any select-type params
      // whose chosen option declares a sizeMul. Only the first such option
      // for each param is multiplied (we don't compose all options).
      const params = spec.artifactParams[id] ?? {};
      let mul = 1.0;
      for (const p of it.params ?? []) {
        if (p.type !== 'select') continue;
        const chosen = params[p.key] ?? p.default;
        const opt = p.options?.find((o) => o.value === chosen);
        if (opt?.sizeMul) mul *= opt.sizeMul;
      }
      sizeMb += it.sizeMb * mul;
      timeSec += it.timeSec;
    }
    return { sizeMb, timeSec, count: spec.artifacts.length };
  }, [catalog, spec.artifacts, spec.artifactParams]);

  const update = <K extends keyof BuildSpec>(k: K, v: BuildSpec[K]) =>
    setSpec((s) => ({ ...s, [k]: v }));

  return (
    <div className="min-h-screen flex flex-col bg-[var(--bg-base)] text-[var(--text-primary)]">
      <Header />
      <Stepper current={step} onJump={setStep} />

      <main className="flex-1 max-w-7xl w-full mx-auto px-6 py-8">
        {loadError && (
          <div className="mb-6 p-4 rounded-lg border border-[var(--danger)]/40 bg-[var(--danger-bg)] text-[var(--danger)] text-sm">
            <strong>Backend not reachable:</strong> {loadError}
            <p className="mt-1 opacity-70">Start it with: <code className="mono">cd builder-server && npm start</code></p>
          </div>
        )}

        {step === 1 && <Step1Target  spec={spec} update={update} />}
        {step === 2 && <Step2Artifacts spec={spec} update={update} catalog={catalog} bundles={bundles} />}
        {step === 3 && <Step3Upload    spec={spec} update={update} />}
        {step === 4 && <Step4Encryption spec={spec} update={update} />}
        {step === 5 && <Step5Performance spec={spec} update={update} />}
        {step === 6 && <Step6Review     spec={spec} catalog={catalog} />}
      </main>

      <Footer step={step} setStep={setStep} totals={totals} />
    </div>
  );
}

function Header() {
  const { theme, toggle } = useTheme();
  return (
    <header
      className="border-b border-[var(--border-default)] sticky top-0 z-30 cyber-grid backdrop-blur"
      style={{ backgroundColor: 'var(--header-bg)' }}
    >
      <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div
            className="w-10 h-10 rounded-lg flex items-center justify-center"
            style={{
              background: 'linear-gradient(135deg, var(--accent-bg) 0%, transparent 100%)',
              border: '1px solid var(--accent-border)',
              boxShadow: 'var(--accent-glow)',
            }}
          >
            <ShieldCheck className="w-5 h-5" style={{ color: 'var(--accent)' }} />
          </div>
          <div>
            <h1 className="text-lg font-semibold tracking-tight">DFIR Agent Builder</h1>
            <p className="text-xs text-[var(--text-muted)]">
              Velociraptor-class triage collector compiler · GPO-ready · AWS S3
            </p>
          </div>
        </div>
        <div className="flex items-center gap-4">
          <ThemeToggle theme={theme} toggle={toggle} />
          <div className="flex items-center gap-2 text-xs text-[var(--text-muted)]">
            <Activity className="w-3.5 h-3.5 text-[var(--success)] animate-pulse" />
            <span>Backend: localhost:8787</span>
          </div>
        </div>
      </div>
    </header>
  );
}

function ThemeToggle({ theme, toggle }: { theme: 'dark' | 'light'; toggle: () => void }) {
  return (
    <button
      onClick={toggle}
      title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`}
      className="relative inline-flex items-center h-8 w-16 rounded-full border transition-all"
      style={{
        backgroundColor: theme === 'dark' ? 'var(--bg-elevated)' : 'var(--accent-bg)',
        borderColor: 'var(--border-default)',
      }}
    >
      <span
        className="absolute h-6 w-6 rounded-full transition-all flex items-center justify-center"
        style={{
          left: theme === 'dark' ? '4px' : 'calc(100% - 28px)',
          backgroundColor: 'var(--bg-surface-solid)',
          border: '1px solid var(--border-default)',
          boxShadow: '0 1px 4px rgba(0,0,0,0.15)',
        }}
      >
        {theme === 'dark'
          ? <Moon className="w-3.5 h-3.5" style={{ color: 'var(--accent)' }} />
          : <Sun  className="w-3.5 h-3.5" style={{ color: 'var(--accent-2)' }} />}
      </span>
    </button>
  );
}

function Stepper({ current, onJump }: { current: number; onJump: (n: number) => void }) {
  return (
    <nav className="border-b border-[var(--border-default)] bg-[var(--bg-page)]">
      <div className="max-w-7xl mx-auto px-6 py-3 flex items-center gap-1 overflow-x-auto">
        {STEPS.map((s, idx) => {
          const active = current === s.id;
          const done = current > s.id;
          return (
            <button
              key={s.id}
              onClick={() => onJump(s.id)}
              className="flex items-center gap-3 px-4 py-2 rounded-md text-sm transition-all whitespace-nowrap"
              style={
                active
                  ? {
                      backgroundColor: 'var(--accent-bg)',
                      color: 'var(--accent)',
                      border: '1px solid var(--accent-border)',
                      boxShadow: 'var(--accent-glow)',
                    }
                  : done
                  ? { color: 'var(--success)' }
                  : { color: 'var(--text-muted)' }
              }
            >
              <span
                className="w-6 h-6 rounded-full flex items-center justify-center text-[11px] font-bold"
                style={
                  active
                    ? { backgroundColor: 'var(--accent-bg)', color: 'var(--accent)', boxShadow: '0 0 0 2px var(--accent-border)' }
                    : done
                    ? { backgroundColor: 'var(--success-bg)', color: 'var(--success)' }
                    : { backgroundColor: 'var(--bg-elevated)', color: 'var(--text-muted)' }
                }
              >{s.id}</span>
              <span className="font-medium">{s.label}</span>
              <span className="hidden lg:inline text-[11px] opacity-70">{s.desc}</span>
              {idx < STEPS.length - 1 && <ChevronRight className="w-3.5 h-3.5 opacity-40 ml-2" />}
            </button>
          );
        })}
      </div>
    </nav>
  );
}

function Footer({ step, setStep, totals }: { step: number; setStep: (n: number) => void; totals: { sizeMb: number; timeSec: number; count: number } }) {
  const last = step === 6;
  return (
    <footer
      className="border-t border-[var(--border-default)] backdrop-blur sticky bottom-0"
      style={{ backgroundColor: 'var(--header-bg)' }}
    >
      <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between gap-4">
        <div className="flex items-center gap-6 text-sm">
          <Stat label="Artifacts"   value={String(totals.count)} />
          <Stat label="Est. size"   value={formatSize(totals.sizeMb)} />
          <Stat label="Est. time"   value={formatTime(totals.timeSec)} />
        </div>
        <div className="flex items-center gap-2">
          <button
            disabled={step === 1}
            onClick={() => setStep(step - 1)}
            className="btn-ghost px-4 py-2 rounded-md flex items-center gap-2"
          >
            <ChevronLeft className="w-4 h-4" /> Back
          </button>
          {!last ? (
            <button
              onClick={() => setStep(step + 1)}
              className="btn-primary px-5 py-2 rounded-md flex items-center gap-2 font-medium"
            >
              Next <ChevronRight className="w-4 h-4" />
            </button>
          ) : null}
        </div>
      </div>
    </footer>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <div className="text-[10px] uppercase tracking-wider text-[var(--text-muted)]">{label}</div>
      <div className="font-mono text-[var(--accent)] text-sm">{value}</div>
    </div>
  );
}

function formatSize(mb: number) {
  if (mb >= 1024) return `${(mb / 1024).toFixed(2)} GB`;
  return `${mb.toFixed(0)} MB`;
}
function formatTime(s: number) {
  if (s >= 3600) return `${(s / 3600).toFixed(1)} hr`;
  if (s >= 60) return `${Math.round(s / 60)} min`;
  return `${s} sec`;
}
