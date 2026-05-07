import { useMemo, useState } from 'react';
import { Check, ChevronDown, ChevronRight, Sparkles, AlertTriangle } from 'lucide-react';
import clsx from 'clsx';

import type { ArtifactCategory, ArtifactItem, Bundle, BuildSpec } from '../../lib/types';
import Card from '../ui/Card';
import { Toggle } from '../ui/Form';

interface P {
  spec: BuildSpec;
  update: <K extends keyof BuildSpec>(k: K, v: BuildSpec[K]) => void;
  catalog: ArtifactCategory[] | null;
  bundles: Bundle[];
}

export default function Step2Artifacts({ spec, update, catalog, bundles }: P) {
  const [openCats, setOpenCats] = useState<Record<string, boolean>>({});
  const selected = useMemo(() => new Set(spec.artifacts), [spec.artifacts]);

  const toggleCat = (c: string) => setOpenCats((s) => ({ ...s, [c]: !s[c] }));
  const toggleArtifact = (id: string) => {
    const next = new Set(spec.artifacts);
    if (next.has(id)) next.delete(id); else next.add(id);
    update('artifacts', Array.from(next));
  };
  const toggleAllInCategory = (cat: ArtifactCategory) => {
    const ids = cat.items.map((i) => i.id);
    const allOn = ids.every((id) => selected.has(id));
    const next = new Set(spec.artifacts);
    if (allOn) ids.forEach((id) => next.delete(id));
    else ids.forEach((id) => next.add(id));
    update('artifacts', Array.from(next));
  };
  const applyBundle = (b: Bundle) => {
    update('artifacts', [...new Set(b.artifacts)]);
    update('kapeTargets', [...new Set(b.kapeTargets)]);
  };
  const clearAll = () => { update('artifacts', []); update('kapeTargets', []); };

  return (
    <div className="space-y-6">
      <div>
        <div className="text-[10px] tracking-[0.2em] font-mono mb-1" style={{ color: 'var(--accent)' }}>STEP 2 of 6</div>
        <h2 className="text-2xl font-semibold tracking-tight">Artifact Selection</h2>
        <p className="text-sm text-[var(--text-muted)] mt-1">Pick a preset bundle or hand-pick artifacts. Live size/time totals update in the footer.</p>
      </div>

      {/* Bundle presets */}
      <Card title="Bundle Presets" desc="One-click activation of curated artifact sets — equivalent to KAPE's compound targets.">
        <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-3">
          {bundles.map((b) => (
            <button
              key={b.id}
              onClick={() => applyBundle(b)}
              className="text-left p-4 rounded-lg border transition-all hover:scale-[1.02]"
              style={bundleCardStyle(b.color)}
            >
              <div className="flex items-center gap-2 mb-1">
                <Sparkles className="w-4 h-4" style={{ color: 'var(--accent)' }} />
                <div className="font-semibold text-[var(--text-primary)]">{b.name}</div>
              </div>
              <div className="text-[11px] font-mono mb-2" style={{ color: 'var(--accent)' }}>{b.estimateLabel}</div>
              <div className="text-xs text-[var(--text-muted)] line-clamp-3">{b.description}</div>
            </button>
          ))}
        </div>
        <div className="mt-3 flex justify-end">
          <button onClick={clearAll} className="text-xs text-[var(--text-muted)] hover:text-[var(--danger)]">Clear all artifacts</button>
        </div>
      </Card>

      {/* VSS toggle */}
      <Card title="Volume Shadow Copy" desc="Take a VSS snapshot of C:\ before reading. Required for locked files (Registry hives, EVTX, MFT). Best practice: ON.">
        <Toggle
          label="Use VSS snapshot"
          desc="Adds 5-15s overhead but allows reading locked system files"
          value={spec.useVss}
          onChange={(v) => update('useVss', v)}
        />
        {!spec.useVss && hasLockedFileArtifacts(spec.artifacts) && (
          <div
            className="mt-3 p-3 rounded border text-xs flex items-start gap-2"
            style={{
              backgroundColor: 'var(--warning-bg)',
              borderColor: 'var(--warning)',
              color: 'var(--warning)',
            }}
          >
            <AlertTriangle className="w-4 h-4 mt-0.5 flex-shrink-0" />
            <div>
              <strong>VSS is OFF but you've selected artifacts that need it.</strong>{' '}
              Registry hives, EVTX, MFT, and Outlook OST/PST are held with
              exclusive locks at runtime — without VSS most files will fail
              with <code className="font-mono">os error 32</code> (sharing
              violation). Turn VSS back on unless you know the host can't
              take a snapshot.
            </div>
          </div>
        )}
      </Card>

      {/* Artifact tree */}
      {!catalog ? (
        <Card title="Loading catalog..." desc="Talking to backend at /api/artifacts">
          <div className="h-32 flex items-center justify-center">
            <div
              className="w-6 h-6 border-2 rounded-full animate-spin"
              style={{ borderColor: 'var(--accent)', borderTopColor: 'transparent' }}
            />
          </div>
        </Card>
      ) : (
        <div className="space-y-3">
          {catalog.map((cat) => {
            const ids = cat.items.map((i) => i.id);
            const allOn = ids.every((id) => selected.has(id));
            const someOn = ids.some((id) => selected.has(id));
            const isOpen = openCats[cat.category] ?? someOn;
            return (
              <div
                key={cat.category}
                className="rounded-lg overflow-hidden border"
                style={{
                  backgroundColor: 'var(--bg-surface)',
                  borderColor: 'var(--border-default)',
                }}
              >
                <div
                  className="flex items-center px-4 py-3 cursor-pointer transition-colors hover:bg-[var(--bg-elevated)]"
                  onClick={() => toggleCat(cat.category)}
                >
                  <button
                    onClick={(e) => { e.stopPropagation(); toggleAllInCategory(cat); }}
                    className="w-5 h-5 rounded flex items-center justify-center mr-3 flex-shrink-0 border"
                    style={{
                      backgroundColor: allOn ? 'var(--accent)' : someOn ? 'var(--accent-bg)' : 'transparent',
                      borderColor: allOn || someOn ? 'var(--accent)' : 'var(--border-strong)',
                    }}
                  >
                    {allOn && <Check className="w-3 h-3" style={{ color: 'var(--text-on-accent)' }} />}
                    {!allOn && someOn && <div className="w-2 h-2 rounded-sm" style={{ backgroundColor: 'var(--accent)' }} />}
                  </button>
                  <div className="flex-1">
                    <div className="font-medium text-[var(--text-primary)]">{cat.category}</div>
                    <div className="text-xs text-[var(--text-muted)]">
                      {cat.items.length} artifacts · {cat.items.filter((i) => selected.has(i.id)).length} selected
                    </div>
                  </div>
                  {isOpen ? <ChevronDown className="w-4 h-4 opacity-60" /> : <ChevronRight className="w-4 h-4 opacity-60" />}
                </div>
                {isOpen && (
                  <div className="border-t" style={{ borderColor: 'var(--border-subtle)' }}>
                    {cat.items.map((it, i) => (
                      <div
                        key={it.id}
                        style={i > 0 ? { borderTop: '1px solid var(--border-subtle)' } : {}}
                      >
                        <ArtifactRow
                          item={it}
                          selected={selected.has(it.id)}
                          onToggle={() => toggleArtifact(it.id)}
                          params={spec.artifactParams[it.id] ?? {}}
                          onParamChange={(key, value) => {
                            const next = { ...spec.artifactParams };
                            const cur = { ...(next[it.id] ?? {}) };
                            cur[key] = value;
                            next[it.id] = cur;
                            update('artifactParams', next);
                          }}
                        />
                      </div>
                    ))}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

function ArtifactRow({
  item, selected, onToggle, params, onParamChange,
}: {
  item: ArtifactItem;
  selected: boolean;
  onToggle: () => void;
  params: Record<string, string | number | boolean>;
  onParamChange: (key: string, value: string | number | boolean) => void;
}) {
  return (
    <div style={selected ? { backgroundColor: 'var(--accent-bg)' } : {}}>
      <button
        onClick={onToggle}
        className="w-full flex items-start gap-3 px-4 py-3 text-left transition-colors hover:bg-[var(--bg-elevated)]"
      >
        <div
          className="w-5 h-5 rounded border flex items-center justify-center mt-0.5 flex-shrink-0"
          style={{
            backgroundColor: selected ? 'var(--accent)' : 'transparent',
            borderColor: selected ? 'var(--accent)' : 'var(--border-strong)',
          }}
        >
          {selected && <Check className="w-3 h-3" style={{ color: 'var(--text-on-accent)' }} />}
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="font-medium text-[var(--text-primary)]">{item.name}</span>
            <span className="text-[10px] font-mono text-[var(--text-faint)]">{item.id}</span>
            {item.deps.map((d) => <DepBadge key={d} dep={d} />)}
            {item.params && item.params.length > 0 && selected && (
              <span
                className="text-[9px] font-bold px-1.5 py-0.5 rounded border tracking-wider"
                style={{
                  backgroundColor: 'var(--accent-2-bg)',
                  color: 'var(--accent-2)',
                  borderColor: 'var(--accent-2-border)',
                }}
              >CUSTOMIZABLE</span>
            )}
          </div>
          <p className="text-xs text-[var(--text-muted)] mt-0.5">{item.desc}</p>
        </div>
        <div className="text-right text-xs flex-shrink-0">
          <div className="font-mono" style={{ color: 'var(--accent)' }}>
            {item.sizeMb < 1024 ? `${item.sizeMb}MB` : `${(item.sizeMb / 1024).toFixed(1)}GB`}
          </div>
          <div className="text-[var(--text-faint)]">~{item.timeSec < 60 ? `${item.timeSec}s` : `${Math.round(item.timeSec / 60)}m`}</div>
        </div>
      </button>

      {selected && item.params && item.params.length > 0 && (
        <div
          className="px-4 py-3 ml-8 mr-4 mb-3 rounded border"
          style={{
            backgroundColor: 'var(--bg-page)',
            borderColor: 'var(--border-subtle)',
          }}
        >
          <div className="text-[10px] uppercase tracking-wider text-[var(--text-muted)] mb-2 font-semibold">
            Customize this artifact
          </div>
          <div className="grid md:grid-cols-2 gap-3">
            {item.params.map((p) => (
              <ParamControl
                key={p.key}
                param={p}
                value={params[p.key] ?? p.default}
                onChange={(v) => onParamChange(p.key, v)}
              />
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function ParamControl({
  param, value, onChange,
}: {
  param: import('../../lib/types').ArtifactParam;
  value: string | number | boolean;
  onChange: (v: string | number | boolean) => void;
}) {
  if (param.type === 'select' && param.options) {
    const opt = param.options.find((o) => o.value === value);
    return (
      <div>
        <label className="text-xs text-[var(--text-secondary)] block mb-1">{param.label}</label>
        <select
          value={String(value)}
          onChange={(e) => onChange(e.target.value)}
          className="w-full px-2 py-1.5 rounded text-sm border focus:outline-none focus:ring-2"
          style={{
            backgroundColor: 'var(--bg-input)',
            borderColor: 'var(--border-default)',
            color: 'var(--text-primary)',
          }}
        >
          {param.options.map((o) => (
            <option key={o.value} value={o.value}>{o.label}</option>
          ))}
        </select>
        {opt?.desc && (
          <p className="text-[11px] text-[var(--text-faint)] mt-1">
            {opt.desc}
            {opt.sizeMul && opt.sizeMul !== 1.0 && (
              <span className="ml-1 font-mono" style={{ color: 'var(--accent)' }}>
                (×{opt.sizeMul.toFixed(opt.sizeMul < 1 ? 2 : 1)} size)
              </span>
            )}
          </p>
        )}
      </div>
    );
  }
  if (param.type === 'number') {
    return (
      <div>
        <label className="text-xs text-[var(--text-secondary)] block mb-1">{param.label}</label>
        <input
          type="number"
          value={Number(value)}
          min={param.min}
          max={param.max}
          step={param.step ?? 1}
          onChange={(e) => onChange(Number(e.target.value))}
          className="w-full px-2 py-1.5 rounded text-sm border focus:outline-none focus:ring-2"
          style={{
            backgroundColor: 'var(--bg-input)',
            borderColor: 'var(--border-default)',
            color: 'var(--text-primary)',
          }}
        />
        {param.suffix && <span className="text-xs text-[var(--text-faint)] ml-1">{param.suffix}</span>}
      </div>
    );
  }
  if (param.type === 'boolean') {
    return (
      <label className="flex items-center gap-2 mt-3 cursor-pointer">
        <input
          type="checkbox"
          checked={Boolean(value)}
          onChange={(e) => onChange(e.target.checked)}
          className="rounded"
        />
        <span className="text-xs text-[var(--text-primary)]">{param.label}</span>
      </label>
    );
  }
  return null;
}

function DepBadge({ dep }: { dep: string }) {
  const palette = depPalette(dep);
  return (
    <span
      className="text-[9px] font-bold px-1.5 py-0.5 rounded border tracking-wider"
      style={palette}
    >
      {dep}
    </span>
  );
}

function depPalette(dep: string): React.CSSProperties {
  switch (dep) {
    case 'ADMIN':   return { backgroundColor: 'var(--warning-bg)', color: 'var(--warning)', borderColor: 'var(--warning)' };
    case 'VSS':     return { backgroundColor: 'var(--accent-bg)',  color: 'var(--accent)',  borderColor: 'var(--accent-border)' };
    case 'SYSMON':  return { backgroundColor: 'rgba(168, 85, 247, 0.12)', color: '#a855f7', borderColor: 'rgba(168, 85, 247, 0.4)' };
    case 'WINPMEM': return { backgroundColor: 'var(--danger-bg)',  color: 'var(--danger)',  borderColor: 'var(--danger)' };
    default:        return { backgroundColor: 'var(--bg-elevated)', color: 'var(--text-muted)', borderColor: 'var(--border-default)' };
  }
}

function bundleCardStyle(color: string): React.CSSProperties {
  // Each bundle uses a slightly different highlight for visual distinction.
  // In light theme these become subtle washes, in dark theme they glow.
  const tints: Record<string, string> = {
    emerald: 'rgba(16, 185, 129, 0.12)',
    blue:    'rgba(59, 130, 246, 0.10)',
    purple:  'rgba(168, 85, 247, 0.12)',
    amber:   'rgba(245, 158, 11, 0.12)',
  };
  const borders: Record<string, string> = {
    emerald: 'rgba(16, 185, 129, 0.40)',
    blue:    'rgba(59, 130, 246, 0.40)',
    purple:  'rgba(168, 85, 247, 0.40)',
    amber:   'rgba(245, 158, 11, 0.40)',
  };
  return {
    backgroundColor: tints[color] ?? 'var(--bg-surface)',
    borderColor: borders[color] ?? 'var(--border-default)',
  };
}

const LOCKED_FILE_ARTIFACTS = new Set([
  'registry.hives',
  'filesystem.mft',
  'eventlogs.security', 'eventlogs.system', 'eventlogs.application',
  'eventlogs.powershell', 'eventlogs.sysmon', 'eventlogs.defender',
  'eventlogs.rdp', 'eventlogs.taskscheduler', 'eventlogs.wmi', 'eventlogs.bits',
  'cloud.outlook',
]);

function hasLockedFileArtifacts(ids: string[]): boolean {
  return ids.some((id) => LOCKED_FILE_ARTIFACTS.has(id));
}
