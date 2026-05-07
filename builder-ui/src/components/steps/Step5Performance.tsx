import type { BuildSpec } from '../../lib/types';
import Card from '../ui/Card';
import { Field, Input, Select } from '../ui/Form';

interface P { spec: BuildSpec; update: <K extends keyof BuildSpec>(k: K, v: BuildSpec[K]) => void; }

const DISK_LABEL: Record<string, string> = {
  windows: 'Cap on spinning disks; increase on fast NVMe endpoints.',
  linux: 'Increase on SSD/NVMe servers; decrease on VM attached storage.',
};

export default function Step5Performance({ spec, update }: P) {
  return (
    <div className="space-y-6">
      <div>
        <div className="text-[10px] tracking-[0.2em] font-mono mb-1" style={{ color: 'var(--accent)' }}>STEP 5 of 6</div>
        <h2 className="text-2xl font-semibold tracking-tight">Performance Tuning</h2>
        <p className="text-sm text-[var(--text-muted)] mt-1">Resource caps for live production endpoints. Defaults are safe.</p>
      </div>

      <Card title="CPU Limit" desc="Cap CPU usage during collection. 0 = unlimited (default for IR triage). Use 30-50% on customer-facing servers.">
        <div className="flex items-center gap-4">
          <input
            type="range"
            min={0}
            max={100}
            step={5}
            value={spec.cpuLimitPercent}
            onChange={(e) => update('cpuLimitPercent', Number(e.target.value))}
            className="flex-1"
            style={{ accentColor: 'var(--accent)' }}
          />
          <div className="font-mono w-16 text-right" style={{ color: 'var(--accent)' }}>
            {spec.cpuLimitPercent === 0 ? '∞' : `${spec.cpuLimitPercent}%`}
          </div>
        </div>
      </Card>

      <div className="grid md:grid-cols-2 gap-6">
        <Card title="Concurrency" desc={`Parallel artifact collectors. ${DISK_LABEL[spec.targetPlatform] ?? DISK_LABEL.windows}`}>
          <Field label="Workers">
            <Select value={String(spec.concurrency)} onChange={(v) => update('concurrency', Number(v))}>
              {[1, 2, 3, 4, 6, 8].map((n) => <option key={n} value={n}>{n}</option>)}
            </Select>
          </Field>
        </Card>

        <Card title="Output Format" desc="JSONL = one JSON row per line (default, structured). CSV = legacy analysis tools.">
          <Field label="Format">
            <Select value={spec.outputFormat} onChange={(v) => update('outputFormat', v as 'jsonl' | 'csv')}>
              <option value="jsonl">JSONL</option>
              <option value="csv">CSV</option>
            </Select>
          </Field>
        </Card>
      </div>

      <div className="grid md:grid-cols-2 gap-6">
        <Card title="Progress Timeout" desc="Kill stalled artifact collectors after this many seconds.">
          <Field label="Seconds">
            <Input type="number" value={String(spec.progressTimeoutSeconds)} onChange={(v) => update('progressTimeoutSeconds', Number(v) || 3600)} />
          </Field>
        </Card>

        <Card title="Max Collection Size (GB)" desc="0 = unlimited. Set a cap to prevent runaway memory dumps from filling disk.">
          <Field label="GB">
            <Input type="number" value={String(spec.maxCollectionSizeGb)} onChange={(v) => update('maxCollectionSizeGb', Number(v) || 0)} />
          </Field>
        </Card>
      </div>
    </div>
  );
}
