import { ReactNode } from 'react';
import clsx from 'clsx';

export function Field({
  label, desc, required, children,
}: { label: string; desc?: string; required?: boolean; children: ReactNode }) {
  return (
    <label className="block">
      <div className="text-xs text-[var(--text-muted)] mb-1.5 flex items-center gap-1">
        {label}
        {required && <span className="text-[var(--danger)]">*</span>}
      </div>
      {children}
      {desc && <p className="text-[11px] text-[var(--text-faint)] mt-1">{desc}</p>}
    </label>
  );
}

export function Input({
  value, onChange, placeholder, type = 'text', className,
}: { value: string; onChange: (v: string) => void; placeholder?: string; type?: string; className?: string }) {
  return (
    <input
      type={type}
      value={value}
      onChange={(e) => onChange(e.target.value)}
      placeholder={placeholder}
      className={clsx(
        'w-full px-3 py-2 rounded-md border focus:outline-none focus:ring-2 transition-colors',
        className,
      )}
      style={{
        backgroundColor: 'var(--bg-input)',
        borderColor: 'var(--border-default)',
        color: 'var(--text-primary)',
      }}
      onFocus={(e) => {
        e.currentTarget.style.borderColor = 'var(--accent-border)';
        e.currentTarget.style.boxShadow = '0 0 0 3px var(--accent-bg)';
      }}
      onBlur={(e) => {
        e.currentTarget.style.borderColor = 'var(--border-default)';
        e.currentTarget.style.boxShadow = 'none';
      }}
    />
  );
}

export function Select({
  value, onChange, children,
}: { value: string; onChange: (v: string) => void; children: ReactNode }) {
  return (
    <select
      value={value}
      onChange={(e) => onChange(e.target.value)}
      className="w-full px-3 py-2 rounded-md border focus:outline-none focus:ring-2"
      style={{
        backgroundColor: 'var(--bg-input)',
        borderColor: 'var(--border-default)',
        color: 'var(--text-primary)',
      }}
    >
      {children}
    </select>
  );
}

export function Toggle({
  label, desc, value, onChange, className,
}: { label: string; desc?: string; value: boolean; onChange: (v: boolean) => void; className?: string }) {
  return (
    <div className={clsx('flex items-start gap-3 py-2', className)}>
      <button
        onClick={() => onChange(!value)}
        className="relative inline-flex h-5 w-9 flex-shrink-0 mt-0.5 rounded-full border transition-colors"
        style={{
          backgroundColor: value ? 'var(--accent-bg)' : 'var(--bg-elevated)',
          borderColor: value ? 'var(--accent-border)' : 'var(--border-default)',
        }}
        role="switch"
        aria-checked={value}
      >
        <span
          className={clsx(
            'inline-block h-3.5 w-3.5 rounded-full transition-transform shadow',
            value ? 'translate-x-5' : 'translate-x-0.5 mt-0.5',
          )}
          style={{
            backgroundColor: value ? 'var(--accent)' : 'var(--text-muted)',
          }}
        />
      </button>
      <div className="flex-1">
        <div className="text-sm text-[var(--text-primary)]">{label}</div>
        {desc && <p className="text-xs text-[var(--text-muted)] mt-0.5">{desc}</p>}
      </div>
    </div>
  );
}
