import { ReactNode } from 'react';

export default function Card({ title, desc, children }: { title: string; desc?: string; children: ReactNode }) {
  return (
    <section
      className="rounded-lg p-5 border"
      style={{
        backgroundColor: 'var(--bg-surface)',
        borderColor: 'var(--border-default)',
      }}
    >
      <header className="mb-4">
        <h3 className="text-base font-semibold tracking-tight text-[var(--text-primary)]">{title}</h3>
        {desc && <p className="text-xs text-[var(--text-muted)] mt-1">{desc}</p>}
      </header>
      {children}
    </section>
  );
}
