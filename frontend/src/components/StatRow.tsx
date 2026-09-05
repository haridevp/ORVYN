interface Stat {
  label: string;
  value: React.ReactNode;
  note?: string;
  noteColor?: string;
}

export function StatRow({ stats }: { stats: Stat[] }) {
  return (
    <div className="grid grid-cols-2 gap-px overflow-hidden rounded-lg border border-[var(--border)] bg-[var(--border)] sm:grid-cols-3 lg:grid-cols-5">
      {stats.map((s) => (
        <div key={s.label} className="bg-[var(--surface-1)] px-5 py-4">
          <p className="text-xs font-medium text-[var(--text-muted)]">{s.label}</p>
          <p className="mt-1 flex items-baseline gap-2 text-2xl font-semibold tabular-nums text-[var(--text-primary)]">
            {s.value}
            {s.note && (
              <span className="text-xs font-medium" style={{ color: s.noteColor ?? "var(--text-muted)" }}>
                {s.note}
              </span>
            )}
          </p>
        </div>
      ))}
    </div>
  );
}
