interface Stat {
  label: string;
  value: React.ReactNode;
  note?: string;
  noteColor?: string;
  icon: React.ReactNode;
  iconColor?: string;
}

export function StatRow({ stats }: { stats: Stat[] }) {
  return (
    <div className="grid grid-cols-2 gap-px overflow-hidden rounded-xl border border-[var(--border)] bg-[var(--border)] sm:grid-cols-3 lg:grid-cols-5">
      {stats.map((s) => (
        <div
          key={s.label}
          className="group bg-[var(--surface-1)] px-5 py-4 transition-colors hover:bg-[var(--surface-page)]"
        >
          <div className="flex items-center gap-2">
            <span
              className="flex h-6 w-6 items-center justify-center rounded-md"
              style={{ color: s.iconColor ?? "var(--text-muted)", backgroundColor: `${s.iconColor ?? "var(--text-muted)"}1a` }}
            >
              {s.icon}
            </span>
            <p className="text-xs font-medium text-[var(--text-muted)]">{s.label}</p>
          </div>
          <p className="mt-2 flex items-baseline gap-2 text-2xl font-semibold tabular-nums text-[var(--text-primary)]">
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
