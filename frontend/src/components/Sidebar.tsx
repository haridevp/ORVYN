interface NavItem {
  label: string;
  icon: React.ReactNode;
  active?: boolean;
  soon?: string;
}

function ShieldMark() {
  return (
    <svg width="22" height="22" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path
        d="M12 2 3 6v6c0 5 3.8 8.6 9 10 5.2-1.4 9-5 9-10V6l-9-4Z"
        fill="var(--series-blue)"
      />
      <path
        d="m9 12 2 2 4-4"
        stroke="var(--surface-sidebar)"
        strokeWidth="1.8"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

function Icon({ d }: { d: string }) {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" aria-hidden="true" className="shrink-0">
      <path d={d} stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

const ICONS = {
  grid: "M4 4h7v7H4zM13 4h7v7h-7zM4 13h7v7H4zM13 13h7v7h-7z",
  history: "M3 12a9 9 0 1 0 3-6.7M3 12V5m0 7h7M12 7v5l3 3",
  knowledge: "M4 5c2-1 5-1 8 0v14c-3-1-6-1-8 0V5ZM20 5c-2-1-5-1-8 0v14c3-1 6-1 8 0V5Z",
  settings:
    "M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6ZM4 12h2m12 0h2M12 4v2m0 12v2M6.3 6.3l1.4 1.4m8.6 8.6 1.4 1.4M17.7 6.3l-1.4 1.4M7.7 16.3l-1.4 1.4",
};

const NAV: NavItem[] = [
  { label: "Dashboard", icon: <Icon d={ICONS.grid} />, active: true },
  { label: "Scan History", icon: <Icon d={ICONS.history} />, soon: "Module 4" },
  { label: "Knowledge Base", icon: <Icon d={ICONS.knowledge} />, soon: "Module 3" },
  { label: "Settings", icon: <Icon d={ICONS.settings} />, soon: "Soon" },
];

export function Sidebar() {
  return (
    <aside className="hidden w-60 shrink-0 flex-col border-r border-[var(--border)] bg-[var(--surface-sidebar)] px-3 py-5 md:flex">
      <div className="flex items-center gap-2 px-2 pb-6">
        <ShieldMark />
        <div>
          <p className="text-sm font-semibold leading-tight">AI Pentest</p>
          <p className="text-xs leading-tight text-[var(--text-muted)]">Multi-Scanner</p>
        </div>
      </div>

      <nav className="flex flex-col gap-0.5">
        {NAV.map((item) => (
          <div
            key={item.label}
            aria-current={item.active ? "page" : undefined}
            className={`flex items-center justify-between rounded-md px-3 py-2 text-sm font-medium ${
              item.active
                ? "bg-[var(--series-blue-wash)] text-[var(--series-blue)]"
                : "text-[var(--text-muted)]"
            }`}
          >
            <span className="flex items-center gap-2.5">
              {item.icon}
              {item.label}
            </span>
            {item.soon && (
              <span className="rounded-full border border-[var(--border)] px-1.5 py-0.5 text-[10px] font-medium text-[var(--text-muted)]">
                {item.soon}
              </span>
            )}
          </div>
        ))}
      </nav>

      <div className="mt-auto rounded-lg border border-[var(--border)] px-3 py-3 text-xs text-[var(--text-muted)]">
        <p className="font-medium text-[var(--text-secondary)]">Module 2</p>
        <p className="mt-0.5">Multi-Scanner Integration &amp; Vulnerability Correlation</p>
      </div>
    </aside>
  );
}
