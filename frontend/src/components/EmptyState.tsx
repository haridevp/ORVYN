import { IconTarget } from "./Icons";

export function EmptyState() {
  return (
    <div className="flex flex-col items-center gap-3 rounded-xl border border-dashed border-[var(--border)] bg-[var(--surface-1)] px-6 py-16 text-center">
      <span className="flex h-12 w-12 items-center justify-center rounded-full bg-[var(--series-blue-wash)] text-[var(--series-blue)]">
        <IconTarget size={24} />
      </span>
      <div>
        <p className="text-sm font-medium text-[var(--text-primary)]">No scan yet</p>
        <p className="mt-1 max-w-sm text-sm text-[var(--text-muted)]">
          Enter a target above and pick your scanners to get a consolidated vulnerability report
          from Nuclei, OWASP ZAP, and Nikto in one place.
        </p>
      </div>
    </div>
  );
}
