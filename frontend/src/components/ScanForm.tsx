import { useState } from "react";
import type { ScannerName } from "../types";
import { IconPlay } from "./Icons";

const ALL_SCANNERS: { id: ScannerName; label: string }[] = [
  { id: "nuclei", label: "Nuclei" },
  { id: "zap", label: "OWASP ZAP" },
  { id: "nikto", label: "Nikto" },
];

interface Props {
  onStart: (target: string, scanners: ScannerName[], profile: string) => void;
  disabled: boolean;
}

export function ScanForm({ onStart, disabled }: Props) {
  const [target, setTarget] = useState("");
  const [profile, setProfile] = useState("web");
  const [scanners, setScanners] = useState<ScannerName[]>(["nuclei", "zap", "nikto"]);

  function toggleScanner(id: ScannerName) {
    setScanners((prev) => (prev.includes(id) ? prev.filter((s) => s !== id) : [...prev, id]));
  }

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!target.trim() || scanners.length === 0) return;
    onStart(target.trim(), scanners, profile);
  }

  return (
    <form
      onSubmit={handleSubmit}
      className="rounded-xl border border-[var(--border)] bg-[var(--surface-1)] p-5 shadow-[var(--shadow-card)]"
    >
      <div className="flex flex-col gap-4 lg:flex-row lg:items-end">
        <label className="flex-1">
          <span className="mb-1.5 block text-xs font-medium text-[var(--text-muted)]">Target</span>
          <input
            type="text"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="scanme.nmap.org or http://localhost:3000"
            className="w-full rounded-md border border-[var(--border)] bg-[var(--surface-page)] px-3 py-2.5 text-sm text-[var(--text-primary)] outline-none transition-colors focus:border-[var(--series-blue)]"
            minLength={3}
            required
          />
        </label>

        <label>
          <span className="mb-1.5 block text-xs font-medium text-[var(--text-muted)]">Profile</span>
          <select
            value={profile}
            onChange={(e) => setProfile(e.target.value)}
            className="w-full rounded-md border border-[var(--border)] bg-[var(--surface-page)] px-3 py-2.5 text-sm text-[var(--text-primary)] outline-none lg:w-auto"
          >
            <option value="recon">Recon</option>
            <option value="web">Web</option>
            <option value="full">Full</option>
          </select>
        </label>

        <div>
          <span className="mb-1.5 block text-xs font-medium text-[var(--text-muted)]">Scanners</span>
          <div className="flex flex-wrap gap-1.5">
            {ALL_SCANNERS.map(({ id, label }) => {
              const checked = scanners.includes(id);
              return (
                <button
                  type="button"
                  key={id}
                  onClick={() => toggleScanner(id)}
                  aria-pressed={checked}
                  className={`rounded-md border px-3 py-2.5 text-sm font-medium transition-colors ${
                    checked
                      ? "border-[var(--series-blue)] bg-[var(--series-blue-wash)] text-[var(--series-blue)]"
                      : "border-[var(--border)] text-[var(--text-secondary)] hover:bg-[var(--surface-page)]"
                  }`}
                >
                  {label}
                </button>
              );
            })}
          </div>
        </div>

        <button
          type="submit"
          disabled={disabled || scanners.length === 0}
          className="flex items-center gap-1.5 rounded-md bg-[var(--series-blue)] px-5 py-2.5 text-sm font-semibold text-white transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-50"
        >
          {disabled ? (
            "Scanning..."
          ) : (
            <>
              <IconPlay size={13} />
              Start Scan
            </>
          )}
        </button>
      </div>
    </form>
  );
}
