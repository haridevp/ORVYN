import { useState } from "react";
import type { ScannerName } from "../types";

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
      className="rounded-lg border border-[var(--border)] bg-[var(--surface-1)] p-5"
    >
      <div className="flex flex-col gap-4 sm:flex-row sm:items-end">
        <label className="flex-1">
          <span className="mb-1 block text-sm font-medium text-[var(--text-secondary)]">
            Target
          </span>
          <input
            type="text"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="scanme.nmap.org or http://localhost:3000"
            className="w-full rounded-md border border-[var(--border)] bg-transparent px-3 py-2 text-sm text-[var(--text-primary)] outline-none focus:border-[var(--series-blue)]"
            minLength={3}
            required
          />
        </label>

        <label>
          <span className="mb-1 block text-sm font-medium text-[var(--text-secondary)]">
            Profile
          </span>
          <select
            value={profile}
            onChange={(e) => setProfile(e.target.value)}
            className="rounded-md border border-[var(--border)] bg-transparent px-3 py-2 text-sm text-[var(--text-primary)] outline-none"
          >
            <option value="recon">Recon</option>
            <option value="web">Web</option>
            <option value="full">Full</option>
          </select>
        </label>

        <button
          type="submit"
          disabled={disabled || scanners.length === 0}
          className="rounded-md bg-[var(--series-blue)] px-4 py-2 text-sm font-medium text-white disabled:opacity-50"
        >
          {disabled ? "Scanning..." : "Start Scan"}
        </button>
      </div>

      <div className="mt-4">
        <span className="mb-1.5 block text-sm font-medium text-[var(--text-secondary)]">
          Scanners
        </span>
        <div className="flex flex-wrap gap-3">
          {ALL_SCANNERS.map(({ id, label }) => (
            <label
              key={id}
              className="flex items-center gap-2 rounded-md border border-[var(--border)] px-3 py-1.5 text-sm"
            >
              <input
                type="checkbox"
                checked={scanners.includes(id)}
                onChange={() => toggleScanner(id)}
              />
              {label}
            </label>
          ))}
        </div>
      </div>
    </form>
  );
}
