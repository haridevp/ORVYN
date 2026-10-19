import { useState } from "react";
import {
  Globe,
  Plus,
  Search,
  CheckCircle2,
  AlertCircle,
  Play,
  X,
  Lock,
} from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";

export interface DomainItem {
  id: string;
  domain: string;
  verified: boolean;
  loginConfigured: boolean;
  issuesCount: number;
  lastTested: string;
}

interface DomainsViewProps {
  currentTarget?: string;
  onSelectDomainForScan: (domain: string) => void;
}

export function DomainsView({ currentTarget = "scanme.nmap.org", onSelectDomainForScan }: DomainsViewProps) {
  const [search, setSearch] = useState("");
  const [showAddModal, setShowAddModal] = useState(false);
  const [newDomainInput, setNewDomainInput] = useState("");
  const [verificationMethod, setVerificationMethod] = useState<"dns" | "file" | "meta">("dns");

  // Initial domain list populated from current target and defaults
  const [domains, setDomains] = useState<DomainItem[]>([
    {
      id: "d1",
      domain: currentTarget,
      verified: true,
      loginConfigured: false,
      issuesCount: 4,
      lastTested: "Just now",
    },
    {
      id: "d2",
      domain: "scanme.sh",
      verified: true,
      loginConfigured: false,
      issuesCount: 3,
      lastTested: "2 hours ago",
    },
    {
      id: "d3",
      domain: "api.target.internal",
      verified: false,
      loginConfigured: true,
      issuesCount: 1,
      lastTested: "Yesterday",
    },
  ]);

  const filtered = domains.filter((d) => d.domain.toLowerCase().includes(search.toLowerCase()));

  const handleAddDomain = () => {
    if (!newDomainInput.trim()) return;
    const clean = newDomainInput.trim().replace(/^https?:\/\//i, "").split("/")[0];
    const newEntry: DomainItem = {
      id: `d-${Date.now()}`,
      domain: clean,
      verified: true,
      loginConfigured: false,
      issuesCount: 0,
      lastTested: "Never",
    };
    setDomains((prev) => [newEntry, ...prev]);
    setNewDomainInput("");
    setShowAddModal(false);
  };

  const cleanDomain = newDomainInput.trim().replace(/^https?:\/\//i, "").split("/")[0] || "yourdomain.com";

  return (
    <div className="w-full space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold tracking-tight text-white font-sans">Domains & APIs</h1>
        <button
          onClick={() => setShowAddModal(true)}
          className="flex items-center gap-1.5 rounded-full bg-white hover:bg-neutral-200 px-4 py-2 text-xs font-bold text-black transition-all cursor-pointer shadow-md"
        >
          <Plus size={14} />
          <span>Add domain</span>
        </button>
      </div>

      {/* Search Bar (Matching Screenshot 3) */}
      <div className="flex items-center justify-between gap-4">
        <div className="relative w-72">
          <Search size={14} className="absolute left-3 top-2.5 text-neutral-500" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search domains... /"
            className="w-full rounded-xl border border-neutral-800 bg-[#0c0d12] pl-9 pr-3 py-1.5 text-xs text-neutral-200 placeholder-neutral-500 focus:border-neutral-600 focus:outline-none"
          />
        </div>
        <div className="text-xs font-mono text-neutral-500">
          {filtered.length} registered perimeter target{filtered.length !== 1 ? "s" : ""}
        </div>
      </div>

      {/* Table (Matching Screenshot 3) */}
      <div className="rounded-2xl border border-neutral-800/80 bg-[#0a0b10] overflow-hidden">
        <div className="grid grid-cols-12 gap-4 px-6 py-3 border-b border-neutral-800/80 text-[11px] font-mono text-neutral-500 uppercase tracking-wider">
          <div className="col-span-4">Domain</div>
          <div className="col-span-2">Verification</div>
          <div className="col-span-2">Login</div>
          <div className="col-span-2">Issues</div>
          <div className="col-span-2 text-right">Last tested</div>
        </div>

        {filtered.length === 0 ? (
          /* Empty State (Matching Screenshot 3) */
          <div className="flex flex-col items-center justify-center p-16 text-center">
            <div className="p-3 rounded-2xl bg-neutral-900/60 border border-neutral-800 text-neutral-500 mb-3">
              <Globe size={28} />
            </div>
            <h3 className="text-sm font-bold text-white">No domains yet</h3>
            <p className="text-xs text-neutral-400 mt-1 max-w-sm">
              Add a domain or API host to pentest it from the outside.
            </p>
            <button
              onClick={() => setShowAddModal(true)}
              className="mt-5 flex items-center gap-1.5 rounded-full bg-white hover:bg-neutral-200 px-5 py-2 text-xs font-bold text-black transition-colors cursor-pointer"
            >
              <Plus size={14} />
              <span>Add domain</span>
            </button>
          </div>
        ) : (
          <div className="divide-y divide-neutral-800/60">
            {filtered.map((item) => (
              <div
                key={item.id}
                className="grid grid-cols-12 gap-4 px-6 py-4 items-center text-xs hover:bg-neutral-900/30 transition-colors"
              >
                {/* Domain Column */}
                <div className="col-span-4 flex items-center gap-3">
                  <div className="p-1.5 rounded-lg bg-neutral-900 border border-neutral-800 text-cyan-400">
                    <Globe size={16} />
                  </div>
                  <div>
                    <span className="font-bold text-white font-mono">{item.domain}</span>
                    <div className="text-[10px] text-neutral-500 font-sans">External Web Perimeter</div>
                  </div>
                </div>

                {/* Verification Column */}
                <div className="col-span-2">
                  {item.verified ? (
                    <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full bg-emerald-500/10 border border-emerald-500/30 text-[10px] font-mono text-emerald-400">
                      <CheckCircle2 size={11} /> Verified
                    </span>
                  ) : (
                    <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full bg-amber-500/10 border border-amber-500/30 text-[10px] font-mono text-amber-400">
                      <AlertCircle size={11} /> Pending DNS
                    </span>
                  )}
                </div>

                {/* Login Column */}
                <div className="col-span-2 text-neutral-400 font-mono text-[11px]">
                  {item.loginConfigured ? (
                    <span className="text-purple-300 flex items-center gap-1">
                      <Lock size={11} /> Configured
                    </span>
                  ) : (
                    <span className="text-neutral-500">—</span>
                  )}
                </div>

                {/* Issues Column */}
                <div className="col-span-2 flex items-center gap-2">
                  {item.issuesCount > 0 ? (
                    <span className="px-2 py-0.5 rounded bg-rose-500/10 border border-rose-500/20 text-rose-300 font-mono text-[11px] font-bold">
                      {item.issuesCount} issue{item.issuesCount !== 1 ? "s" : ""}
                    </span>
                  ) : (
                    <span className="text-emerald-400 font-mono text-[11px]">0 issues</span>
                  )}
                </div>

                {/* Last Tested & Action */}
                <div className="col-span-2 flex items-center justify-end gap-3 text-right">
                  <span className="text-neutral-500 font-mono text-[11px]">{item.lastTested}</span>
                  <button
                    onClick={() => onSelectDomainForScan(item.domain)}
                    className="p-1.5 rounded-lg bg-neutral-900 border border-neutral-800 text-neutral-300 hover:text-white hover:border-neutral-600 transition-colors cursor-pointer"
                    title="Launch Pentest against this domain"
                  >
                    <Play size={12} className="fill-current" />
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Add Domain Modal (Matching Screenshot 5) */}
      <AnimatePresence>
        {showAddModal && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md">
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              className="w-full max-w-lg rounded-2xl border border-neutral-800 bg-[#0e0f16] shadow-2xl p-6 space-y-5"
            >
              <div className="flex items-start justify-between">
                <div>
                  <h3 className="text-base font-bold text-white">Add Domain & Target</h3>
                  <p className="text-xs text-neutral-400 mt-0.5">
                    Register a new host for authorized automated penetration testing
                  </p>
                </div>
                <button
                  onClick={() => setShowAddModal(false)}
                  className="text-neutral-500 hover:text-white"
                >
                  <X size={16} />
                </button>
              </div>

              <div>
                <label className="text-[11px] font-mono text-neutral-400 uppercase tracking-wider block mb-1.5">
                  Domain or API Hostname
                </label>
                <input
                  type="text"
                  value={newDomainInput}
                  onChange={(e) => setNewDomainInput(e.target.value)}
                  placeholder="app.mycompany.com"
                  className="w-full rounded-xl border border-neutral-700 bg-black/60 px-3.5 py-2 text-xs text-white placeholder-neutral-500 focus:border-white focus:outline-none font-mono"
                />
              </div>

              {/* Verification Info */}
              <div className="rounded-xl border border-neutral-800 bg-neutral-900/60 p-4 space-y-3 text-xs">
                <div className="font-semibold text-neutral-200">Verification Protocol</div>
                <div className="flex items-center gap-2">
                  {(["dns", "file", "meta"] as const).map((m) => (
                    <button
                      key={m}
                      onClick={() => setVerificationMethod(m)}
                      className={`px-3 py-1 rounded-lg text-xs font-mono transition-colors ${
                        verificationMethod === m
                          ? "bg-white text-black font-bold"
                          : "bg-neutral-800 text-neutral-400 hover:text-white"
                      }`}
                    >
                      {m === "dns" ? "DNS Record" : m === "file" ? "File Challenge" : "Meta Tag"}
                    </button>
                  ))}
                </div>

                <div className="text-[11px] font-mono text-neutral-400 space-y-1">
                  <div>TXT Record: <code className="text-neutral-200">_orvyn-verification.{cleanDomain}</code></div>
                  <div>Value: <code className="text-neutral-200">orvyn-verify-{cleanDomain.replace(/[^a-z0-9]/gi, "")}-token</code></div>
                </div>
              </div>

              <div className="flex items-center justify-end gap-3 pt-2 border-t border-neutral-800">
                <button
                  onClick={() => setShowAddModal(false)}
                  className="px-4 py-2 text-xs text-neutral-400 hover:text-white"
                >
                  Cancel
                </button>
                <button
                  onClick={handleAddDomain}
                  disabled={!newDomainInput.trim()}
                  className="rounded-full bg-white hover:bg-neutral-200 disabled:opacity-40 px-5 py-2 text-xs font-bold text-black transition-colors"
                >
                  Verify & Add Domain
                </button>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </div>
  );
}
