import { useState } from "react";
import {
  BookOpen,
  Plus,
  Search,
  Sparkles,
  X,
} from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";

interface KnowledgeItem {
  id: string;
  title: string;
  scope: string;
  type: string;
  summary: string;
  category: "internal" | "custom" | "connected";
  updated: string;
}

const PRELOADED_CHUNKS: KnowledgeItem[] = [
  {
    id: "chunk-owasp-a01",
    title: "OWASP A01:2025 - Broken Access Control & BOLA Enforcement",
    scope: "Web Application / API",
    type: "Vector Embedding (384-dim)",
    summary: "Validation criteria for IDOR, horizontal privilege escalation, and missing functional-level access controls.",
    category: "internal",
    updated: "Active Database",
  },
  {
    id: "chunk-owasp-a02",
    title: "OWASP A02:2025 - Cryptographic Failures & Deprecated TLS",
    scope: "SSL/TLS & Transit",
    type: "Vector Embedding (384-dim)",
    summary: "Judicial verification for TLS 1.0/1.1 deprecation (RFC 8996), weak CBC ciphers, and missing HSTS security directives.",
    category: "internal",
    updated: "Active Database",
  },
  {
    id: "chunk-owasp-a03",
    title: "OWASP A03:2025 - Injection Flaws (SQLi, Command Injection, LDAP)",
    scope: "Data Input / SQL",
    type: "Vector Embedding (384-dim)",
    summary: "Pattern detection and secondary verification rules for blind SQLi, time-based delays, and database syntax leakage.",
    category: "internal",
    updated: "Active Database",
  },
  {
    id: "chunk-cwe-89",
    title: "CWE-89: Improper Neutralization of Special Elements used in an SQL Command",
    scope: "CWE Top 25:2024",
    type: "Benchmark Rule",
    summary: "Mitre CWE definition and remediation guidance requiring parameterized prepared statements.",
    category: "internal",
    updated: "Active Database",
  },
  {
    id: "chunk-cwe-79",
    title: "CWE-79: Improper Neutralization of Input During Web Page Generation (XSS)",
    scope: "CWE Top 25:2024",
    type: "Benchmark Rule",
    summary: "Reflected, stored, and DOM-based cross-site scripting attack surface analysis and context-aware encoding rules.",
    category: "internal",
    updated: "Active Database",
  },
  {
    id: "chunk-cve-log4j",
    title: "CVE-2021-44228: Apache Log4j2 JNDI Remote Code Execution (Log4Shell)",
    scope: "Critical CVE Benchmark",
    type: "CVE Benchmark",
    summary: "Payload signatures and Out-of-band verification criteria for JNDI LDAP lookup strings.",
    category: "internal",
    updated: "Active Database",
  },
  {
    id: "chunk-cve-path-traversal",
    title: "CVE-2021-41773: Apache HTTP Server Path Traversal & File Disclosure",
    scope: "Web Server / HTTP",
    type: "CVE Benchmark",
    summary: "Verification heuristics for URL-encoded dot-dot-slash (%2e%2e/) directory traversal against mapped document roots.",
    category: "internal",
    updated: "Active Database",
  },
  {
    id: "chunk-cve-heartbleed",
    title: "CVE-2014-0160: OpenSSL TLS Heartbeat Information Disclosure (Heartbleed)",
    scope: "Cryptographic / TLS",
    type: "CVE Benchmark",
    summary: "Memory leakage inspection pattern verifying length field bound mismatch in TLS heartbeat requests.",
    category: "internal",
    updated: "Active Database",
  },
];

export function KnowledgeView() {
  const [activeTab, setActiveTab] = useState<"internal" | "custom" | "connected">("internal");
  const [search, setSearch] = useState("");
  const [scopeFilter, setScopeFilter] = useState("All");
  const [showAddModal, setShowAddModal] = useState(false);

  // Custom knowledge entries created by user
  const [customEntries, setCustomEntries] = useState<KnowledgeItem[]>([]);
  const [customTitle, setCustomTitle] = useState("");
  const [customScope, setCustomScope] = useState("");
  const [customSummary, setCustomSummary] = useState("");

  const allItems = [...PRELOADED_CHUNKS, ...customEntries];

  const filtered = allItems.filter((item) => {
    if (activeTab === "custom" && item.category !== "custom") return false;
    if (activeTab === "internal" && item.category !== "internal") return false;
    if (activeTab === "connected" && item.category !== "connected") return false;

    const matchesSearch =
      item.title.toLowerCase().includes(search.toLowerCase()) ||
      item.summary.toLowerCase().includes(search.toLowerCase()) ||
      item.scope.toLowerCase().includes(search.toLowerCase());

    const matchesScope = scopeFilter === "All" || item.scope.toLowerCase().includes(scopeFilter.toLowerCase());

    return matchesSearch && matchesScope;
  });

  const handleAddCustom = () => {
    if (!customTitle.trim()) return;
    const newItem: KnowledgeItem = {
      id: `custom-${Date.now()}`,
      title: customTitle.trim(),
      scope: customScope.trim() || "Application Context",
      type: "Custom Business Rule",
      summary: customSummary.trim() || "User-defined testing boundary and context rule.",
      category: "custom",
      updated: "Just now",
    };
    setCustomEntries((prev) => [newItem, ...prev]);
    setCustomTitle("");
    setCustomScope("");
    setCustomSummary("");
    setShowAddModal(false);
    setActiveTab("custom");
  };

  return (
    <div className="w-full space-y-6">
      {/* Header (Matching Screenshot 4) */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white font-sans">Knowledge</h1>
          <p className="text-xs text-neutral-400 mt-1">
            ORVYN learns your apps, context, and business logic across runs to deliver smarter results.
          </p>
        </div>
        <button
          onClick={() => setShowAddModal(true)}
          className="flex items-center gap-1.5 rounded-full bg-white hover:bg-neutral-200 px-4 py-2 text-xs font-bold text-black transition-all cursor-pointer shadow-md"
        >
          <Plus size={14} />
          <span>Add knowledge</span>
        </button>
      </div>

      {/* Tabs (Matching Screenshot 4) */}
      <div className="flex items-center gap-6 border-b border-neutral-800 text-xs">
        {[
          { id: "custom" as const, label: "Custom", count: customEntries.length },
          { id: "internal" as const, label: "Internal (ChromaDB)", count: "5,000+ Chunks" },
          { id: "connected" as const, label: "Connected sources", count: 7 },
        ].map((tab) => {
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`pb-3 font-medium transition-colors cursor-pointer flex items-center gap-2 ${
                isActive
                  ? "border-b-2 border-white text-white font-semibold"
                  : "text-neutral-500 hover:text-neutral-300"
              }`}
            >
              <span>{tab.label}</span>
              <span className={`text-[11px] font-mono px-1.5 py-0.2 rounded ${
                isActive ? "bg-neutral-800 text-neutral-200" : "bg-neutral-900 text-neutral-600"
              }`}>
                {tab.count}
              </span>
            </button>
          );
        })}
      </div>

      {/* Search and Scope Filter (Matching Screenshot 4) */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="relative w-72">
            <Search size={14} className="absolute left-3 top-2.5 text-neutral-500" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search knowledge... /"
              className="w-full rounded-xl border border-neutral-800 bg-[#0c0d12] pl-9 pr-3 py-1.5 text-xs text-neutral-200 placeholder-neutral-500 focus:border-neutral-600 focus:outline-none"
            />
          </div>

          <select
            value={scopeFilter}
            onChange={(e) => setScopeFilter(e.target.value)}
            className="rounded-xl border border-neutral-800 bg-[#0c0d12] px-3 py-1.5 text-xs text-neutral-300 focus:border-neutral-600 focus:outline-none cursor-pointer"
          >
            <option value="All">All scopes</option>
            <option value="OWASP">OWASP Top 10</option>
            <option value="CWE">CWE Standards</option>
            <option value="CVE">CVE Benchmarks</option>
            <option value="SSL">SSL / TLS Transit</option>
          </select>
        </div>

        <div className="text-xs font-mono text-purple-400 bg-purple-950/30 border border-purple-800/40 px-3 py-1 rounded-full flex items-center gap-1.5">
          <Sparkles size={12} />
          <span>Vector Index: ChromaDB Persistent Collection</span>
        </div>
      </div>

      {/* Table (Matching Screenshot 4) */}
      <div className="rounded-2xl border border-neutral-800/80 bg-[#0a0b10] overflow-hidden">
        <div className="grid grid-cols-12 gap-4 px-6 py-3 border-b border-neutral-800/80 text-[11px] font-mono text-neutral-500 uppercase tracking-wider">
          <div className="col-span-6">Knowledge / Vector Concept</div>
          <div className="col-span-2">Scope</div>
          <div className="col-span-2">Type</div>
          <div className="col-span-2 text-right">Updated</div>
        </div>

        {filtered.length === 0 ? (
          /* Empty State (Matching Screenshot 4) */
          <div className="flex flex-col items-center justify-center p-16 text-center">
            <div className="p-3 rounded-2xl bg-neutral-900/60 border border-neutral-800 text-neutral-500 mb-3">
              <BookOpen size={28} />
            </div>
            <h3 className="text-sm font-bold text-white">No custom knowledge</h3>
            <p className="text-xs text-neutral-400 mt-1 max-w-sm">
              Add business logic, critical assets, testing rules, or accepted risks so every run starts with your context.
            </p>
            <button
              onClick={() => setShowAddModal(true)}
              className="mt-5 flex items-center gap-1.5 rounded-full bg-white hover:bg-neutral-200 px-5 py-2 text-xs font-bold text-black transition-colors cursor-pointer"
            >
              <Plus size={14} />
              <span>Add knowledge</span>
            </button>
          </div>
        ) : (
          <div className="divide-y divide-neutral-800/60">
            {filtered.map((item) => (
              <div
                key={item.id}
                className="grid grid-cols-12 gap-4 px-6 py-4 items-center text-xs hover:bg-neutral-900/30 transition-colors"
              >
                {/* Title & Summary */}
                <div className="col-span-6 pr-4">
                  <div className="font-bold text-white tracking-wide">{item.title}</div>
                  <div className="text-[11px] text-neutral-400 mt-0.5 leading-relaxed">{item.summary}</div>
                </div>

                {/* Scope */}
                <div className="col-span-2">
                  <span className="px-2 py-0.5 rounded-md bg-neutral-900 border border-neutral-800 text-[11px] font-mono text-neutral-300">
                    {item.scope}
                  </span>
                </div>

                {/* Type */}
                <div className="col-span-2">
                  <span className="text-[11px] font-mono text-purple-300">
                    {item.type}
                  </span>
                </div>

                {/* Updated */}
                <div className="col-span-2 text-right font-mono text-[11px] text-neutral-500">
                  {item.updated}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Add Knowledge Modal */}
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
                  <h3 className="text-base font-bold text-white">Add Custom Knowledge</h3>
                  <p className="text-xs text-neutral-400 mt-0.5">
                    Inject business context, accepted risks, or authentication secrets into RAG Validator
                  </p>
                </div>
                <button
                  onClick={() => setShowAddModal(false)}
                  className="text-neutral-500 hover:text-white"
                >
                  <X size={16} />
                </button>
              </div>

              <div className="space-y-4 text-xs font-mono">
                <div>
                  <label className="text-neutral-400 block mb-1 uppercase tracking-wider text-[10px]">Title</label>
                  <input
                    type="text"
                    value={customTitle}
                    onChange={(e) => setCustomTitle(e.target.value)}
                    placeholder="e.g. Legacy Endpoint Rate-Limiting Policy"
                    className="w-full rounded-xl border border-neutral-700 bg-black/60 px-3 py-2 text-white focus:border-white focus:outline-none"
                  />
                </div>

                <div>
                  <label className="text-neutral-400 block mb-1 uppercase tracking-wider text-[10px]">Scope</label>
                  <input
                    type="text"
                    value={customScope}
                    onChange={(e) => setCustomScope(e.target.value)}
                    placeholder="e.g. /api/v2/* or Auth Service"
                    className="w-full rounded-xl border border-neutral-700 bg-black/60 px-3 py-2 text-white focus:border-white focus:outline-none"
                  />
                </div>

                <div>
                  <label className="text-neutral-400 block mb-1 uppercase tracking-wider text-[10px]">Context / Rule Description</label>
                  <textarea
                    rows={4}
                    value={customSummary}
                    onChange={(e) => setCustomSummary(e.target.value)}
                    placeholder="Specify acceptable status codes, bypass exceptions, or specific business constraints..."
                    className="w-full rounded-xl border border-neutral-700 bg-black/60 px-3 py-2 text-white focus:border-white focus:outline-none font-sans"
                  />
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
                  onClick={handleAddCustom}
                  disabled={!customTitle.trim()}
                  className="rounded-full bg-white hover:bg-neutral-200 disabled:opacity-40 px-5 py-2 text-xs font-bold text-black transition-colors"
                >
                  Save Knowledge
                </button>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </div>
  );
}
