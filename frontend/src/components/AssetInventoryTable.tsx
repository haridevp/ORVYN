import { useState, useMemo } from "react";
import { Globe, Cpu, Layers, Server, Zap, Play, ShieldAlert, ShieldCheck } from "lucide-react";
import type { ScannerFinding } from "../types";

interface AssetRecord {
  id: string;
  project: string;
  type: "Web App" | "GraphQL API" | "REST API" | "Microservice" | "Endpoint";
  name: string;
  url: string;
  risks: { count: number; high: number; med: number; low: number; info: number };
  status: "Monitored" | "Vulnerable" | "Secure";
  pentesting: "DAST" | "AI Agent" | "Pentest now";
  lastScanned: string;
}

interface AssetInventoryProps {
  target: string;
  findings?: ScannerFinding[];
  onTriggerScan: (endpoint: string) => void;
}

export function AssetInventoryTable({
  target,
  findings = [],
  onTriggerScan,
}: AssetInventoryProps) {
  const [selectedAssets, setSelectedAssets] = useState<string[]>([]);
  const [filterType, setFilterType] = useState<string>("All");

  // Dynamically derive asset records from real target & findings
  const assets: AssetRecord[] = useMemo(() => {
    const records: AssetRecord[] = [];
    const rootUrl = target.startsWith("http") ? target : `http://${target}`;
    
    // Group findings by URI or endpoint
    const endpointMap: Record<string, ScannerFinding[]> = {};
    const rootFindings: ScannerFinding[] = [];

    findings.forEach((f) => {
      const ev = f.evidence || f.target;
      let path = "/";
      try {
        if (ev.startsWith("http://") || ev.startsWith("https://")) {
          const u = new URL(ev);
          path = u.pathname || "/";
        } else if (ev.startsWith("/")) {
          path = ev.split("?")[0];
        }
      } catch {
        path = "/";
      }

      if (path === "/" || path === "") {
        rootFindings.push(f);
      } else {
        if (!endpointMap[path]) endpointMap[path] = [];
        endpointMap[path].push(f);
      }
    });

    // Root Target Asset
    const rootHigh = rootFindings.filter((f) => f.severity === "critical" || f.severity === "high").length;
    const rootMed = rootFindings.filter((f) => f.severity === "medium").length;
    const rootLow = rootFindings.filter((f) => f.severity === "low").length;

    records.push({
      id: "root-asset",
      project: "Primary Web Target",
      type: "Web App",
      name: "/",
      url: `${rootUrl}/`,
      risks: {
        count: rootFindings.length,
        high: rootHigh,
        med: rootMed,
        low: rootLow,
        info: rootFindings.filter((f) => f.severity === "info").length,
      },
      status: rootFindings.length > 0 ? "Vulnerable" : "Secure",
      pentesting: "DAST",
      lastScanned: "Active Scan Session",
    });

    // Sub-endpoints discovered from real findings
    Object.entries(endpointMap).forEach(([path, list], idx) => {
      const high = list.filter((f) => f.severity === "critical" || f.severity === "high").length;
      const med = list.filter((f) => f.severity === "medium").length;
      const low = list.filter((f) => f.severity === "low").length;
      const isApi = path.includes("/api/") || path.includes("/v1/");
      const isGql = path.includes("graphql");

      records.push({
        id: `ep-${idx}`,
        project: isApi ? "API Service" : isGql ? "GraphQL Interface" : "Discovered Route",
        type: isGql ? "GraphQL API" : isApi ? "REST API" : "Endpoint",
        name: path,
        url: `${rootUrl}${path.startsWith("/") ? "" : "/"}${path}`,
        risks: {
          count: list.length,
          high,
          med,
          low,
          info: list.filter((f) => f.severity === "info").length,
        },
        status: list.length > 0 ? "Vulnerable" : "Secure",
        pentesting: "AI Agent",
        lastScanned: "Active Scan Session",
      });
    });

    return records;
  }, [target, findings]);

  function toggleAsset(id: string) {
    setSelectedAssets((prev) =>
      prev.includes(id) ? prev.filter((item) => item !== id) : [...prev, id]
    );
  }

  const filtered = filterType === "All" ? assets : assets.filter((a) => a.type === filterType);

  return (
    <div className="rounded-2xl border border-gray-800 bg-[#080c14]/90 shadow-2xl backdrop-blur-xl overflow-hidden">
      {/* Table Header Controls */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-gray-800/80 bg-gray-900/40 px-6 py-4">
        <div className="flex items-center gap-3">
          <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-blue-500/10 border border-blue-500/20 text-blue-400">
            <Layers size={18} />
          </div>
          <div>
            <h3 className="text-base font-bold text-white tracking-wide flex items-center gap-2">
              Attack Surface & Real Monitored Assets
              <span className="text-[11px] font-mono font-medium px-2 py-0.5 rounded-full bg-blue-950/80 border border-blue-700/50 text-blue-300">
                {filtered.length} Discovered Endpoint{filtered.length === 1 ? "" : "s"}
              </span>
            </h3>
            <p className="text-xs text-gray-400">
              Live inventory derived from target network probes and scanner engine findings.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          {["All", "REST API", "GraphQL API", "Web App", "Endpoint"].map((t) => (
            <button
              key={t}
              onClick={() => setFilterType(t)}
              className={`px-3 py-1 text-xs font-semibold rounded-lg transition-all ${
                filterType === t
                  ? "bg-blue-600 text-white shadow-md shadow-blue-600/30"
                  : "text-gray-400 hover:text-white bg-black/30 border border-gray-800"
              }`}
            >
              {t}
            </button>
          ))}
        </div>
      </div>

      {/* Responsive Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs">
          <thead>
            <tr className="border-b border-gray-800 bg-black/40 text-[11px] font-mono uppercase tracking-wider text-gray-400">
              <th className="py-3.5 pl-6 pr-3 w-10">
                <input
                  type="checkbox"
                  checked={selectedAssets.length === assets.length && assets.length > 0}
                  onChange={() =>
                    setSelectedAssets(selectedAssets.length === assets.length ? [] : assets.map((a) => a.id))
                  }
                  className="rounded border-gray-700 bg-gray-900 text-blue-600 focus:ring-0 cursor-pointer"
                />
              </th>
              <th className="px-4 py-3.5">Asset / Group</th>
              <th className="px-4 py-3.5">Type</th>
              <th className="px-4 py-3.5">Endpoint URI</th>
              <th className="px-4 py-3.5">Security Status</th>
              <th className="px-4 py-3.5">Pentest Engine</th>
              <th className="px-4 py-3.5">Findings Breakdown</th>
              <th className="px-4 py-3.5">Assessed</th>
              <th className="py-3.5 pl-4 pr-6 text-right">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800/50">
            {filtered.map((asset) => {
              const isChecked = selectedAssets.includes(asset.id);
              return (
                <tr
                  key={asset.id}
                  className={`transition-colors hover:bg-white/[0.03] ${isChecked ? "bg-blue-950/20" : ""}`}
                >
                  <td className="py-3.5 pl-6 pr-3">
                    <input
                      type="checkbox"
                      checked={isChecked}
                      onChange={() => toggleAsset(asset.id)}
                      className="rounded border-gray-700 bg-gray-900 text-blue-600 focus:ring-0 cursor-pointer"
                    />
                  </td>

                  <td className="px-4 py-3.5 font-medium text-gray-200">
                    <span className="rounded-md border border-gray-700/60 bg-black/40 px-2 py-1 font-mono text-[11px] text-gray-300">
                      {asset.project}
                    </span>
                  </td>

                  <td className="px-4 py-3.5">
                    <div className="flex items-center gap-1.5 font-medium text-gray-300">
                      {asset.type === "GraphQL API" && <Cpu size={14} className="text-cyan-400" />}
                      {asset.type === "REST API" && <Server size={14} className="text-purple-400" />}
                      {asset.type === "Web App" && <Globe size={14} className="text-blue-400" />}
                      {asset.type === "Endpoint" && <Layers size={14} className="text-amber-400" />}
                      <span>{asset.type}</span>
                    </div>
                  </td>

                  <td className="px-4 py-3.5 font-mono text-cyan-300">
                    <div className="flex items-center gap-1.5">
                      <span className="font-bold">{asset.name}</span>
                    </div>
                  </td>

                  <td className="px-4 py-3.5">
                    {asset.status === "Vulnerable" ? (
                      <span className="inline-flex items-center gap-1.5 rounded-full border border-rose-500/30 bg-rose-500/10 px-2.5 py-0.5 text-[10px] font-bold uppercase tracking-wider text-rose-400">
                        <ShieldAlert size={11} />
                        Vulnerable
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1.5 rounded-full border border-emerald-500/30 bg-emerald-500/10 px-2.5 py-0.5 text-[10px] font-bold uppercase tracking-wider text-emerald-400">
                        <ShieldCheck size={11} />
                        Secure
                      </span>
                    )}
                  </td>

                  <td className="px-4 py-3.5">
                    {asset.pentesting === "DAST" && (
                      <span className="rounded-md border border-amber-500/30 bg-amber-500/10 px-2 py-0.5 font-mono text-[10px] font-bold text-amber-300 uppercase">
                        DAST
                      </span>
                    )}
                    {asset.pentesting === "AI Agent" && (
                      <span className="rounded-md border border-purple-500/30 bg-purple-500/10 px-2 py-0.5 font-mono text-[10px] font-bold text-purple-300 uppercase flex items-center gap-1 w-fit">
                        <Zap size={10} /> AI Agent
                      </span>
                    )}
                  </td>

                  <td className="px-4 py-3.5">
                    {asset.risks.count > 0 ? (
                      <div className="flex items-center gap-1.5 font-mono text-[10px] font-bold">
                        {asset.risks.high > 0 && (
                          <span className="rounded bg-rose-500/20 border border-rose-500/40 px-1.5 py-0.5 text-rose-300">
                            H {asset.risks.high}
                          </span>
                        )}
                        {asset.risks.med > 0 && (
                          <span className="rounded bg-amber-500/20 border border-amber-500/40 px-1.5 py-0.5 text-amber-300">
                            M {asset.risks.med}
                          </span>
                        )}
                        {asset.risks.low > 0 && (
                          <span className="rounded bg-blue-500/20 border border-blue-500/40 px-1.5 py-0.5 text-blue-300">
                            L {asset.risks.low}
                          </span>
                        )}
                      </div>
                    ) : (
                      <span className="font-mono text-[11px] text-emerald-400">0 Threats</span>
                    )}
                  </td>

                  <td className="px-4 py-3.5 text-gray-400 font-mono text-[11px]">
                    {asset.lastScanned}
                  </td>

                  <td className="py-3.5 pl-4 pr-6 text-right">
                    <button
                      onClick={() => onTriggerScan(asset.url)}
                      className="inline-flex items-center gap-1 rounded-lg border border-blue-500/40 bg-blue-500/10 hover:bg-blue-600 px-2.5 py-1 text-[11px] font-semibold text-blue-300 hover:text-white transition-colors cursor-pointer"
                    >
                      <Play size={11} /> Scan
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
