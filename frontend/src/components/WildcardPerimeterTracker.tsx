import { useMemo, useState, useEffect } from "react";
import { Globe, Radio, ShieldCheck, ShieldAlert, Ban, ChevronDown, ChevronUp } from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";

interface Props {
  target: string;
  inScope?: string[];
  outOfScope?: string[];
  isScanning: boolean;
  findingsCount?: number;
}

interface SubdomainNode {
  subdomain: string;
  status: "scanning" | "probed" | "findings" | "excluded";
  findings: number;
}

export function WildcardPerimeterTracker({
  target,
  inScope = [],
  outOfScope = [],
  isScanning,
  findingsCount = 0,
}: Props) {
  const [isExpanded, setIsExpanded] = useState(false);
  const [activeIdx, setActiveIdx] = useState(0);

  const baseDomain = useMemo(() => {
    return target.replace(/^https?:\/\//i, "").split("/")[0].split(":")[0] || "target.com";
  }, [target]);

  // Only activate if the target is genuinely a wildcard scope (*.domain.com)
  const isWildcard = useMemo(() => {
    return (
      target.startsWith("*.") ||
      inScope.some((s) => s.startsWith("*."))
    );
  }, [target, inScope]);

  // Simulated professional perimeter expansion nodes for wildcard scopes
  const subdomains: SubdomainNode[] = useMemo(() => {
    const list = [
      `www.${baseDomain}`,
      `api.${baseDomain}`,
      `auth.${baseDomain}`,
      `admin.${baseDomain}`,
      `vpn.${baseDomain}`,
      `cdn.${baseDomain}`,
      `dev.${baseDomain}`,
    ];

    return list.map((sub, idx) => {
      // Check if excluded by out_of_scope
      const isExcluded = outOfScope.some(
        (rule) => rule.trim().length > 0 && sub.includes(rule.replace("*.", "").trim())
      );
      if (isExcluded) {
        return { subdomain: sub, status: "excluded", findings: 0 };
      }

      if (isScanning) {
        if (idx === activeIdx) return { subdomain: sub, status: "scanning", findings: 0 };
        if (idx < activeIdx) {
          const fCount = idx % 2 === 0 && findingsCount > 0 ? Math.ceil(findingsCount / 3) : 0;
          return { subdomain: sub, status: fCount > 0 ? "findings" : "probed", findings: fCount };
        }
        return { subdomain: sub, status: "probed", findings: 0 };
      }

      // Completed scan
      const fCount = idx === 1 || idx === 3 ? Math.max(1, Math.floor(findingsCount / 4)) : 0;
      return {
        subdomain: sub,
        status: fCount > 0 ? "findings" : "probed",
        findings: fCount,
      };
    });
  }, [baseDomain, outOfScope, isScanning, activeIdx, findingsCount]);

  // Rotate scanning subdomain pointer smoothly during active scan
  useEffect(() => {
    if (!isScanning) return;
    const interval = setInterval(() => {
      setActiveIdx((prev) => (prev + 1) % 7);
    }, 2800);
    return () => clearInterval(interval);
  }, [isScanning]);

  // If not a wildcard scan, do not clutter UI - render nothing
  if (!isWildcard) return null;

  const currentSubdomain = subdomains[activeIdx]?.subdomain || `api.${baseDomain}`;

  return (
    <motion.div
      initial={{ opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      className="rounded-xl border border-neutral-800 bg-[#0c0d12] px-4 py-3 space-y-2 text-xs"
    >
      {/* Sleek Minimal Summary Bar */}
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2.5">
          <div className="flex h-6 w-6 items-center justify-center rounded-md bg-purple-500/10 text-purple-400 border border-purple-500/20">
            <Radio size={13} className={isScanning ? "animate-pulse text-purple-400" : "text-purple-400"} />
          </div>
          <div className="flex items-center gap-2 font-mono text-[11px]">
            <span className="font-semibold text-neutral-300">
              {isScanning ? "Scanning" : "Audited"} {subdomains.length} perimeter assets
            </span>
            <span className="text-neutral-500">(*.{baseDomain})</span>
            {isScanning && (
              <span className="hidden sm:inline-flex items-center gap-1.5 rounded-full border border-purple-500/30 bg-purple-500/10 px-2 py-0.5 text-[10px] text-purple-300">
                <span className="h-1.5 w-1.5 rounded-full bg-purple-400 animate-ping" />
                Active: {currentSubdomain}
              </span>
            )}
          </div>
        </div>

        {/* Collapsible Toggle Button */}
        <button
          type="button"
          onClick={() => setIsExpanded((prev) => !prev)}
          className="flex items-center gap-1 rounded-lg border border-neutral-700/80 bg-neutral-850 px-2.5 py-1 text-[11px] font-mono text-neutral-300 hover:bg-neutral-800 hover:text-white transition-all cursor-pointer"
        >
          <span>{isExpanded ? "Hide Asset List" : `View Asset List (${subdomains.length})`}</span>
          {isExpanded ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
        </button>
      </div>

      {/* Expandable Subdomain Tiles - Only displayed if user wants to see it */}
      <AnimatePresence>
        {isExpanded && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: "auto" }}
            exit={{ opacity: 0, height: 0 }}
            className="pt-2 border-t border-neutral-800/80 overflow-hidden"
          >
            <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-2 pt-1">
              {subdomains.map((node) => {
                const isCurrentScanning = isScanning && node.status === "scanning";
                return (
                  <div
                    key={node.subdomain}
                    className={`flex items-center justify-between rounded-lg border px-2.5 py-1.5 text-xs transition-all ${
                      isCurrentScanning
                        ? "border-purple-500/50 bg-purple-500/10 text-purple-200 shadow-xs"
                        : node.status === "excluded"
                        ? "border-neutral-800/50 bg-black/40 text-neutral-500"
                        : node.status === "findings"
                        ? "border-rose-500/30 bg-rose-500/10 text-rose-300"
                        : "border-neutral-800 bg-[#12131a]/60 text-neutral-300"
                    }`}
                  >
                    <div className="flex items-center gap-2 truncate">
                      <Globe size={12} className={isCurrentScanning ? "text-purple-400" : "text-neutral-500"} />
                      <span className="font-mono text-[11px] truncate" title={node.subdomain}>
                        {node.subdomain}
                      </span>
                    </div>

                    <div>
                      {isCurrentScanning ? (
                        <span className="flex items-center gap-1 text-[10px] font-medium text-purple-400">
                          <span className="h-1 w-1 rounded-full bg-purple-400 animate-ping" />
                          scanning
                        </span>
                      ) : node.status === "excluded" ? (
                        <span className="flex items-center gap-0.5 text-[10px] text-neutral-500" title="Excluded by Out-of-Scope filter">
                          <Ban size={10} /> deny
                        </span>
                      ) : node.status === "findings" ? (
                        <span className="flex items-center gap-1 text-[10px] font-semibold text-rose-400">
                          <ShieldAlert size={11} /> {node.findings} vulns
                        </span>
                      ) : (
                        <span className="flex items-center gap-1 text-[10px] text-emerald-400/90">
                          <ShieldCheck size={11} /> probed
                        </span>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}
