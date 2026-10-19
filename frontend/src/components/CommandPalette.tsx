import { useState, useEffect } from "react";
import {
  Search,
  Crosshair,
  AlertTriangle,
  Globe,
  BookOpen,
  Terminal,
  GitBranch,
  History,
  LayoutDashboard,
  X,
} from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";

interface CommandPaletteProps {
  isOpen: boolean;
  onClose: () => void;
  onNavigate: (tab: string) => void;
  onNewPentest: () => void;
}

export function CommandPalette({ isOpen, onClose, onNavigate, onNewPentest }: CommandPaletteProps) {
  const [query, setQuery] = useState("");

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        if (isOpen) {
          onClose();
        } else {
          // Trigger open if parent handles it
        }
      }
      if (e.key === "Escape" && isOpen) {
        onClose();
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  const actions = [
    { id: "pentests", label: "Launch New AI Pentest", icon: <Crosshair size={16} className="text-emerald-400" />, action: () => { onNewPentest(); onClose(); } },
    { id: "issues", label: "View Issues & RAG Verdicts", icon: <AlertTriangle size={16} className="text-amber-400" />, action: () => { onNavigate("issues"); onClose(); } },
    { id: "dashboard", label: "Dashboard & Executive Metrics", icon: <LayoutDashboard size={16} className="text-blue-400" />, action: () => { onNavigate("dashboard"); onClose(); } },
    { id: "domains", label: "Domains & Attack Surface", icon: <Globe size={16} className="text-cyan-400" />, action: () => { onNavigate("domains"); onClose(); } },
    { id: "knowledge", label: "Knowledge Base (5,000+ Chunks)", icon: <BookOpen size={16} className="text-purple-400" />, action: () => { onNavigate("knowledge"); onClose(); } },
    { id: "topology", label: "API Attack Graph (Topology)", icon: <GitBranch size={16} className="text-indigo-400" />, action: () => { onNavigate("topology"); onClose(); } },
    { id: "terminal", label: "Live Scanner Console Logs", icon: <Terminal size={16} className="text-slate-400" />, action: () => { onNavigate("terminal"); onClose(); } },
    { id: "history", label: "Scan History & Past Reports", icon: <History size={16} className="text-rose-400" />, action: () => { onNavigate("history"); onClose(); } },
  ];

  const filtered = actions.filter((a) => a.label.toLowerCase().includes(query.toLowerCase()));

  return (
    <AnimatePresence>
      <div className="fixed inset-0 z-50 flex items-start justify-center pt-24 px-4 bg-black/70 backdrop-blur-md">
        <motion.div
          initial={{ opacity: 0, scale: 0.95, y: -10 }}
          animate={{ opacity: 1, scale: 1, y: 0 }}
          exit={{ opacity: 0, scale: 0.95, y: -10 }}
          className="w-full max-w-xl overflow-hidden rounded-2xl border border-neutral-800 bg-[#0c0d12] shadow-2xl"
        >
          <div className="flex items-center gap-3 border-b border-neutral-800 px-4 py-3.5">
            <Search size={18} className="text-neutral-500" />
            <input
              type="text"
              autoFocus
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Type a command or search..."
              className="w-full bg-transparent text-sm text-neutral-100 placeholder-neutral-500 focus:outline-none font-sans"
            />
            <button
              onClick={onClose}
              className="rounded p-1 text-neutral-500 hover:text-neutral-300 hover:bg-neutral-800 transition-colors"
            >
              <X size={16} />
            </button>
          </div>

          <div className="max-h-80 overflow-y-auto p-2 space-y-1">
            <div className="px-3 py-1.5 text-[10px] font-mono uppercase tracking-wider text-neutral-500">
              Quick Navigation
            </div>
            {filtered.length === 0 ? (
              <div className="p-8 text-center text-xs text-neutral-500">
                No commands matching "{query}"
              </div>
            ) : (
              filtered.map((item) => (
                <button
                  key={item.id}
                  onClick={item.action}
                  className="flex w-full items-center justify-between rounded-xl px-3.5 py-2.5 text-xs text-neutral-300 hover:bg-neutral-800/80 hover:text-white transition-colors cursor-pointer text-left group"
                >
                  <div className="flex items-center gap-3">
                    <div className="p-1 rounded-lg bg-neutral-900 border border-neutral-800 group-hover:border-neutral-700">
                      {item.icon}
                    </div>
                    <span className="font-medium">{item.label}</span>
                  </div>
                  <span className="font-mono text-[10px] text-neutral-600 group-hover:text-neutral-400">Jump</span>
                </button>
              ))
            )}
          </div>

          <div className="border-t border-neutral-800/80 bg-neutral-950/60 px-4 py-2.5 flex items-center justify-between text-[11px] font-mono text-neutral-500">
            <span>Navigation Shortcuts</span>
            <div className="flex items-center gap-2">
              <span className="px-1.5 py-0.5 rounded bg-neutral-900 border border-neutral-800 text-[10px]">ESC to close</span>
              <span className="px-1.5 py-0.5 rounded bg-neutral-900 border border-neutral-800 text-[10px]">↵ to select</span>
            </div>
          </div>
        </motion.div>
      </div>
    </AnimatePresence>
  );
}
