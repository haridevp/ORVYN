import { motion } from "framer-motion";
import {
  LayoutDashboard,
  GitBranch,
  ShieldAlert,
  Terminal,
  Cpu,
  Shield,
  Sparkles,
  LogOut,
  UserCheck,
} from "lucide-react";

export type NavTab = "overview" | "topology" | "findings" | "terminal" | "scanners";

interface SidebarProps {
  activeTab: NavTab;
  setActiveTab: (tab: NavTab) => void;
  threatCount?: number;
  logsCount?: number;
  user?: { username: string; role: string } | null;
  onLogout?: () => void;
}

export function Sidebar({
  activeTab,
  setActiveTab,
  threatCount = 0,
  logsCount = 0,
  user,
  onLogout,
}: SidebarProps) {
  const navItems = [
    {
      id: "overview" as NavTab,
      label: "Overview & ASM",
      icon: <LayoutDashboard size={18} />,
    },
    {
      id: "topology" as NavTab,
      label: "API Attack Graph",
      icon: <GitBranch size={18} />,
      badge: "Escape",
    },
    {
      id: "findings" as NavTab,
      label: "Threats & Findings",
      icon: <ShieldAlert size={18} />,
      count: threatCount,
    },
    {
      id: "terminal" as NavTab,
      label: "Live Console",
      icon: <Terminal size={18} />,
      count: logsCount,
      pulse: true,
    },
    {
      id: "scanners" as NavTab,
      label: "Engines Cluster",
      icon: <Cpu size={18} />,
      badge: "3 Active",
    },
  ];

  return (
    <motion.aside
      initial={{ x: -200, opacity: 0 }}
      animate={{ x: 0, opacity: 1 }}
      className="hidden w-64 shrink-0 flex-col glass-sidebar px-4 py-6 md:flex relative z-30 shadow-2xl border-r border-gray-800/80 bg-[#080c14]/95"
    >
      {/* Brand Header */}
      <div className="flex items-center gap-3 px-2 pb-8 border-b border-gray-800/60">
        <div className="p-2 bg-gradient-to-tr from-rose-500/20 via-blue-500/20 to-purple-500/20 rounded-xl border border-blue-500/30 shadow-[0_0_20px_rgba(59,130,246,0.3)]">
          <Shield className="text-cyan-400" size={24} />
        </div>
        <div>
          <div className="flex items-center gap-1.5">
            <p className="text-sm font-black tracking-wider text-white uppercase font-mono">Aegis AI</p>
            <span className="text-[9px] font-bold text-rose-400 bg-rose-950/80 border border-rose-800/60 px-1 rounded">SOC</span>
          </div>
          <p className="text-[11px] tracking-wider text-gray-400 font-medium">Auto-Penetration Testing</p>
        </div>
      </div>

      {/* Nav List */}
      <nav className="flex flex-col gap-1.5 mt-6">
        <div className="px-3 pb-2 text-[10px] font-bold font-mono uppercase tracking-widest text-gray-500">
          Security Operations
        </div>
        {navItems.map((item) => {
          const isActive = activeTab === item.id;
          return (
            <motion.button
              key={item.id}
              onClick={() => setActiveTab(item.id)}
              whileHover={{ x: 4 }}
              className={`flex items-center justify-between rounded-xl px-3 py-2.5 text-xs font-semibold transition-all text-left cursor-pointer ${
                isActive
                  ? "bg-gradient-to-r from-blue-600/30 via-indigo-600/20 to-purple-600/10 text-white border border-blue-500/40 shadow-lg shadow-blue-500/10 font-bold"
                  : "text-gray-400 hover:text-white hover:bg-white/[0.04]"
              }`}
            >
              <span className="flex items-center gap-3">
                <span className={isActive ? "text-cyan-400" : "text-gray-500"}>{item.icon}</span>
                {item.label}
              </span>

              {item.badge && (
                <span className="rounded-full border border-gray-700/60 bg-black/40 px-2 py-0.5 text-[9px] font-mono font-bold text-cyan-300">
                  {item.badge}
                </span>
              )}

              {item.count !== undefined && item.count > 0 && (
                <span
                  className={`rounded-full px-2 py-0.2 text-[10px] font-mono font-bold ${
                    item.id === "findings"
                      ? "bg-rose-950/80 border border-rose-800/60 text-rose-300"
                      : "bg-blue-950/80 border border-blue-800/60 text-blue-300"
                  }`}
                >
                  {item.count}
                </span>
              )}
            </motion.button>
          );
        })}
      </nav>

      {/* Autonomous Agent Card */}
      <div className="mt-auto relative overflow-hidden rounded-2xl border border-cyan-500/20 bg-gradient-to-br from-cyan-950/30 via-gray-900 to-black p-4 text-xs shadow-xl">
        <div className="flex items-center gap-2 text-cyan-400 font-bold font-mono">
          <Sparkles size={14} className="animate-spin" />
          Autonomous DAST Agent
        </div>
        <p className="mt-1 text-[11px] text-gray-400 leading-relaxed">
          Zero-false-positive multi-scanner pipeline correlating Nuclei, ZAP, and Nikto.
        </p>
        <div className="mt-3 flex items-center justify-between font-mono text-[10px] border-t border-gray-800 pt-2 text-gray-500">
          <span>Target Profile</span>
          <span className="text-emerald-400 font-bold">Web + API</span>
        </div>
      </div>

      {/* Authenticated User Session */}
      {user && (
        <div className="mt-4 flex items-center justify-between rounded-xl border border-gray-800/80 bg-black/40 px-3 py-2.5">
          <div className="flex items-center gap-2.5">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-blue-600/20 border border-blue-500/30 text-blue-400">
              <UserCheck size={16} />
            </div>
            <div>
              <div className="text-xs font-bold text-white font-mono">{user.username}</div>
              <div className="text-[10px] text-gray-400 font-mono">{user.role}</div>
            </div>
          </div>
          {onLogout && (
            <button
              onClick={onLogout}
              title="Sign Out"
              className="rounded-lg p-1.5 text-gray-400 hover:bg-rose-500/20 hover:text-rose-300 transition-colors cursor-pointer"
            >
              <LogOut size={15} />
            </button>
          )}
        </div>
      )}
    </motion.aside>
  );
}
