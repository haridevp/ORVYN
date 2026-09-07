import { motion } from "framer-motion";
import {
  LayoutDashboard,
  GitBranch,
  ShieldAlert,
  Terminal,
  Cpu,
  Shield,
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
      icon: <LayoutDashboard size={16} />,
    },
    {
      id: "topology" as NavTab,
      label: "API Attack Graph",
      icon: <GitBranch size={16} />,
      badge: "Escape",
    },
    {
      id: "findings" as NavTab,
      label: "Threats & Findings",
      icon: <ShieldAlert size={16} />,
      count: threatCount,
    },
    {
      id: "terminal" as NavTab,
      label: "Live Console",
      icon: <Terminal size={16} />,
      count: logsCount,
      pulse: true,
    },
    {
      id: "scanners" as NavTab,
      label: "Engine Cluster",
      icon: <Cpu size={16} />,
      badge: "3 Active",
    },
  ];

  return (
    <motion.aside
      initial={{ x: -200, opacity: 0 }}
      animate={{ x: 0, opacity: 1 }}
      className="hidden w-64 shrink-0 flex-col glass-sidebar px-4 py-6 md:flex relative z-30 border-r border-slate-800/80 bg-[#080c14]"
    >
      {/* Brand Header */}
      <div className="flex items-center gap-3 px-2 pb-6 border-b border-slate-800/60">
        <div className="p-2 bg-slate-900 border border-slate-800 rounded-lg text-blue-400">
          <Shield size={20} />
        </div>
        <div>
          <div className="flex items-center gap-1.5">
            <p className="text-xs font-bold tracking-wider text-slate-100 uppercase font-mono">AEGIS</p>
            <span className="text-[9px] font-mono font-medium text-slate-400 bg-slate-900 border border-slate-800 px-1.5 py-0.2 rounded">SEC</span>
          </div>
          <p className="text-[11px] text-slate-400 font-normal">Penetration Testing & DAST</p>
        </div>
      </div>

      {/* Nav List */}
      <nav className="flex flex-col gap-1 mt-5">
        <div className="px-3 pb-2 text-[10px] font-mono uppercase tracking-wider text-slate-500">
          Platform Navigation
        </div>
        {navItems.map((item) => {
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => setActiveTab(item.id)}
              className={`flex items-center justify-between rounded-lg px-3 py-2 text-xs font-medium transition-colors text-left cursor-pointer ${
                isActive
                  ? "bg-blue-600/15 text-slate-100 border border-blue-500/30"
                  : "text-slate-400 hover:text-slate-200 hover:bg-slate-900/50"
              }`}
            >
              <span className="flex items-center gap-2.5">
                <span className={isActive ? "text-blue-400" : "text-slate-500"}>{item.icon}</span>
                <span>{item.label}</span>
              </span>

              {item.badge && (
                <span className="rounded border border-slate-800 bg-slate-900 px-1.5 py-0.2 text-[9px] font-mono text-slate-400">
                  {item.badge}
                </span>
              )}

              {item.count !== undefined && item.count > 0 && (
                <span
                  className={`rounded px-1.5 py-0.2 text-[10px] font-mono font-medium ${
                    item.id === "findings"
                      ? "bg-rose-500/15 border border-rose-500/25 text-rose-300"
                      : "bg-blue-500/15 border border-blue-500/25 text-blue-300"
                  }`}
                >
                  {item.count}
                </span>
              )}
            </button>
          );
        })}
      </nav>

      {/* Engine Cluster Status Telemetry */}
      <div className="mt-auto rounded-xl border border-slate-800/80 bg-slate-900/40 p-3 text-xs space-y-2">
        <div className="flex items-center justify-between text-[11px] font-mono">
          <span className="text-slate-400">Engine Cluster</span>
          <span className="text-emerald-400 font-medium flex items-center gap-1">
            <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />
            3 Active
          </span>
        </div>
        <div className="text-[10px] font-mono text-slate-500 space-y-1 pt-1 border-t border-slate-800/60">
          <div className="flex justify-between">
            <span>Nuclei v3</span>
            <span className="text-slate-400">Templates</span>
          </div>
          <div className="flex justify-between">
            <span>OWASP ZAP</span>
            <span className="text-slate-400">DAST & Spider</span>
          </div>
          <div className="flex justify-between">
            <span>Nikto</span>
            <span className="text-slate-400">Server Audit</span>
          </div>
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
