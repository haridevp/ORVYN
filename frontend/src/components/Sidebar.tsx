import {
  LayoutDashboard,
  Crosshair,
  AlertTriangle,
  Globe,
  Radio,
  BookOpen,
  Settings,
  LogOut,
  Search,
  Terminal,
  History,
  Shield,
} from "lucide-react";

export type NavTab =
  | "dashboard"
  | "pentests"
  | "issues"
  | "domains"
  | "topology"
  | "terminal"
  | "knowledge"
  | "history"
  | "settings";

interface SidebarProps {
  activeTab: NavTab;
  setActiveTab: (tab: NavTab) => void;
  threatCount?: number;
  logsCount?: number;
  historyCount?: number;
  user?: { username: string; role: string } | null;
  onLogout?: () => void;
  onOpenCommandPalette: () => void;
  onOpenDocs?: () => void;
}

export function Sidebar({
  activeTab,
  setActiveTab,
  threatCount = 0,
  logsCount = 0,
  historyCount = 0,
  user,
  onLogout,
  onOpenCommandPalette,
}: SidebarProps) {
  const username = user?.username || "SecOps";
  const userInitial = username.charAt(0).toUpperCase();
  const userRole = user?.role || "Security Analyst";

  return (
    <aside className="hidden w-60 shrink-0 flex-col border-r border-neutral-800/80 bg-[#090a0f] px-3.5 py-4 md:flex select-none text-xs">
      {/* Brand Header */}
      <div className="mb-4 px-1.5 flex items-center justify-between pb-3 border-b border-neutral-800/80">
        <div className="flex items-center gap-2.5">
          <div className="flex h-7 w-7 items-center justify-center rounded-lg bg-neutral-800 border border-neutral-700/60 text-white">
            <Shield size={15} />
          </div>
          <div>
            <div className="text-xs font-bold tracking-tight text-white flex items-center gap-1.5">
              <span>ORVYN</span>
              <span className="text-[10px] font-mono font-normal text-neutral-400">v3.0</span>
            </div>
            <div className="text-[10px] text-neutral-400">Penetration Testing</div>
          </div>
        </div>
        <div className="flex items-center gap-1 rounded-full bg-emerald-500/10 border border-emerald-500/20 px-2 py-0.5 text-[10px] text-emerald-400 font-mono">
          <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse" />
          <span>Active</span>
        </div>
      </div>

      {/* Quick Search / Command Palette Trigger */}
      <button
        onClick={onOpenCommandPalette}
        className="mb-4 flex items-center justify-between w-full px-2.5 py-1.5 rounded-lg bg-neutral-900 border border-neutral-800 text-neutral-400 hover:text-white hover:border-neutral-700 transition-colors cursor-pointer text-xs"
      >
        <span className="flex items-center gap-2">
          <Search size={13} className="text-neutral-500" />
          <span>Quick search...</span>
        </span>
        <kbd className="rounded bg-neutral-800 border border-neutral-700 px-1.5 py-0.5 text-[9px] font-mono text-neutral-400">
          ⌘K
        </kbd>
      </button>

      {/* Navigation Group 1: Operations */}
      <div className="mb-4 space-y-1">
        <div className="px-2 mb-1 text-[10px] font-semibold text-neutral-400 uppercase tracking-wider">
          Operations
        </div>

        <button
          onClick={() => setActiveTab("dashboard")}
          className={`group flex items-center justify-between w-full rounded-lg px-2.5 py-2 transition-colors cursor-pointer ${
            activeTab === "dashboard"
              ? "bg-neutral-800 text-white font-medium border border-neutral-700/60"
              : "text-neutral-300 hover:bg-neutral-900 hover:text-white"
          }`}
        >
          <span className="flex items-center gap-2.5">
            <LayoutDashboard size={14} className={activeTab === "dashboard" ? "text-white" : "text-neutral-400 group-hover:text-neutral-200"} />
            <span>Dashboard</span>
          </span>
        </button>

        <button
          onClick={() => setActiveTab("pentests")}
          className={`group flex items-center justify-between w-full rounded-lg px-2.5 py-2 transition-colors cursor-pointer ${
            activeTab === "pentests"
              ? "bg-neutral-800 text-white font-medium border border-neutral-700/60"
              : "text-neutral-300 hover:bg-neutral-900 hover:text-white"
          }`}
        >
          <span className="flex items-center gap-2.5">
            <Crosshair size={14} className={activeTab === "pentests" ? "text-white" : "text-neutral-400 group-hover:text-neutral-200"} />
            <span>New Pentest</span>
          </span>
          <span className="rounded bg-neutral-900 border border-neutral-700/80 px-1.5 py-0.5 text-[9px] font-mono text-neutral-300">
            Scan
          </span>
        </button>

        <button
          onClick={() => setActiveTab("issues")}
          className={`group flex items-center justify-between w-full rounded-lg px-2.5 py-2 transition-colors cursor-pointer ${
            activeTab === "issues"
              ? "bg-neutral-800 text-white font-medium border border-neutral-700/60"
              : "text-neutral-300 hover:bg-neutral-900 hover:text-white"
          }`}
        >
          <span className="flex items-center gap-2.5">
            <AlertTriangle size={14} className={activeTab === "issues" ? "text-amber-400" : "text-neutral-400 group-hover:text-neutral-200"} />
            <span>Vulnerabilities</span>
          </span>
          {threatCount > 0 && (
            <span className="rounded-full bg-rose-500/20 border border-rose-500/30 px-1.5 py-0.5 text-[10px] font-mono font-medium text-rose-300">
              {threatCount}
            </span>
          )}
        </button>
      </div>

      {/* Navigation Group 2: Target & Surface */}
      <div className="mb-4 space-y-1">
        <div className="px-2 mb-1 text-[10px] font-semibold text-neutral-400 uppercase tracking-wider">
          Target & Surface
        </div>

        <button
          onClick={() => setActiveTab("domains")}
          className={`group flex items-center justify-between w-full rounded-lg px-2.5 py-2 transition-colors cursor-pointer ${
            activeTab === "domains"
              ? "bg-neutral-800 text-white font-medium border border-neutral-700/60"
              : "text-neutral-300 hover:bg-neutral-900 hover:text-white"
          }`}
        >
          <span className="flex items-center gap-2.5">
            <Globe size={14} className={activeTab === "domains" ? "text-white" : "text-neutral-400 group-hover:text-neutral-200"} />
            <span>Domains & IPs</span>
          </span>
        </button>

        <button
          onClick={() => setActiveTab("topology")}
          className={`group flex items-center justify-between w-full rounded-lg px-2.5 py-2 transition-colors cursor-pointer ${
            activeTab === "topology"
              ? "bg-neutral-800 text-white font-medium border border-neutral-700/60"
              : "text-neutral-300 hover:bg-neutral-900 hover:text-white"
          }`}
        >
          <span className="flex items-center gap-2.5">
            <Radio size={14} className={activeTab === "topology" ? "text-white" : "text-neutral-400 group-hover:text-neutral-200"} />
            <span>Topology & Assets</span>
          </span>
        </button>

        <button
          onClick={() => setActiveTab("terminal")}
          className={`group flex items-center justify-between w-full rounded-lg px-2.5 py-2 transition-colors cursor-pointer ${
            activeTab === "terminal"
              ? "bg-neutral-800 text-white font-medium border border-neutral-700/60"
              : "text-neutral-300 hover:bg-neutral-900 hover:text-white"
          }`}
        >
          <span className="flex items-center gap-2.5">
            <Terminal size={14} className={activeTab === "terminal" ? "text-white" : "text-neutral-400 group-hover:text-neutral-200"} />
            <span>Console Logs</span>
          </span>
          {logsCount > 0 && (
            <span className="text-[10px] font-mono text-neutral-400 bg-neutral-900 px-1.5 py-0.5 rounded border border-neutral-800">
              {logsCount}
            </span>
          )}
        </button>
      </div>

      {/* Navigation Group 3: Intelligence & System */}
      <div className="space-y-1">
        <div className="px-2 mb-1 text-[10px] font-semibold text-neutral-400 uppercase tracking-wider">
          Intelligence & Archive
        </div>

        <button
          onClick={() => setActiveTab("history")}
          className={`group flex items-center justify-between w-full rounded-lg px-2.5 py-2 transition-colors cursor-pointer ${
            activeTab === "history"
              ? "bg-neutral-800 text-white font-medium border border-neutral-700/60"
              : "text-neutral-300 hover:bg-neutral-900 hover:text-white"
          }`}
        >
          <span className="flex items-center gap-2.5">
            <History size={14} className={activeTab === "history" ? "text-white" : "text-neutral-400 group-hover:text-neutral-200"} />
            <span>Scan History</span>
          </span>
          {historyCount > 0 && (
            <span className="text-[10px] font-mono text-neutral-400 bg-neutral-900 px-1.5 py-0.5 rounded border border-neutral-800">
              {historyCount}
            </span>
          )}
        </button>

        <button
          onClick={() => setActiveTab("knowledge")}
          className={`group flex items-center justify-between w-full rounded-lg px-2.5 py-2 transition-colors cursor-pointer ${
            activeTab === "knowledge"
              ? "bg-neutral-800 text-white font-medium border border-neutral-700/60"
              : "text-neutral-300 hover:bg-neutral-900 hover:text-white"
          }`}
        >
          <span className="flex items-center gap-2.5">
            <BookOpen size={14} className={activeTab === "knowledge" ? "text-white" : "text-neutral-400 group-hover:text-neutral-200"} />
            <span>Security Knowledge</span>
          </span>
          <span className="rounded bg-neutral-900 border border-neutral-800 px-1.5 py-0.5 text-[9px] font-mono text-neutral-400">
            5k+ RAG
          </span>
        </button>

        <button
          onClick={() => setActiveTab("settings")}
          className={`group flex items-center justify-between w-full rounded-lg px-2.5 py-2 transition-colors cursor-pointer ${
            activeTab === "settings"
              ? "bg-neutral-800 text-white font-medium border border-neutral-700/60"
              : "text-neutral-300 hover:bg-neutral-900 hover:text-white"
          }`}
        >
          <span className="flex items-center gap-2.5">
            <Settings size={14} className={activeTab === "settings" ? "text-white" : "text-neutral-400 group-hover:text-neutral-200"} />
            <span>Settings</span>
          </span>
        </button>
      </div>

      {/* Clean User / Account Footer */}
      <div className="mt-auto pt-3 border-t border-neutral-800/80 flex items-center justify-between">
        <div className="flex items-center gap-2.5 min-w-0">
          <div className="h-6 w-6 rounded-full bg-neutral-800 border border-neutral-700 flex items-center justify-center font-bold text-neutral-200 text-xs shrink-0">
            {userInitial}
          </div>
          <div className="min-w-0">
            <div className="font-semibold text-white truncate text-xs">
              {username}
            </div>
            <div className="text-[10px] text-neutral-400 truncate">
              {userRole}
            </div>
          </div>
        </div>

        {onLogout && (
          <button
            onClick={onLogout}
            title="Sign Out"
            className="p-1.5 rounded text-neutral-500 hover:text-rose-400 hover:bg-rose-500/10 transition-colors cursor-pointer"
          >
            <LogOut size={13} />
          </button>
        )}
      </div>
    </aside>
  );
}
