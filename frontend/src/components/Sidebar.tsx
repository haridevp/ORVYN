import { useState, useRef, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  LayoutDashboard,
  Crosshair,
  AlertTriangle,
  Package,
  Box,
  Globe,
  Radio,
  BookOpen,
  Plug,
  Code2,
  Settings,
  ChevronDown,
  LogOut,
  Search,
  Terminal,
  History,
  Shield,
  User,
  CheckCircle2,
  Cpu,
  Wifi,
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
  const [isAdminDropdownOpen, setIsAdminDropdownOpen] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);

  const username = user?.username || "admin";
  const userInitial = username.charAt(0).toUpperCase();
  const userRole = user?.role || "SecOps Cyber-Lead";

  // Close dropdown on click outside
  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setIsAdminDropdownOpen(false);
      }
    }
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  return (
    <motion.aside
      initial={{ x: -220, opacity: 0 }}
      animate={{ x: 0, opacity: 1 }}
      transition={{ duration: 0.3, ease: "easeOut" }}
      className="hidden w-64 shrink-0 flex-col border-r border-cyan-500/15 bg-gradient-to-b from-[#080911] via-[#06070c] to-[#040508] px-3.5 py-4 md:flex relative z-30 select-none text-xs shadow-2xl backdrop-blur-2xl"
    >
      {/* Background ambient futuristic glow element */}
      <div className="pointer-events-none absolute -top-24 -left-24 h-48 w-48 rounded-full bg-cyan-500/10 blur-3xl" />
      <div className="pointer-events-none absolute top-1/2 -right-20 h-40 w-40 rounded-full bg-purple-500/5 blur-3xl" />

      {/* Futuristic Command Deck Header & System Status */}
      <div className="mb-3 px-1 flex items-center justify-between border-b border-cyan-500/10 pb-2.5">
        <div className="flex items-center gap-2">
          <div className="relative flex h-6 w-6 items-center justify-center rounded-lg bg-cyan-950/60 border border-cyan-500/40 text-cyan-400 shadow-[0_0_10px_rgba(0,240,255,0.25)]">
            <Cpu size={13} className="animate-pulse" />
            <div className="absolute -top-0.5 -right-0.5 h-1.5 w-1.5 rounded-full bg-emerald-400 shadow-[0_0_6px_#10b981]" />
          </div>
          <div className="flex flex-col">
            <span className="font-mono text-[10px] font-extrabold tracking-widest text-cyan-400 uppercase">
              AEGIS // DECK
            </span>
            <span className="text-[9px] font-mono text-slate-500 tracking-wider">
              AI-PENTEST v3.0
            </span>
          </div>
        </div>
        <div className="flex items-center gap-1.5 rounded-full bg-cyan-950/40 border border-cyan-500/20 px-2 py-0.5 text-[9px] font-mono text-cyan-300">
          <span className="h-1.5 w-1.5 rounded-full bg-cyan-400 animate-ping" />
          <span className="font-semibold tracking-wide">ONLINE</span>
        </div>
      </div>

      {/* Operator Account Switcher / HUD Dropdown */}
      <div className="relative mb-3" ref={dropdownRef}>
        <button
          type="button"
          onClick={() => setIsAdminDropdownOpen((prev) => !prev)}
          className="flex items-center justify-between w-full px-2.5 py-2 rounded-xl bg-[#0c0e18]/80 hover:bg-[#101322] border border-cyan-500/20 hover:border-cyan-500/40 transition-all duration-200 cursor-pointer group text-left shadow-sm hover:shadow-[0_0_15px_rgba(0,240,255,0.1)]"
          title="Operator & Scope Configuration"
        >
          <div className="flex items-center gap-2.5 min-w-0">
            <div className="relative h-7 w-7 rounded-lg bg-gradient-to-tr from-cyan-600 to-purple-600 p-[1px] shrink-0 shadow-sm">
              <div className="h-full w-full rounded-[7px] bg-[#090b14] flex items-center justify-center font-bold text-cyan-300 text-xs font-mono">
                {userInitial}
              </div>
              <div className="absolute -bottom-0.5 -right-0.5 h-2 w-2 rounded-full bg-emerald-400 ring-2 ring-[#080911]" />
            </div>
            <div className="flex flex-col min-w-0">
              <span className="font-bold text-slate-100 tracking-wide text-xs truncate capitalize group-hover:text-cyan-300 transition-colors">
                {username}
              </span>
              <span className="text-[9px] text-slate-400 font-mono truncate">
                {userRole}
              </span>
            </div>
          </div>
          <ChevronDown
            size={13}
            className={`text-slate-400 transition-transform duration-200 shrink-0 ${
              isAdminDropdownOpen ? "rotate-180 text-cyan-400" : "group-hover:text-slate-200"
            }`}
          />
        </button>

        {/* Futuristic Glassmorphic Dropdown Menu */}
        <AnimatePresence>
          {isAdminDropdownOpen && (
            <motion.div
              initial={{ opacity: 0, y: -6, scale: 0.95 }}
              animate={{ opacity: 1, y: 0, scale: 1 }}
              exit={{ opacity: 0, y: -6, scale: 0.95 }}
              transition={{ duration: 0.15 }}
              className="absolute left-0 top-full mt-1.5 w-68 rounded-2xl border border-cyan-500/30 bg-[#080a14]/95 backdrop-blur-2xl shadow-[0_15px_40px_rgba(0,0,0,0.8),0_0_20px_rgba(0,240,255,0.12)] z-50 p-2.5 space-y-2 text-xs font-sans"
            >
              {/* Account Card */}
              <div className="p-2.5 rounded-xl bg-[#0f1222]/90 border border-cyan-500/20 shadow-inner">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <User size={13} className="text-cyan-400" />
                    <span className="font-bold text-white capitalize tracking-wide">{username}</span>
                  </div>
                  <span className="flex items-center gap-1 px-1.5 py-0.5 rounded-full bg-emerald-500/15 text-emerald-300 border border-emerald-500/30 text-[9px] font-mono font-bold">
                    <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse" />
                    SEC-ACTIVE
                  </span>
                </div>
                <div className="text-[10px] text-slate-400 mt-1 font-mono">{userRole}</div>
                <div className="text-[9px] text-cyan-400/80 font-mono mt-0.5 truncate">
                  {username}@secops.network
                </div>
              </div>

              {/* Workspace Scopes */}
              <div>
                <div className="px-2 py-1 text-[9px] font-mono text-cyan-400/70 uppercase tracking-widest flex items-center justify-between">
                  <span>ACTIVE LAB SCOPES</span>
                  <Wifi size={10} className="text-cyan-400" />
                </div>
                <div className="space-y-1 mt-1">
                  <div className="flex items-center justify-between px-2.5 py-1.5 rounded-lg bg-cyan-950/40 border border-cyan-500/30 text-white font-medium text-[11px]">
                    <div className="flex items-center gap-2">
                      <Shield size={12} className="text-cyan-400" />
                      <span className="truncate">Autonomous Recon Lab</span>
                    </div>
                    <CheckCircle2 size={12} className="text-cyan-400 shrink-0" />
                  </div>
                  <button
                    type="button"
                    onClick={() => {
                      setActiveTab("domains");
                      setIsAdminDropdownOpen(false);
                    }}
                    className="flex items-center justify-between w-full px-2.5 py-1.5 rounded-lg text-slate-400 hover:text-cyan-200 hover:bg-cyan-950/30 transition-colors text-left cursor-pointer text-[11px]"
                  >
                    <span>Target IP / Host Registry</span>
                    <span className="text-[9px] font-mono text-cyan-400 font-bold">MANAGE</span>
                  </button>
                </div>
              </div>

              {/* Direct Actions */}
              <div className="border-t border-cyan-500/15 pt-1.5 space-y-0.5">
                <button
                  type="button"
                  onClick={() => {
                    setActiveTab("settings");
                    setIsAdminDropdownOpen(false);
                  }}
                  className="flex items-center gap-2 w-full px-2.5 py-1.5 rounded-lg text-slate-300 hover:bg-cyan-950/40 hover:text-cyan-200 transition-colors text-left cursor-pointer text-[11px]"
                >
                  <Settings size={13} className="text-cyan-400" />
                  <span>Platform Engine Config</span>
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setActiveTab("history");
                    setIsAdminDropdownOpen(false);
                  }}
                  className="flex items-center gap-2 w-full px-2.5 py-1.5 rounded-lg text-slate-300 hover:bg-cyan-950/40 hover:text-cyan-200 transition-colors text-left cursor-pointer text-[11px]"
                >
                  <History size={13} className="text-cyan-400" />
                  <span>Audit Event Telemetry</span>
                </button>
                {onLogout && (
                  <button
                    type="button"
                    onClick={() => {
                      setIsAdminDropdownOpen(false);
                      onLogout();
                    }}
                    className="flex items-center gap-2 w-full px-2.5 py-1.5 rounded-lg text-rose-400 hover:bg-rose-500/15 transition-colors text-left cursor-pointer font-medium text-[11px]"
                  >
                    <LogOut size={13} />
                    <span>Terminate Session</span>
                  </button>
                )}
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>

      {/* Futuristic Command Palette Launcher */}
      <button
        onClick={onOpenCommandPalette}
        className="flex items-center justify-between w-full rounded-xl border border-cyan-500/20 bg-[#0a0c16]/80 px-3 py-1.5 text-xs text-slate-400 hover:border-cyan-400/50 hover:text-cyan-200 hover:bg-[#0f1222] transition-all duration-200 mb-3 cursor-pointer shadow-inner group"
      >
        <span className="flex items-center gap-2 text-[11px]">
          <Search size={13} className="text-cyan-500 group-hover:text-cyan-400 transition-colors" />
          <span className="tracking-wide">Command Matrix...</span>
        </span>
        <span className="rounded-md bg-cyan-950/80 border border-cyan-500/30 px-1.5 py-0.5 text-[9px] font-mono text-cyan-300 font-semibold shadow-xs">
          CTRL K
        </span>
      </button>

      {/* NAVIGATION SECTION 1: MISSION & OPERATIONS */}
      <div className="mb-1 px-1">
        <span className="text-[9px] font-mono font-bold tracking-widest text-cyan-500/70 uppercase">
          // 01 MISSION OPS
        </span>
      </div>

      <div className="space-y-1">
        {/* Dashboard */}
        <button
          onClick={() => setActiveTab("dashboard")}
          className={`group relative flex items-center justify-between w-full rounded-xl px-3 py-2 transition-all duration-150 cursor-pointer ${
            activeTab === "dashboard"
              ? "bg-gradient-to-r from-cyan-950/60 via-cyan-900/20 to-transparent border border-cyan-500/30 text-white font-medium shadow-[0_0_15px_rgba(0,240,255,0.08)]"
              : "text-slate-400 hover:bg-[#0c0e1a]/80 hover:text-slate-200 border border-transparent"
          }`}
        >
          {activeTab === "dashboard" && (
            <motion.div
              layoutId="activeRail"
              className="absolute left-0 top-2 bottom-2 w-1 rounded-r-full bg-cyan-400 shadow-[0_0_8px_#00f0ff]"
            />
          )}
          <span className="flex items-center gap-2.5">
            <LayoutDashboard
              size={15}
              className={activeTab === "dashboard" ? "text-cyan-400 drop-shadow-[0_0_6px_rgba(0,240,255,0.6)]" : "text-slate-500 group-hover:text-slate-300"}
            />
            <span className="tracking-wide">Dashboard</span>
          </span>
        </button>

        {/* Pentests */}
        <button
          onClick={() => setActiveTab("pentests")}
          className={`group relative flex items-center justify-between w-full rounded-xl px-3 py-2 transition-all duration-150 cursor-pointer ${
            activeTab === "pentests"
              ? "bg-gradient-to-r from-cyan-950/60 via-cyan-900/20 to-transparent border border-cyan-500/30 text-white font-medium shadow-[0_0_15px_rgba(0,240,255,0.08)]"
              : "text-slate-400 hover:bg-[#0c0e1a]/80 hover:text-slate-200 border border-transparent"
          }`}
        >
          {activeTab === "pentests" && (
            <motion.div
              layoutId="activeRail"
              className="absolute left-0 top-2 bottom-2 w-1 rounded-r-full bg-cyan-400 shadow-[0_0_8px_#00f0ff]"
            />
          )}
          <span className="flex items-center gap-2.5">
            <Crosshair
              size={15}
              className={activeTab === "pentests" ? "text-cyan-400 drop-shadow-[0_0_6px_rgba(0,240,255,0.6)]" : "text-slate-500 group-hover:text-slate-300"}
            />
            <span className="tracking-wide">Pentests</span>
          </span>
          <span className="rounded-full bg-cyan-500/20 border border-cyan-500/40 px-2 py-0.5 text-[9px] font-mono font-bold text-cyan-300 shadow-[0_0_8px_rgba(0,240,255,0.3)]">
            LIVE
          </span>
        </button>

        {/* Issues */}
        <button
          onClick={() => setActiveTab("issues")}
          className={`group relative flex items-center justify-between w-full rounded-xl px-3 py-2 transition-all duration-150 cursor-pointer ${
            activeTab === "issues"
              ? "bg-gradient-to-r from-cyan-950/60 via-cyan-900/20 to-transparent border border-cyan-500/30 text-white font-medium shadow-[0_0_15px_rgba(0,240,255,0.08)]"
              : "text-slate-400 hover:bg-[#0c0e1a]/80 hover:text-slate-200 border border-transparent"
          }`}
        >
          {activeTab === "issues" && (
            <motion.div
              layoutId="activeRail"
              className="absolute left-0 top-2 bottom-2 w-1 rounded-r-full bg-cyan-400 shadow-[0_0_8px_#00f0ff]"
            />
          )}
          <span className="flex items-center gap-2.5">
            <AlertTriangle
              size={15}
              className={activeTab === "issues" ? "text-cyan-400 drop-shadow-[0_0_6px_rgba(0,240,255,0.6)]" : "text-slate-500 group-hover:text-slate-300"}
            />
            <span className="tracking-wide">Issues</span>
          </span>
          {threatCount > 0 && (
            <span className="rounded-full bg-rose-500/20 border border-rose-500/50 px-2 py-0.5 text-[10px] font-mono font-bold text-rose-300 shadow-[0_0_8px_rgba(244,63,94,0.3)]">
              {threatCount}
            </span>
          )}
        </button>

        {/* Supply Chain */}
        <button
          onClick={() => setActiveTab("domains")}
          className="group relative flex items-center justify-between w-full rounded-xl px-3 py-2 text-slate-400 hover:bg-[#0c0e1a]/80 hover:text-slate-200 border border-transparent transition-all duration-150 cursor-pointer"
        >
          <span className="flex items-center gap-2.5">
            <Package size={15} className="text-slate-500 group-hover:text-slate-300" />
            <span className="tracking-wide">Supply Chain</span>
          </span>
        </button>

        {/* Containers */}
        <button
          onClick={() => setActiveTab("domains")}
          className="group relative flex items-center justify-between w-full rounded-xl px-3 py-2 text-slate-400 hover:bg-[#0c0e1a]/80 hover:text-slate-200 border border-transparent transition-all duration-150 cursor-pointer"
        >
          <span className="flex items-center gap-2.5">
            <Box size={15} className="text-slate-500 group-hover:text-slate-300" />
            <span className="tracking-wide">Containers</span>
          </span>
        </button>
      </div>

      {/* Cyber Separator Line */}
      <div className="my-3 border-t border-cyan-500/10 relative">
        <div className="absolute left-4 -top-[1px] h-[2px] w-8 bg-cyan-400/40" />
      </div>

      {/* NAVIGATION SECTION 2: INTEL & SURFACE MATRIX */}
      <div className="mb-1 px-1">
        <span className="text-[9px] font-mono font-bold tracking-widest text-cyan-500/70 uppercase">
          // 02 INTEL & SURFACE
        </span>
      </div>

      <div className="space-y-1">
        {/* Domains & IPs */}
        <button
          onClick={() => setActiveTab("domains")}
          className={`group relative flex items-center justify-between w-full rounded-xl px-3 py-2 transition-all duration-150 cursor-pointer ${
            activeTab === "domains"
              ? "bg-gradient-to-r from-cyan-950/60 via-cyan-900/20 to-transparent border border-cyan-500/30 text-white font-medium shadow-[0_0_15px_rgba(0,240,255,0.08)]"
              : "text-slate-400 hover:bg-[#0c0e1a]/80 hover:text-slate-200 border border-transparent"
          }`}
        >
          {activeTab === "domains" && (
            <motion.div
              layoutId="activeRail"
              className="absolute left-0 top-2 bottom-2 w-1 rounded-r-full bg-cyan-400 shadow-[0_0_8px_#00f0ff]"
            />
          )}
          <span className="flex items-center gap-2.5">
            <Globe
              size={15}
              className={activeTab === "domains" ? "text-cyan-400 drop-shadow-[0_0_6px_rgba(0,240,255,0.6)]" : "text-slate-500 group-hover:text-slate-300"}
            />
            <span className="tracking-wide">Domains & IPs</span>
          </span>
        </button>

        {/* Asset Discovery */}
        <button
          onClick={() => setActiveTab("topology")}
          className={`group relative flex items-center justify-between w-full rounded-xl px-3 py-2 transition-all duration-150 cursor-pointer ${
            activeTab === "topology"
              ? "bg-gradient-to-r from-cyan-950/60 via-cyan-900/20 to-transparent border border-cyan-500/30 text-white font-medium shadow-[0_0_15px_rgba(0,240,255,0.08)]"
              : "text-slate-400 hover:bg-[#0c0e1a]/80 hover:text-slate-200 border border-transparent"
          }`}
        >
          {activeTab === "topology" && (
            <motion.div
              layoutId="activeRail"
              className="absolute left-0 top-2 bottom-2 w-1 rounded-r-full bg-cyan-400 shadow-[0_0_8px_#00f0ff]"
            />
          )}
          <span className="flex items-center gap-2.5">
            <Radio
              size={15}
              className={activeTab === "topology" ? "text-cyan-400 drop-shadow-[0_0_6px_rgba(0,240,255,0.6)]" : "text-slate-500 group-hover:text-slate-300"}
            />
            <span className="tracking-wide">Asset Discovery</span>
          </span>
        </button>

        {/* Live Console */}
        <button
          onClick={() => setActiveTab("terminal")}
          className={`group relative flex items-center justify-between w-full rounded-xl px-3 py-2 transition-all duration-150 cursor-pointer ${
            activeTab === "terminal"
              ? "bg-gradient-to-r from-cyan-950/60 via-cyan-900/20 to-transparent border border-cyan-500/30 text-white font-medium shadow-[0_0_15px_rgba(0,240,255,0.08)]"
              : "text-slate-400 hover:bg-[#0c0e1a]/80 hover:text-slate-200 border border-transparent"
          }`}
        >
          {activeTab === "terminal" && (
            <motion.div
              layoutId="activeRail"
              className="absolute left-0 top-2 bottom-2 w-1 rounded-r-full bg-cyan-400 shadow-[0_0_8px_#00f0ff]"
            />
          )}
          <span className="flex items-center gap-2.5">
            <Terminal
              size={15}
              className={activeTab === "terminal" ? "text-cyan-400 drop-shadow-[0_0_6px_rgba(0,240,255,0.6)]" : "text-slate-500 group-hover:text-slate-300"}
            />
            <span className="tracking-wide">Live Console</span>
          </span>
          {logsCount > 0 && (
            <span className="text-[10px] font-mono text-cyan-400/80 bg-cyan-950/50 px-1.5 py-0.5 rounded border border-cyan-500/30">
              {logsCount}
            </span>
          )}
        </button>

        {/* Knowledge */}
        <button
          onClick={() => setActiveTab("knowledge")}
          className={`group relative flex items-center justify-between w-full rounded-xl px-3 py-2 transition-all duration-150 cursor-pointer ${
            activeTab === "knowledge"
              ? "bg-gradient-to-r from-cyan-950/60 via-cyan-900/20 to-transparent border border-cyan-500/30 text-white font-medium shadow-[0_0_15px_rgba(0,240,255,0.08)]"
              : "text-slate-400 hover:bg-[#0c0e1a]/80 hover:text-slate-200 border border-transparent"
          }`}
        >
          {activeTab === "knowledge" && (
            <motion.div
              layoutId="activeRail"
              className="absolute left-0 top-2 bottom-2 w-1 rounded-r-full bg-cyan-400 shadow-[0_0_8px_#00f0ff]"
            />
          )}
          <span className="flex items-center gap-2.5">
            <BookOpen
              size={15}
              className={activeTab === "knowledge" ? "text-cyan-400 drop-shadow-[0_0_6px_rgba(0,240,255,0.6)]" : "text-slate-500 group-hover:text-slate-300"}
            />
            <span className="tracking-wide">Knowledge RAG</span>
          </span>
          <span className="rounded bg-purple-500/20 border border-purple-500/40 px-1.5 py-0.5 text-[9px] font-mono text-purple-300 font-bold">
            5k+
          </span>
        </button>

        {/* Scan History */}
        <button
          onClick={() => setActiveTab("history")}
          className={`group relative flex items-center justify-between w-full rounded-xl px-3 py-2 transition-all duration-150 cursor-pointer ${
            activeTab === "history"
              ? "bg-gradient-to-r from-cyan-950/60 via-cyan-900/20 to-transparent border border-cyan-500/30 text-white font-medium shadow-[0_0_15px_rgba(0,240,255,0.08)]"
              : "text-slate-400 hover:bg-[#0c0e1a]/80 hover:text-slate-200 border border-transparent"
          }`}
        >
          {activeTab === "history" && (
            <motion.div
              layoutId="activeRail"
              className="absolute left-0 top-2 bottom-2 w-1 rounded-r-full bg-cyan-400 shadow-[0_0_8px_#00f0ff]"
            />
          )}
          <span className="flex items-center gap-2.5">
            <History
              size={15}
              className={activeTab === "history" ? "text-cyan-400 drop-shadow-[0_0_6px_rgba(0,240,255,0.6)]" : "text-slate-500 group-hover:text-slate-300"}
            />
            <span className="tracking-wide">Scan History</span>
          </span>
          {historyCount > 0 && (
            <span className="text-[10px] font-mono text-slate-400 bg-slate-900 px-1.5 py-0.5 rounded border border-slate-800">
              {historyCount}
            </span>
          )}
        </button>

        {/* Integrations */}
        <button
          onClick={() => setActiveTab("settings")}
          className="group relative flex items-center justify-between w-full rounded-xl px-3 py-2 text-slate-400 hover:bg-[#0c0e1a]/80 hover:text-slate-200 border border-transparent transition-all duration-150 cursor-pointer"
        >
          <span className="flex items-center gap-2.5">
            <Plug size={15} className="text-slate-500 group-hover:text-slate-300" />
            <span className="tracking-wide">Integrations</span>
          </span>
        </button>

        {/* API Surface */}
        <button
          onClick={() => setActiveTab("topology")}
          className="group relative flex items-center justify-between w-full rounded-xl px-3 py-2 text-slate-400 hover:bg-[#0c0e1a]/80 hover:text-slate-200 border border-transparent transition-all duration-150 cursor-pointer"
        >
          <span className="flex items-center gap-2.5">
            <Code2 size={15} className="text-slate-500 group-hover:text-slate-300" />
            <span className="tracking-wide">API Surface</span>
          </span>
        </button>

        {/* Settings */}
        <button
          onClick={() => setActiveTab("settings")}
          className={`group relative flex items-center justify-between w-full rounded-xl px-3 py-2 transition-all duration-150 cursor-pointer ${
            activeTab === "settings"
              ? "bg-gradient-to-r from-cyan-950/60 via-cyan-900/20 to-transparent border border-cyan-500/30 text-white font-medium shadow-[0_0_15px_rgba(0,240,255,0.08)]"
              : "text-slate-400 hover:bg-[#0c0e1a]/80 hover:text-slate-200 border border-transparent"
          }`}
        >
          {activeTab === "settings" && (
            <motion.div
              layoutId="activeRail"
              className="absolute left-0 top-2 bottom-2 w-1 rounded-r-full bg-cyan-400 shadow-[0_0_8px_#00f0ff]"
            />
          )}
          <span className="flex items-center gap-2.5">
            <Settings
              size={15}
              className={activeTab === "settings" ? "text-cyan-400 drop-shadow-[0_0_6px_rgba(0,240,255,0.6)]" : "text-slate-500 group-hover:text-slate-300"}
            />
            <span className="tracking-wide">Settings</span>
          </span>
        </button>
      </div>

      {/* Futuristic Telemetry Footer & Quick User Status */}
      <div className="mt-auto pt-3 border-t border-cyan-500/15 flex items-center justify-between">
        <button
          type="button"
          onClick={() => setIsAdminDropdownOpen((prev) => !prev)}
          className="flex items-center gap-2.5 min-w-0 text-left hover:opacity-90 transition-opacity cursor-pointer group"
          title="Open Operator Profile"
        >
          <div className="relative h-7 w-7 rounded-lg bg-[#0e1120] border border-cyan-500/30 flex items-center justify-center font-bold text-cyan-300 text-xs shrink-0 shadow-sm">
            {userInitial}
            <div className="absolute -top-0.5 -right-0.5 h-1.5 w-1.5 rounded-full bg-emerald-400 shadow-[0_0_4px_#10b981]" />
          </div>
          <div className="min-w-0">
            <div className="font-bold text-slate-100 truncate text-xs capitalize group-hover:text-cyan-300 transition-colors">
              {username}
            </div>
            <div className="text-[9px] text-cyan-500/80 font-mono truncate">
              {username}@secops.network
            </div>
          </div>
        </button>

        {onLogout && (
          <button
            onClick={onLogout}
            title="Terminate Session"
            className="p-1.5 rounded-lg text-slate-500 hover:text-rose-400 hover:bg-rose-500/10 transition-colors cursor-pointer border border-transparent hover:border-rose-500/20"
          >
            <LogOut size={14} />
          </button>
        )}
      </div>
    </motion.aside>
  );
}
