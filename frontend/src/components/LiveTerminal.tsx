import { useState, useEffect, useRef } from "react";
import { Terminal, Copy, Check, ArrowDown, ChevronDown, ChevronUp } from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";

interface LiveTerminalProps {
  logs: string[];
  isRunning: boolean;
  isOpen: boolean;
  onToggle: () => void;
}

export function LiveTerminal({ logs, isRunning, isOpen, onToggle }: LiveTerminalProps) {
  const [copied, setCopied] = useState(false);
  const [autoScroll, setAutoScroll] = useState(true);
  const [filter, setFilter] = useState<"all" | "nuclei" | "zap" | "nikto" | "system">("all");
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (autoScroll && scrollRef.current && isOpen) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [logs, autoScroll, isOpen]);

  function handleCopy() {
    navigator.clipboard.writeText(logs.join("\n"));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  const filteredLogs = logs.filter((line) => {
    if (filter === "all") return true;
    return line.toLowerCase().includes(`[${filter}]`);
  });

  function formatLine(line: string) {
    // Expected format: [HH:MM:SS] [tool] message
    const match = line.match(/^(\[\d{2}:\d{2}:\d{2}\])\s*(\[[a-zA-Z0-9_-]+\])\s*(.*)$/);
    if (!match) {
      return <span className="text-gray-300">{line}</span>;
    }

    const [, timestamp, toolTag, content] = match;
    const toolLower = toolTag.toLowerCase();

    let toolColor = "text-gray-400 bg-gray-800/60 border-gray-700/50";
    if (toolLower.includes("nuclei")) toolColor = "text-cyan-400 bg-cyan-950/40 border-cyan-800/40";
    else if (toolLower.includes("zap")) toolColor = "text-amber-400 bg-amber-950/40 border-amber-800/40";
    else if (toolLower.includes("nikto")) toolColor = "text-purple-400 bg-purple-950/40 border-purple-800/40";
    else if (toolLower.includes("system")) toolColor = "text-blue-400 bg-blue-950/40 border-blue-800/40";

    const isHighlight =
      content.toLowerCase().includes("finding") ||
      content.toLowerCase().includes("error") ||
      content.toLowerCase().includes("critical") ||
      content.toLowerCase().includes("high") ||
      content.toLowerCase().includes("warn") ||
      content.toLowerCase().includes("completed") ||
      content.toLowerCase().includes("real engine");

    let contentColor = "text-gray-300";
    if (content.toLowerCase().includes("error") || content.toLowerCase().includes("failed")) {
      contentColor = "text-rose-400 font-medium";
    } else if (content.toLowerCase().includes("real engine") || content.toLowerCase().includes("completed")) {
      contentColor = "text-emerald-400 font-medium";
    } else if (content.toLowerCase().includes("simulated")) {
      contentColor = "text-amber-300 font-medium";
    } else if (content.toLowerCase().includes("executing") || content.toLowerCase().includes("started")) {
      contentColor = "text-sky-300";
    }

    return (
      <div className={`flex items-start gap-2.5 py-0.5 leading-relaxed ${isHighlight ? "bg-white/[0.02] px-1 rounded" : ""}`}>
        <span className="text-gray-600 select-none text-[11px] font-mono shrink-0">{timestamp}</span>
        <span className={`text-[11px] font-mono uppercase tracking-wider px-1.5 py-0.2 rounded border shrink-0 ${toolColor}`}>
          {toolTag.replace(/\[|\]/g, "")}
        </span>
        <span className={`font-mono text-xs break-all ${contentColor}`}>{content}</span>
      </div>
    );
  }

  return (
    <div className="rounded-2xl border border-gray-700/50 bg-[#0c1017]/90 shadow-2xl backdrop-blur-xl overflow-hidden">
      {/* Header Bar */}
      <div
        onClick={onToggle}
        className="flex flex-wrap items-center justify-between gap-3 px-5 py-3.5 border-b border-gray-800/80 bg-gray-900/50 cursor-pointer select-none hover:bg-gray-800/40 transition-colors"
      >
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5">
            <span className="w-3 h-3 rounded-full bg-rose-500/80 border border-rose-600/50"></span>
            <span className="w-3 h-3 rounded-full bg-amber-500/80 border border-amber-600/50"></span>
            <span className="w-3 h-3 rounded-full bg-emerald-500/80 border border-emerald-600/50"></span>
          </div>
          <div className="h-4 w-[1px] bg-gray-700/60 mx-1" />
          <div className="flex items-center gap-2">
            <Terminal size={16} className="text-cyan-400" />
            <span className="text-sm font-bold text-gray-200 tracking-wide">Live Scanner Console</span>
            <span className="text-xs text-gray-400 font-mono hidden sm:inline">(Backend Verbose Stream)</span>
          </div>

          <div className="flex items-center gap-2">
            {isRunning ? (
              <span className="flex items-center gap-1.5 text-[11px] font-semibold tracking-wider text-emerald-400 bg-emerald-950/60 border border-emerald-700/50 px-2 py-0.5 rounded-full">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                STREAMING
              </span>
            ) : (
              <span className="text-[11px] font-medium text-gray-400 bg-gray-800/60 border border-gray-700/50 px-2 py-0.5 rounded-full">
                {logs.length > 0 ? "IDLE / LOGS READY" : "STANDBY"}
              </span>
            )}
            <span className="text-xs text-gray-400 font-mono bg-black/40 px-2 py-0.5 rounded border border-gray-800">
              {logs.length} lines
            </span>
          </div>
        </div>

        <div className="flex items-center gap-2" onClick={(e) => e.stopPropagation()}>
          <button
            onClick={handleCopy}
            disabled={logs.length === 0}
            className="flex items-center gap-1.5 text-xs font-medium text-gray-300 hover:text-white bg-gray-800/80 hover:bg-gray-700 border border-gray-700 px-2.5 py-1 rounded-lg transition-all disabled:opacity-40"
            title="Copy all logs"
          >
            {copied ? <Check size={13} className="text-emerald-400" /> : <Copy size={13} />}
            <span className="hidden sm:inline">{copied ? "Copied" : "Copy"}</span>
          </button>

          <button
            onClick={onToggle}
            className="text-gray-400 hover:text-white p-1 rounded-md transition-colors"
            title={isOpen ? "Collapse Terminal" : "Expand Terminal"}
          >
            {isOpen ? <ChevronUp size={18} /> : <ChevronDown size={18} />}
          </button>
        </div>
      </div>

      {/* Expandable Console Content */}
      <AnimatePresence initial={false}>
        {isOpen && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.25, ease: "easeInOut" }}
            className="flex flex-col"
          >
            {/* Filter Bar */}
            <div className="flex flex-wrap items-center justify-between gap-2 px-5 py-2 border-b border-gray-800/60 bg-black/40 text-xs">
              <div className="flex items-center gap-1.5">
                <span className="text-gray-500 font-medium mr-1">Filter:</span>
                {(["all", "nuclei", "zap", "nikto", "system"] as const).map((f) => (
                  <button
                    key={f}
                    onClick={() => setFilter(f)}
                    className={`px-2 py-0.5 rounded text-[11px] font-mono uppercase tracking-wider transition-colors ${
                      filter === f
                        ? "bg-blue-600/30 text-blue-300 border border-blue-500/40 font-bold"
                        : "text-gray-400 hover:text-gray-200 hover:bg-gray-800/50"
                    }`}
                  >
                    {f}
                  </button>
                ))}
              </div>

              <div className="flex items-center gap-2">
                <button
                  onClick={() => setAutoScroll(!autoScroll)}
                  className={`flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono transition-colors ${
                    autoScroll
                      ? "text-cyan-400 bg-cyan-950/40 border border-cyan-800/40"
                      : "text-gray-500 hover:text-gray-400"
                  }`}
                  title="Auto-scroll as new output arrives"
                >
                  <ArrowDown size={12} className={autoScroll ? "animate-bounce" : ""} />
                  Auto-scroll: {autoScroll ? "ON" : "OFF"}
                </button>
              </div>
            </div>

            {/* Terminal Body */}
            <div
              ref={scrollRef}
              className="h-80 overflow-y-auto p-4 font-mono text-xs space-y-0.5 bg-black/70 scrollbar-thin scrollbar-thumb-gray-700 scrollbar-track-transparent"
            >
              {filteredLogs.length === 0 ? (
                <div className="flex flex-col items-center justify-center h-full text-center text-gray-500 py-8">
                  <Terminal size={32} className="mb-2 opacity-30 text-cyan-400" />
                  <p className="font-mono text-xs text-gray-400">
                    {logs.length === 0
                      ? "No output yet. Launch a scan to observe live scanner stdout/stderr."
                      : `No logs match the current filter "${filter}".`}
                  </p>
                  {isRunning && (
                    <p className="text-[11px] text-cyan-400/80 animate-pulse mt-1">
                      Scanners are actively running in backend... Output will appear here momentarily.
                    </p>
                  )}
                </div>
              ) : (
                filteredLogs.map((line, idx) => (
                  <div key={idx}>{formatLine(line)}</div>
                ))
              )}
            </div>

            {/* Terminal Footer Status */}
            <div className="px-5 py-2 border-t border-gray-800/60 bg-black/50 flex items-center justify-between text-[11px] text-gray-500 font-mono">
              <span className="flex items-center gap-1.5">
                <span className={`w-2 h-2 rounded-full ${isRunning ? "bg-emerald-500 animate-ping" : "bg-gray-600"}`} />
                {isRunning ? "Receiving live scanner pipes..." : "Scan completed. Output preserved."}
              </span>
              <span>UTF-8 • JSON & Plaintext Stdout/Stderr</span>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
