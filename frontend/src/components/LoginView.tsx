import { useState } from "react";
import { motion } from "framer-motion";
import { ShieldAlert, Lock, User, Key, ArrowRight, ShieldCheck, Zap } from "lucide-react";

interface LoginViewProps {
  onLogin: (username: string) => void;
}

export function LoginView({ onLogin }: LoginViewProps) {
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("admin");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading(true);

    setTimeout(() => {
      // Valid credentials check (admin / admin)
      if (username.trim() === "admin" && password === "admin") {
        onLogin(username.trim());
      } else {
        setError("Invalid Security Credentials. Required: admin / admin");
        setLoading(false);
      }
    }, 400);
  }

  return (
    <div className="relative flex min-h-screen w-full items-center justify-center overflow-hidden bg-[#06090e] px-4 font-sans text-gray-200">
      {/* Dynamic Background Cyber Grid & Glows */}
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_50%_20%,rgba(37,99,235,0.15),transparent_60%)]" />
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_80%_80%,rgba(168,85,247,0.1),transparent_50%)]" />
      <div className="absolute inset-0 bg-[linear-gradient(to_right,rgba(255,255,255,0.02)_1px,transparent_1px),linear-gradient(to_bottom,rgba(255,255,255,0.02)_1px,transparent_1px)] bg-[size:3rem_3rem] [mask-image:radial-gradient(ellipse_60%_50%_at_50%_50%,#000_70%,transparent_100%)]" />

      <motion.div
        initial={{ opacity: 0, scale: 0.95, y: 20 }}
        animate={{ opacity: 1, scale: 1, y: 0 }}
        transition={{ duration: 0.5, ease: "easeOut" }}
        className="relative z-10 w-full max-w-md overflow-hidden rounded-3xl border border-blue-500/20 bg-[#0a0f18]/90 p-8 shadow-[0_0_50px_rgba(37,99,235,0.2)] backdrop-blur-2xl"
      >
        {/* Glowing Top Accent Line */}
        <div className="absolute top-0 left-0 right-0 h-[2px] bg-gradient-to-r from-blue-500 via-cyan-400 to-purple-600" />

        <div className="mb-6 flex flex-col items-center text-center">
          <motion.div
            initial={{ rotate: -10 }}
            animate={{ rotate: 0 }}
            transition={{ type: "spring", stiffness: 200 }}
            className="flex h-14 w-14 items-center justify-center rounded-2xl border border-blue-500/30 bg-gradient-to-br from-blue-600/30 to-purple-600/20 text-blue-400 shadow-[0_0_25px_rgba(59,130,246,0.3)] mb-4"
          >
            <ShieldAlert size={30} />
          </motion.div>

          <div className="inline-flex items-center gap-2 rounded-full border border-blue-500/30 bg-blue-500/10 px-3 py-0.5 text-[10px] font-mono font-bold tracking-widest text-cyan-300 uppercase mb-2">
            <span className="h-1.5 w-1.5 rounded-full bg-cyan-400 animate-ping" />
            SOC ACCESS GATEWAY
          </div>

          <h1 className="text-2xl font-black tracking-tight text-white">
            AI Pentest Platform
          </h1>
          <p className="mt-1 text-xs text-gray-400">
            Autonomous DAST & Multi-Engine Vulnerability Assessment
          </p>
        </div>

        {error && (
          <motion.div
            initial={{ opacity: 0, y: -8 }}
            animate={{ opacity: 1, y: 0 }}
            className="mb-4 rounded-xl border border-rose-500/40 bg-rose-500/10 p-3 text-xs text-rose-300 flex items-center gap-2"
          >
            <Lock size={14} className="text-rose-400 shrink-0" />
            <span>{error}</span>
          </motion.div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="mb-1.5 flex items-center justify-between text-xs font-semibold text-gray-300">
              <span className="flex items-center gap-1.5">
                <User size={13} className="text-blue-400" /> Username
              </span>
              <span className="font-mono text-[10px] text-gray-500">Default: admin</span>
            </label>
            <div className="relative">
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
                className="w-full rounded-xl border border-gray-700/60 bg-black/40 px-4 py-2.5 text-sm font-mono text-white outline-none transition-all focus:border-blue-500 focus:bg-black/60 focus:ring-2 focus:ring-blue-500/20"
                placeholder="admin"
              />
            </div>
          </div>

          <div>
            <label className="mb-1.5 flex items-center justify-between text-xs font-semibold text-gray-300">
              <span className="flex items-center gap-1.5">
                <Key size={13} className="text-purple-400" /> Password
              </span>
              <span className="font-mono text-[10px] text-gray-500">Default: admin</span>
            </label>
            <div className="relative">
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                className="w-full rounded-xl border border-gray-700/60 bg-black/40 px-4 py-2.5 text-sm font-mono text-white outline-none transition-all focus:border-purple-500 focus:bg-black/60 focus:ring-2 focus:ring-purple-500/20"
                placeholder="admin"
              />
            </div>
          </div>

          <div className="pt-2">
            <motion.button
              type="submit"
              disabled={loading}
              whileHover={{ scale: 1.02 }}
              whileTap={{ scale: 0.98 }}
              className="flex w-full items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-blue-600 via-indigo-600 to-purple-600 py-3 text-sm font-bold text-white shadow-[0_0_20px_rgba(59,130,246,0.3)] transition-all hover:from-blue-500 hover:to-purple-500 disabled:opacity-50 cursor-pointer"
            >
              {loading ? (
                <>
                  <Zap size={16} className="animate-spin text-cyan-300" />
                  Verifying Credentials...
                </>
              ) : (
                <>
                  <ShieldCheck size={16} />
                  Authorize & Access Dashboard
                  <ArrowRight size={14} />
                </>
              )}
            </motion.button>
          </div>
        </form>

        <div className="mt-6 border-t border-gray-800/80 pt-4 text-center">
          <div className="inline-flex items-center gap-1 text-[11px] font-mono text-gray-500">
            <Lock size={11} className="text-emerald-400" />
            SecOps Clearance Tier 3 • End-to-End Encrypted Session
          </div>
        </div>
      </motion.div>
    </div>
  );
}
