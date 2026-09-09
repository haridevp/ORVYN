import { useState } from "react";
import { ShieldAlert, Lock, User, Key, ArrowRight, ShieldCheck } from "lucide-react";

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
    <div className="relative flex min-h-screen w-full items-center justify-center bg-[#080c14] px-4 font-sans text-slate-200">
      <div className="enterprise-panel w-full max-w-sm p-6 space-y-6">
        <div className="flex flex-col items-center text-center">
          <div className="flex h-11 w-11 items-center justify-center rounded-lg border border-slate-800 bg-slate-900 text-blue-400 mb-3">
            <ShieldAlert size={22} />
          </div>

          <div className="inline-flex items-center gap-1.5 rounded border border-slate-800 bg-slate-900 px-2 py-0.5 text-[10px] font-mono uppercase tracking-wider text-slate-400 mb-2">
            Console Authentication
          </div>

          <h1 className="text-xl font-bold tracking-tight text-white font-mono">
            ORVYN
          </h1>
          <p className="mt-1 text-xs text-slate-400">
            Offensive Risk and Vulnerability Intelligence Network
          </p>
        </div>

        {error && (
          <div className="rounded-lg border border-rose-500/30 bg-rose-500/10 p-2.5 text-xs text-rose-300 flex items-center gap-2">
            <Lock size={13} className="text-rose-400 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-3.5">
          <div className="space-y-1">
            <label className="flex items-center justify-between text-xs font-medium text-slate-300">
              <span className="flex items-center gap-1.5">
                <User size={12} className="text-slate-400" /> Username
              </span>
              <span className="font-mono text-[10px] text-slate-500">Default: admin</span>
            </label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
              className="w-full rounded-lg border border-slate-800 bg-slate-900/90 px-3 py-2 text-xs font-mono text-white outline-none transition-colors focus:border-blue-500"
              placeholder="admin"
            />
          </div>

          <div className="space-y-1">
            <label className="flex items-center justify-between text-xs font-medium text-slate-300">
              <span className="flex items-center gap-1.5">
                <Key size={12} className="text-slate-400" /> Password
              </span>
              <span className="font-mono text-[10px] text-slate-500">Default: admin</span>
            </label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              className="w-full rounded-lg border border-slate-800 bg-slate-900/90 px-3 py-2 text-xs font-mono text-white outline-none transition-colors focus:border-blue-500"
              placeholder="admin"
            />
          </div>

          <div className="pt-2">
            <button
              type="submit"
              disabled={loading}
              className="flex w-full items-center justify-center gap-2 rounded-lg bg-blue-600 hover:bg-blue-500 py-2.5 text-xs font-medium text-white transition-colors disabled:opacity-50 cursor-pointer shadow-xs"
            >
              {loading ? (
                <span>Authenticating...</span>
              ) : (
                <>
                  <ShieldCheck size={14} />
                  <span>Sign In to Platform</span>
                  <ArrowRight size={13} />
                </>
              )}
            </button>
          </div>
        </form>

        <div className="border-t border-slate-800/80 pt-3 text-center">
          <div className="inline-flex items-center gap-1.5 text-[10px] font-mono text-slate-500">
            <Lock size={11} className="text-emerald-400" />
            <span>Encrypted Session • Role: SecOps Admin</span>
          </div>
        </div>
      </div>
    </div>
  );
}
