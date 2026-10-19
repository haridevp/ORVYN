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
    <div className="relative flex min-h-screen w-full items-center justify-center bg-[#07080c] px-4 font-sans text-neutral-200">
      <div className="enterprise-panel w-full max-w-sm p-6 space-y-6 bg-[#0c0d12] border border-neutral-800 rounded-2xl shadow-2xl">
        <div className="flex flex-col items-center text-center">
          <div className="flex h-11 w-11 items-center justify-center rounded-xl border border-neutral-800 bg-neutral-900 text-purple-400 mb-3">
            <ShieldAlert size={22} />
          </div>

          <div className="inline-flex items-center gap-1.5 rounded-full border border-neutral-800 bg-neutral-900/80 px-2.5 py-0.5 text-[10px] font-mono uppercase tracking-wider text-neutral-400 mb-2">
            Console Authentication
          </div>

          <h1 className="text-xl font-bold tracking-tight text-white font-mono">
            ORVYN
          </h1>
          <p className="mt-1 text-xs text-neutral-400">
            Offensive Risk and Vulnerability Intelligence Network
          </p>
        </div>

        {error && (
          <div className="rounded-xl border border-rose-500/30 bg-rose-500/10 p-2.5 text-xs text-rose-300 flex items-center gap-2">
            <Lock size={13} className="text-rose-400 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-3.5">
          <div className="space-y-1">
            <label className="flex items-center justify-between text-xs font-medium text-neutral-300">
              <span className="flex items-center gap-1.5">
                <User size={12} className="text-neutral-400" /> Username
              </span>
              <span className="font-mono text-[10px] text-neutral-500">Default: admin</span>
            </label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
              className="w-full rounded-xl border border-neutral-800 bg-black/60 px-3 py-2 text-xs font-mono text-white outline-none transition-colors focus:border-white"
              placeholder="admin"
            />
          </div>

          <div className="space-y-1">
            <label className="flex items-center justify-between text-xs font-medium text-neutral-300">
              <span className="flex items-center gap-1.5">
                <Key size={12} className="text-neutral-400" /> Password
              </span>
              <span className="font-mono text-[10px] text-neutral-500">Default: admin</span>
            </label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              className="w-full rounded-xl border border-neutral-800 bg-black/60 px-3 py-2 text-xs font-mono text-white outline-none transition-colors focus:border-white"
              placeholder="admin"
            />
          </div>

          <div className="pt-2">
            <button
              type="submit"
              disabled={loading}
              className="flex w-full items-center justify-center gap-2 rounded-full bg-white hover:bg-neutral-200 py-2.5 text-xs font-bold text-black transition-colors disabled:opacity-50 cursor-pointer shadow-lg"
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

        <div className="border-t border-neutral-800/80 pt-3 text-center">
          <div className="inline-flex items-center gap-1.5 text-[10px] font-mono text-neutral-500">
            <Lock size={11} className="text-emerald-400" />
            <span>Encrypted Session • Role: SecOps Admin</span>
          </div>
        </div>
      </div>
    </div>
  );
}
