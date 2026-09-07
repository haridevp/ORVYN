import { motion } from "framer-motion";

interface Stat {
  label: string;
  value: React.ReactNode;
  note?: string;
  noteColor?: string;
  icon: React.ReactNode;
  iconColor?: string;
}

export function StatRow({ stats }: { stats: Stat[] }) {
  return (
    <div className="grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-5">
      {stats.map((s, i) => (
        <motion.div
          key={s.label}
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: i * 0.1, type: "spring", stiffness: 100 }}
          whileHover={{ y: -5, scale: 1.02 }}
          className="group relative overflow-hidden rounded-2xl glass-panel p-5 transition-all hover:shadow-[var(--shadow-glow)] hover:border-white/20"
        >
          {/* Subtle gradient overlay */}
          <div className="absolute inset-0 bg-gradient-to-br from-white/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity" />
          
          <div className="relative z-10 flex items-center gap-3">
            <span
              className="flex h-8 w-8 items-center justify-center rounded-lg shadow-inner transition-transform group-hover:scale-110"
              style={{ color: s.iconColor ?? "var(--text-muted)", backgroundColor: `${s.iconColor ?? "var(--text-muted)"}2a` }}
            >
              {s.icon}
            </span>
            <p className="text-xs font-bold tracking-wide uppercase text-[var(--text-muted)]">{s.label}</p>
          </div>
          <div className="relative z-10 mt-4 flex items-baseline gap-2">
            <p className="text-3xl font-black tabular-nums tracking-tight text-white drop-shadow-md">
              {s.value}
            </p>
            {s.note && (
              <span className="text-xs font-bold uppercase tracking-wider" style={{ color: s.noteColor ?? "var(--text-muted)" }}>
                {s.note}
              </span>
            )}
          </div>
        </motion.div>
      ))}
    </div>
  );
}
