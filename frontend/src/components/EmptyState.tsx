import { Crosshair } from "lucide-react";
import { motion } from "framer-motion";

export function EmptyState() {
  return (
    <motion.div 
      initial={{ opacity: 0, scale: 0.95 }}
      animate={{ opacity: 1, scale: 1 }}
      className="flex flex-col items-center gap-4 rounded-2xl border border-dashed border-gray-600/50 glass-panel px-6 py-20 text-center shadow-[0_0_30px_rgba(0,0,0,0.2)]"
    >
      <motion.div 
        animate={{ 
          scale: [1, 1.1, 1],
          boxShadow: [
            "0 0 0 rgba(59, 130, 246, 0)",
            "0 0 20px rgba(59, 130, 246, 0.5)",
            "0 0 0 rgba(59, 130, 246, 0)"
          ]
        }}
        transition={{ duration: 2, repeat: Infinity }}
        className="flex h-16 w-16 items-center justify-center rounded-full bg-blue-500/10 text-blue-400 border border-blue-500/20"
      >
        <Crosshair size={32} />
      </motion.div>
      <div className="flex flex-col items-center max-w-md">
        <h3 className="text-lg font-bold tracking-wide text-white">No active targets</h3>
        <p className="mt-2 text-sm text-gray-400 leading-relaxed">
          Enter a target URL and select your engines to initiate a multi-scanner sequence. 
          Vulnerabilities from Nuclei, OWASP ZAP, and Nikto will be automatically correlated.
        </p>
      </div>
    </motion.div>
  );
}
