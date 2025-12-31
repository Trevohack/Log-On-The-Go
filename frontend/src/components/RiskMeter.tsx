import { motion } from 'framer-motion';
import { Gauge } from 'lucide-react';

interface RiskMeterProps {
  score: number;
  level: 'LOW' | 'MEDIUM' | 'HIGH';
}

export function RiskMeter({ score, level }: RiskMeterProps) {
  const levelConfig = {
    LOW: { color: 'text-success', bg: 'bg-success', glow: 'shadow-success/50' },
    MEDIUM: { color: 'text-warning', bg: 'bg-warning', glow: 'shadow-warning/50' },
    HIGH: { color: 'text-destructive', bg: 'bg-destructive', glow: 'shadow-destructive/50' },
  };

  const config = levelConfig[level];

  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.9 }}
      animate={{ opacity: 1, scale: 1 }}
      className="glass-card p-6"
    >
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <Gauge className={`w-5 h-5 ${config.color}`} />
          <span className="text-sm font-medium text-foreground">Risk Score</span>
        </div>
        <motion.span
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.3 }}
          className={`text-3xl font-bold font-mono ${config.color}`}
        >
          {score}
        </motion.span>
      </div>

      {/* Score bar */}
      <div className="relative h-3 bg-muted rounded-full overflow-hidden">
        <motion.div
          initial={{ width: 0 }}
          animate={{ width: `${Math.min(score, 100)}%` }}
          transition={{ delay: 0.2, duration: 0.8, ease: 'easeOut' }}
          className={`absolute inset-y-0 left-0 ${config.bg} rounded-full shadow-lg ${config.glow}`}
        />
        
        {/* Threshold markers */}
        <div className="absolute top-0 bottom-0 left-[40%] w-px bg-warning/50" />
        <div className="absolute top-0 bottom-0 left-[70%] w-px bg-destructive/50" />
      </div>

      <div className="flex justify-between mt-2 text-xs text-muted-foreground">
        <span>0</span>
        <span className="text-warning">40</span>
        <span className="text-destructive">70</span>
        <span>100</span>
      </div>

      {/* Risk level badge */}
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.5 }}
        className="mt-4 flex justify-center"
      >
        <div className={`inline-flex items-center gap-2 px-4 py-2 rounded-full border ${
          level === 'LOW' ? 'border-success/30 bg-success/10' :
          level === 'MEDIUM' ? 'border-warning/30 bg-warning/10' :
          'border-destructive/30 bg-destructive/10'
        }`}>
          <div className={`w-2 h-2 rounded-full ${config.bg} animate-pulse`} />
          <span className={`text-sm font-bold ${config.color}`}>
            {level} RISK
          </span>
        </div>
      </motion.div>
    </motion.div>
  );
}