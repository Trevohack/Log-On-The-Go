import { motion } from 'framer-motion';
import { Shield, ShieldAlert, ShieldX } from 'lucide-react';

interface RiskBadgeProps {
  level: 'LOW' | 'MEDIUM' | 'HIGH';
  size?: 'sm' | 'lg';
}

const riskConfig = {
  LOW: {
    icon: Shield,
    className: 'risk-low',
    label: 'LOW RISK',
  },
  MEDIUM: {
    icon: ShieldAlert,
    className: 'risk-medium',
    label: 'MEDIUM RISK',
  },
  HIGH: {
    icon: ShieldX,
    className: 'risk-high',
    label: 'HIGH RISK',
  },
};

export function RiskBadge({ level, size = 'sm' }: RiskBadgeProps) {
  const config = riskConfig[level];
  const Icon = config.icon;

  if (size === 'lg') {
    return (
      <motion.div
        initial={{ scale: 0.8, opacity: 0 }}
        animate={{ scale: 1, opacity: 1 }}
        className={`${config.className} p-6 rounded-xl border-2 text-center`}
      >
        <Icon className="w-12 h-12 mx-auto mb-2" />
        <div className="text-2xl font-bold font-sans">{config.label}</div>
      </motion.div>
    );
  }

  return (
    <motion.span
      initial={{ scale: 0.8, opacity: 0 }}
      animate={{ scale: 1, opacity: 1 }}
      className={`${config.className} px-3 py-1 rounded-full border text-xs font-bold inline-flex items-center gap-1`}
    >
      <Icon className="w-3 h-3" />
      {level}
    </motion.span>
  );
}
