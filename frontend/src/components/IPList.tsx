import { motion } from 'framer-motion';
import { Wifi } from 'lucide-react';

interface IPListProps {
  ips: [string, number][];
}

export function IPList({ ips }: IPListProps) {
  if (!ips.length) return null;

  return (
    <div className="glass-card p-4">
      <h3 className="font-sans font-semibold text-foreground mb-4 flex items-center gap-2">
        <Wifi className="w-4 h-4 text-primary" />
        Top Suspicious IPs
      </h3>
      <div className="space-y-2">
        {ips.map(([ip, count], index) => (
          <motion.div
            key={ip}
            initial={{ opacity: 0, x: -10 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: index * 0.05, duration: 0.2 }}
            className="flex items-center justify-between p-3 rounded-lg bg-muted/50 border border-border/30 hover:border-primary/30 transition-colors"
          >
            <div className="flex items-center gap-3">
              <span className="text-xs text-muted-foreground w-6">#{index + 1}</span>
              <code className="text-primary font-mono">{ip}</code>
            </div>
            <span className="text-sm text-muted-foreground">
              {count} {count === 1 ? 'event' : 'events'}
            </span>
          </motion.div>
        ))}
      </div>
    </div>
  );
}
