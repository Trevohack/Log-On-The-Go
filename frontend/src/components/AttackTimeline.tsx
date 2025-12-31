import { motion } from 'framer-motion';
import { Clock, Globe, Activity, AlertCircle, CheckCircle, XCircle } from 'lucide-react';
import type { TimelineEvent } from '@/lib/api';

interface AttackTimelineProps {
  timeline: TimelineEvent[];
}

const statusConfig: Record<string, { icon: typeof CheckCircle; color: string }> = {
  '200': { icon: CheckCircle, color: 'text-success' },
  '201': { icon: CheckCircle, color: 'text-success' },
  'SUCCESS': { icon: CheckCircle, color: 'text-success' },
  '401': { icon: XCircle, color: 'text-warning' },
  '403': { icon: XCircle, color: 'text-destructive' },
  '404': { icon: AlertCircle, color: 'text-muted-foreground' },
  '500': { icon: AlertCircle, color: 'text-destructive' },
  'FAILED': { icon: XCircle, color: 'text-destructive' },
};

export function AttackTimeline({ timeline }: AttackTimelineProps) {
  if (!timeline || timeline.length === 0) {
    return (
      <div className="glass-card p-8 text-center">
        <p className="text-muted-foreground">No timeline events recorded</p>
      </div>
    );
  }

  return (
    <div className="space-y-2">
      <div className="flex items-center gap-2 mb-4">
        <Clock className="w-4 h-4 text-primary" />
        <h2 className="font-sans font-semibold text-foreground">Attack Timeline</h2>
        <span className="px-2 py-0.5 rounded-full bg-primary/20 text-primary text-xs">
          {timeline.length} events
        </span>
      </div>

      <div className="glass-card p-4 max-h-[400px] overflow-y-auto custom-scrollbar">
        <div className="relative">
          {/* Timeline line */}
          <div className="absolute left-[19px] top-0 bottom-0 w-px bg-border" />

          <div className="space-y-3">
            {timeline.map((event, index) => {
              const config = statusConfig[event.status] || { icon: Activity, color: 'text-muted-foreground' };
              const Icon = config.icon;

              return (
                <motion.div
                  key={index}
                  initial={{ opacity: 0, x: -10 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: index * 0.02, duration: 0.2 }}
                  className="relative flex items-start gap-4 pl-10"
                >
                  {/* Timeline dot */}
                  <div className={`absolute left-[15px] top-1 w-2 h-2 rounded-full ${
                    event.status === 'FAILED' || event.status === '403' 
                      ? 'bg-destructive' 
                      : event.status === '200' || event.status === 'SUCCESS'
                      ? 'bg-success'
                      : 'bg-muted-foreground'
                  }`} />

                  <div className="flex-1 min-w-0 p-3 rounded-lg bg-muted/30 border border-border/50 hover:border-primary/30 transition-colors">
                    <div className="flex items-start justify-between gap-2">
                      <div className="flex items-center gap-2 min-w-0">
                        <Globe className="w-3.5 h-3.5 text-primary shrink-0" />
                        <span className="font-mono text-sm text-primary truncate">{event.ip}</span>
                      </div>
                      <div className="flex items-center gap-1.5 shrink-0">
                        <Icon className={`w-3.5 h-3.5 ${config.color}`} />
                        <span className={`text-xs font-mono ${config.color}`}>{event.status}</span>
                      </div>
                    </div>

                    <p className="text-xs text-muted-foreground font-mono mt-2 truncate" title={event.action}>
                      {event.action}
                    </p>

                    {event.time && event.time !== 'None' && (
                      <p className="text-xs text-muted-foreground/70 mt-1">
                        {event.time}
                      </p>
                    )}
                  </div>
                </motion.div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
}
