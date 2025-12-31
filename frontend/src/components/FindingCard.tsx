import { motion } from 'framer-motion';
import { AlertTriangle, Skull, Bug, Link2, Search, Key, Shield, Upload } from 'lucide-react';
import type { Finding } from '@/lib/api';
import { useState } from 'react';

interface FindingCardProps {
  finding: Finding;
  index: number;
}

const typeConfig: Record<string, { icon: typeof AlertTriangle; label: string }> = {
  brute_force: { icon: Skull, label: 'Brute Force Attack' },
  attack_chain_detected: { icon: Link2, label: 'Attack Chain Detected' },
  possible_compromise: { icon: Shield, label: 'Possible Compromise' },
  failed_login: { icon: AlertTriangle, label: 'Failed Login Attempts' },
  default: { icon: Bug, label: 'Suspicious Activity' },
};

const intentConfig: Record<string, { icon: typeof Search; color: string; label: string }> = {
  recon: { icon: Search, color: 'bg-blue-500/20 text-blue-400 border-blue-500/30', label: 'Recon' },
  auth_attack: { icon: Key, color: 'bg-orange-500/20 text-orange-400 border-orange-500/30', label: 'Auth Attack' },
  admin_probe: { icon: Shield, color: 'bg-purple-500/20 text-purple-400 border-purple-500/30', label: 'Admin Probe' },
  exploit: { icon: Bug, color: 'bg-red-500/20 text-red-400 border-red-500/30', label: 'Exploit' },
  persistence: { icon: Upload, color: 'bg-pink-500/20 text-pink-400 border-pink-500/30', label: 'Persistence' },
  normal: { icon: AlertTriangle, color: 'bg-muted text-muted-foreground border-border', label: 'Normal' },
};

export function FindingCard({ finding, index }: FindingCardProps) {
  const [showEvidence, setShowEvidence] = useState(false);
  const config = typeConfig[finding.type] || typeConfig.default;
  const Icon = config.icon;
  
  const severityColor = finding.severity >= 8 
    ? 'text-destructive border-destructive/30 bg-destructive/10' 
    : finding.severity >= 5 
    ? 'text-warning border-warning/30 bg-warning/10'
    : 'text-success border-success/30 bg-success/10';

  const confidencePercent = Math.round((finding.confidence || 0) * 100);

  return (
    <motion.div
      initial={{ opacity: 0, x: -20 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ delay: index * 0.1, duration: 0.3 }}
      className="glass-card-hover p-4"
    >
      <div className="flex items-start justify-between gap-4">
        <div className="flex items-start gap-3">
          <div className={`p-2 rounded-lg border ${severityColor}`}>
            <Icon className="w-5 h-5" />
          </div>
          <div>
            <h4 className="font-sans font-medium text-foreground">{config.label}</h4>
            <p className="text-sm text-muted-foreground font-mono mt-1">
              IP: <span className="text-primary">{finding.ip}</span>
            </p>
          </div>
        </div>
        <div className="text-right">
          <div className={`text-2xl font-bold ${
            finding.severity >= 8 ? 'text-destructive' : 
            finding.severity >= 5 ? 'text-warning' : 'text-success'
          }`}>
            {finding.severity}
          </div>
          <div className="text-xs text-muted-foreground">severity</div>
        </div>
      </div>

      {/* Intents */}
      {finding.intents && finding.intents.length > 0 && (
        <div className="mt-3 flex flex-wrap gap-2">
          {finding.intents.map((intent) => {
            const intentCfg = intentConfig[intent] || intentConfig.normal;
            const IntentIcon = intentCfg.icon;
            return (
              <motion.span
                key={intent}
                initial={{ opacity: 0, scale: 0.8 }}
                animate={{ opacity: 1, scale: 1 }}
                transition={{ delay: index * 0.1 + 0.2 }}
                className={`inline-flex items-center gap-1 px-2 py-1 rounded-full text-xs border ${intentCfg.color}`}
              >
                <IntentIcon className="w-3 h-3" />
                {intentCfg.label}
              </motion.span>
            );
          })}
        </div>
      )}

      {/* Severity & Confidence bars */}
      <div className="mt-3 space-y-2">
        <div className="flex items-center gap-2">
          <span className="text-xs text-muted-foreground w-20">Severity:</span>
          <div className="flex-1 h-2 bg-muted rounded-full overflow-hidden">
            <motion.div
              initial={{ width: 0 }}
              animate={{ width: `${finding.severity * 10}%` }}
              transition={{ delay: index * 0.1 + 0.3, duration: 0.5 }}
              className={`h-full rounded-full ${
                finding.severity >= 8 ? 'bg-destructive' : 
                finding.severity >= 5 ? 'bg-warning' : 'bg-success'
              }`}
            />
          </div>
          <span className={`text-xs font-bold w-10 text-right ${
            finding.severity >= 8 ? 'text-destructive' : 
            finding.severity >= 5 ? 'text-warning' : 'text-success'
          }`}>
            {finding.severity}/10
          </span>
        </div>

        {finding.confidence !== undefined && (
          <div className="flex items-center gap-2">
            <span className="text-xs text-muted-foreground w-20">Confidence:</span>
            <div className="flex-1 h-2 bg-muted rounded-full overflow-hidden">
              <motion.div
                initial={{ width: 0 }}
                animate={{ width: `${confidencePercent}%` }}
                transition={{ delay: index * 0.1 + 0.4, duration: 0.5 }}
                className="h-full rounded-full bg-primary"
              />
            </div>
            <span className="text-xs font-bold text-primary w-10 text-right">
              {confidencePercent}%
            </span>
          </div>
        )}
      </div>

      {/* Evidence toggle */}
      {finding.evidence && (
        <div className="mt-3">
          <button
            onClick={() => setShowEvidence(!showEvidence)}
            className="text-xs text-primary hover:text-primary/80 transition-colors flex items-center gap-1"
          >
            {showEvidence ? '▼' : '▶'} View Evidence
          </button>
          
          {showEvidence && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
              exit={{ opacity: 0, height: 0 }}
              className="mt-2 p-3 rounded-lg bg-muted/50 border border-border/50 max-h-40 overflow-auto"
            >
              {Array.isArray(finding.evidence) ? (
                <ul className="space-y-1">
                  {finding.evidence.map((e, i) => (
                    <li key={i} className="text-xs font-mono text-muted-foreground break-all">
                      {e}
                    </li>
                  ))}
                </ul>
              ) : (
                <div className="flex flex-wrap gap-2">
                  {Object.entries(finding.evidence).map(([key, val]) => (
                    <span key={key} className="text-xs font-mono px-2 py-1 rounded bg-background border border-border">
                      {key}: <span className="text-primary">{val}</span>
                    </span>
                  ))}
                </div>
              )}
            </motion.div>
          )}
        </div>
      )}

      {/* Attempts (if present) */}
      {finding.attempts && (
        <div className="mt-2 text-xs text-muted-foreground">
          <span className="text-foreground font-medium">{finding.attempts}</span> attempts detected
        </div>
      )}
    </motion.div>
  );
} 
