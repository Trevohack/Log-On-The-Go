import { useLocation, useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import { ArrowLeft, FileText, BarChart3, Users, AlertTriangle, Skull } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { RiskMeter } from '@/components/RiskMeter';
import { FindingCard } from '@/components/FindingCard';
import { StatsCard } from '@/components/StatsCard';
import { IPList } from '@/components/IPList';
import { AttackTimeline } from '@/components/AttackTimeline';
import type { AnalysisReport } from '@/lib/api';
import { useEffect } from 'react';

const Analysis = () => {
  const location = useLocation();
  const navigate = useNavigate();
  const report = location.state?.report as AnalysisReport | undefined;

  useEffect(() => {
    if (!report) {
      navigate('/');
    }
  }, [report, navigate]);

  if (!report) {
    return null;
  }

  return (
    <div className="min-h-screen bg-background relative overflow-hidden">
      <div className="fixed inset-0 scanline pointer-events-none z-10" />
      
      <div 
        className="fixed inset-0 opacity-5"
        style={{
          backgroundImage: `
            linear-gradient(to right, hsl(var(--primary)) 1px, transparent 1px),
            linear-gradient(to bottom, hsl(var(--primary)) 1px, transparent 1px)
          `,
          backgroundSize: '40px 40px',
        }}
      />

      <div className="relative z-20 container mx-auto px-4 py-8">
        <motion.header
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          className="flex items-center justify-between mb-8"
        >
          <Button 
            variant="ghost" 
            onClick={() => navigate('/')}
            className="gap-2 text-muted-foreground hover:text-foreground"
          >
            <ArrowLeft className="w-4 h-4" />
            Back
          </Button>
          <div className="text-right">
            <p className="text-xs text-muted-foreground uppercase tracking-wider">Log Type</p>
            <p className="text-primary font-mono">{report.log_type}</p>
          </div>
        </motion.header>

        <motion.section
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ delay: 0.1 }}
          className="mb-8"
        >
          <div className="max-w-md mx-auto">
            <RiskMeter score={report.risk_score} level={report.risk_level} />
          </div>
        </motion.section>

        <motion.section initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }} className="mb-8"> 
          <div className="glass-card p-6 max-w-3xl mx-auto">
            <div className="flex items-start gap-3">
              <div className="p-2 rounded-lg bg-primary/10 border border-primary/30">
                <FileText className="w-5 h-5 text-primary" />
              </div>
              <div>
                <h2 className="font-sans font-semibold text-foreground mb-1">Analysis Summary</h2>
                <p className="text-muted-foreground">{report.summary}</p>
              </div>
            </div>
          </div>
        </motion.section>

        <motion.section initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.3 }} className="mb-8"> 
          <h2 className="font-sans font-semibold text-foreground mb-4 flex items-center gap-2">
            <BarChart3 className="w-4 h-4 text-primary" />
            Statistics
          </h2>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <StatsCard 
              title="Total Events" 
              value={report.statistics.total_events} 
              icon={FileText} 
              index={0} 
            />
            <StatsCard 
              title="Unique IPs" 
              value={report.statistics.unique_ips} 
              icon={Users} 
              index={1} 
            />
            <StatsCard 
              title="Attackers" 
              value={report.statistics.attackers} 
              icon={Skull} 
              index={2} 
            />
            <StatsCard 
              title="Findings" 
              value={report.findings.length} 
              icon={AlertTriangle} 
              index={3} 
            />
          </div>
        </motion.section>

        {report.timeline && report.timeline.length > 0 && (
          <motion.section initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.35 }} className="mb-8"> 
            <AttackTimeline timeline={report.timeline} />
          </motion.section>
        )}

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          <motion.section initial={{ opacity: 0, x: -20 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: 0.4 }}> 
            <h2 className="font-sans font-semibold text-foreground mb-4 flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-warning" />
              Security Findings
              {report.findings.length > 0 && (
                <span className="px-2 py-0.5 rounded-full bg-warning/20 text-warning text-xs">
                  {report.findings.length}
                </span>
              )}
            </h2>
            {report.findings.length > 0 ? (
              <div className="space-y-3 max-h-[600px] overflow-y-auto custom-scrollbar pr-2">
                {report.findings.map((finding, index) => (
                  <FindingCard key={index} finding={finding} index={index} />
                ))}
              </div>
            ) : (
              <div className="glass-card p-8 text-center">
                <p className="text-muted-foreground">No suspicious findings detected</p>
              </div>
            )}
          </motion.section>


          <motion.section initial={{ opacity: 0, x: 20 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: 0.5 }}> 
            <IPList ips={report.top_suspicious_ips} />
          </motion.section>
        </div> 

        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.6 }} className="mt-12 text-center"> 
          <Button onClick={() => navigate('/')} size="lg" className="gap-2">
            <FileText className="w-4 h-4" />
            Analyze Another Log
          </Button>
        </motion.div>
      </div>
    </div>
  );
};

export default Analysis;
