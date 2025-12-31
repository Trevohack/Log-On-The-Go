import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import { Shield, Terminal } from 'lucide-react';
import { FileUpload } from '@/components/FileUpload';
import { TerminalLoader } from '@/components/TerminalLoader';
import { analyzePath, uploadFile, AnalysisReport } from '@/lib/api';
import { toast } from 'sonner';


const SERV_LOG_PATHS = [
  '<path>',
  '<path>', 
]; 

const Index = () => {
  const navigate = useNavigate();
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  
  const [activeTab, setActiveTab] = useState<'upload' | 'path' | 'serv'>('upload');
  
  const [servAuth, setServAuth] = useState(false);
  const [servUser, setServUser] = useState('');
  const [servPass, setServPass] = useState('');
  const [servError, setServError] = useState<string | null>(null);

  const handleAnalysis = async (analyzeFunc: () => Promise<AnalysisReport>) => {
    setIsLoading(true);
    setError(null);

    try {
      const report = await analyzeFunc();
      navigate('/analysis', { state: { report } });
      toast.success('Analysis complete');
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Analysis failed';
      setError(message);
      toast.error(message);
    } finally {
      setIsLoading(false);
    }
  };

  const handleFileUpload = (file: File) => {
    handleAnalysis(() => uploadFile(file));
  };

  const handlePathSubmit = (path: string) => {
    handleAnalysis(() => analyzePath(path));
  };

  const handleServLogin = async () => {
    setServError(null);

    if (!servUser || !servPass) {
      setServError('Missing credentials');
      return;
    }

    try {
      const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || '/api').replace(/\/$/, '');
      const response = await fetch(`${API_BASE_URL}/serv/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: servUser, password: servPass })
      });

      if (!response.ok) {
        const error = await response.json().catch(() => ({ detail: 'Authentication failed' }));
        setServError(error.detail || 'Invalid credentials');
        return;
      }

      const data = await response.json();
      if (data.ok) {
        setServAuth(true);
        toast.success('SERV access granted');
      } else {
        setServError('Invalid credentials');
      }
    } catch (err) {
      setServError('Connection error');
      console.error('SERV login error:', err);
    }
  };

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

      <div className="relative z-20 container mx-auto px-4 py-12">
        <motion.header
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
          className="text-center mb-12"
        >
          <div className="flex items-center justify-center gap-3 mb-4">
            <motion.div
              animate={{ rotate: [0, 360] }}
              transition={{ duration: 20, repeat: Infinity, ease: 'linear' }}
              className="p-3 rounded-xl bg-primary/10 border border-primary/30"
            >
              <Shield className="w-8 h-8 text-primary" />
            </motion.div>
          </div>
          <h1 className="text-4xl md:text-5xl font-sans font-bold text-foreground mb-3 glow-text">
            Log<span className="text-primary">On The Go</span>
          </h1>
          <p className="text-muted-foreground max-w-md mx-auto">
            Advanced security log analysis
            Detect threats, identify patterns, protect your systems.
          </p>
          
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.5 }}
            className="mt-6 inline-flex items-center gap-2 px-4 py-2 rounded-full bg-muted/50 border border-border/50"
          >
            <Terminal className="w-4 h-4 text-primary" />
            <code className="text-sm text-muted-foreground">
              <span className="text-primary">$</span> analyze --security-scan
              <span className="terminal-cursor ml-1">█</span>
            </code>
          </motion.div>
        </motion.header>

        <main className="max-w-3xl mx-auto">
          {isLoading ? (
            <TerminalLoader />
          ) : (
            <>
              <div className="glass-card p-4 mb-4">
                <div className="flex gap-2 justify-center">
                  {(['upload', 'path', 'serv'] as const).map(tab => (
                    <button
                      key={tab}
                      onClick={() => setActiveTab(tab)}
                      className={`px-4 py-2 rounded-md text-sm font-mono transition-all duration-200
                        ${activeTab === tab
                          ? 'bg-primary text-primary-foreground shadow-lg'
                          : 'bg-muted/40 text-muted-foreground hover:bg-muted'
                        }`}
                    >
                      {tab.toUpperCase()}
                    </button>
                  ))}
                </div>
              </div>

              {activeTab !== 'serv' && (
                <FileUpload
                  onUpload={handleFileUpload}
                  onPathSubmit={handlePathSubmit}
                  isLoading={isLoading}
                />
              )}

              {activeTab === 'serv' && (
                <motion.div
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  className="glass-card p-6 space-y-4"
                >
                  {!servAuth ? (
                    <>
                      <h3 className="text-center font-mono text-sm text-primary mb-4">
                        LOTG Serv Access
                      </h3>

                      <input
                        placeholder="Username"
                        value={servUser}
                        onChange={e => setServUser(e.target.value)}
                        onKeyDown={e => e.key === 'Enter' && handleServLogin()}
                        className="w-full bg-muted/40 border border-border rounded px-3 py-2 text-sm font-mono focus:outline-none focus:border-primary transition-colors"
                      />

                      <input
                        type="password"
                        placeholder="Password"
                        value={servPass}
                        onChange={e => setServPass(e.target.value)}
                        onKeyDown={e => e.key === 'Enter' && handleServLogin()}
                        className="w-full bg-muted/40 border border-border rounded px-3 py-2 text-sm font-mono focus:outline-none focus:border-primary transition-colors"
                      />

                      {servError && (
                        <p className="text-xs text-destructive text-center font-mono">
                          {servError}
                        </p>
                      )}

                      <button
                        onClick={handleServLogin}
                        className="w-full bg-primary text-primary-foreground py-2 rounded-md text-sm font-mono hover:opacity-90 transition-opacity"
                      >
                        Authenticate
                      </button>
                    </>
                  ) : (
                    <>
                      <h3 className="text-sm font-mono text-primary mb-3">
                        Configured Server Logs
                      </h3>

                      <div className="space-y-2">
                        {SERV_LOG_PATHS.map(path => (
                          <button
                            key={path}
                            onClick={() => handlePathSubmit(path)}
                            className="w-full text-left px-3 py-2 rounded bg-muted/40 hover:bg-muted border border-border text-sm font-mono transition-colors group"
                          >
                            <span className="text-primary group-hover:text-primary/80">→</span> {path}
                          </button>
                        ))}
                      </div>

                      <button
                        onClick={() => {
                          setServAuth(false);
                          setServUser('');
                          setServPass('');
                          toast.info('Logged out from SERV');
                        }}
                        className="w-full mt-4 py-2 rounded-md text-xs font-mono text-muted-foreground hover:text-foreground border border-border/50 hover:border-border transition-colors"
                      >
                        Logout
                      </button>
                    </>
                  )}
                </motion.div>
              )}

              {error && (
                <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="mt-4 p-4 rounded-lg bg-destructive/10 border border-destructive/30 text-destructive text-center"> 
                  <p className="font-mono text-sm">{error}</p>
                </motion.div>
              )} 

              <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.3 }} className="mt-8 grid grid-cols-1 md:grid-cols-3 gap-4"> 
                {[
                  { title: 'Linux Auth Logs', desc: 'SSH, PAM, sudo events' },
                  { title: 'Apache Access', desc: 'Web server logs' },
                  { title: 'Custom Formats', desc: 'Auto-detection' },
                ].map((item, i) => (
                  <div key={i} className="glass-card p-4 text-center">
                    <h3 className="font-sans font-medium text-foreground text-sm">{item.title}</h3>
                    <p className="text-xs text-muted-foreground mt-1">{item.desc}</p>
                  </div>
                ))}
              </motion.div>
            </>
          )}
        </main>

        <motion.footer initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.6 }} className="mt-16 text-center text-xs text-muted-foreground"> 
          <code>v1.0.0 • LOTG | Log On The Go</code>
        </motion.footer>
      </div>
    </div>
  );
};

export default Index; 
