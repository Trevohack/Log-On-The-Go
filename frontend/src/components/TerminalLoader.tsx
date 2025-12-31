import { motion } from 'framer-motion';

const loadingLines = [
  '> Initializing security scan...',
  '> Parsing log entries...',
  '> Detecting log format...',
  '> Analyzing patterns...',
  '> Identifying threats...',
];

export function TerminalLoader() {
  return (
    <div className="glass-card p-8 max-w-lg mx-auto">
      <div className="flex items-center gap-2 mb-4 pb-4 border-b border-border/30">
        <div className="w-3 h-3 rounded-full bg-destructive" />
        <div className="w-3 h-3 rounded-full bg-warning" />
        <div className="w-3 h-3 rounded-full bg-success" />
        <span className="ml-2 text-muted-foreground text-sm">analysis.exe</span>
      </div>
      
      <div className="space-y-2 font-mono text-sm">
        {loadingLines.map((line, index) => (
          <motion.div
            key={index}
            initial={{ opacity: 0, x: -10 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: index * 0.4, duration: 0.3 }}
            className="text-primary"
          >
            {line}
            {index === loadingLines.length - 1 && (
              <motion.span
                initial={{ opacity: 0 }}
                animate={{ opacity: [0, 1, 0] }}
                transition={{ duration: 0.8, repeat: Infinity, delay: index * 0.4 + 0.3 }}
                className="ml-1"
              >
                █
              </motion.span>
            )}
          </motion.div>
        ))}
      </div>
      
      <motion.div
        className="mt-6 h-1 bg-muted rounded-full overflow-hidden"
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 1.5 }}
      >
        <motion.div
          className="h-full bg-primary"
          initial={{ width: '0%' }}
          animate={{ width: '100%' }}
          transition={{ duration: 2, delay: 1.5, ease: 'easeInOut' }}
        />
      </motion.div>
    </div>
  );
}
