import { useState, useCallback } from 'react';
import { motion } from 'framer-motion';
import { Upload, FileText, Terminal, ArrowRight } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';

interface FileUploadProps {
  onUpload: (file: File) => void;
  onPathSubmit: (path: string) => void;
  isLoading: boolean;
}

export function FileUpload({ onUpload, onPathSubmit, isLoading }: FileUploadProps) {
  const [isDragging, setIsDragging] = useState(false);
  const [filePath, setFilePath] = useState('');
  const [mode, setMode] = useState<'upload' | 'path'>('upload');

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  }, []);

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
  }, []);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    const file = e.dataTransfer.files[0];
    if (file) onUpload(file);
  }, [onUpload]);

  const handleFileChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) onUpload(file);
  }, [onUpload]);

  const handlePathSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (filePath.trim()) {
      onPathSubmit(filePath.trim());
    }
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5 }}
      className="glass-card p-8 max-w-2xl mx-auto"
    >
      {/* Mode Toggle */}
      <div className="flex gap-2 mb-6">
        <Button
          variant={mode === 'upload' ? 'default' : 'outline'}
          onClick={() => setMode('upload')}
          className="flex-1"
          disabled={isLoading}
        >
          <Upload className="w-4 h-4 mr-2" />
          Upload File
        </Button>
        <Button
          variant={mode === 'path' ? 'default' : 'outline'}
          onClick={() => setMode('path')}
          className="flex-1"
          disabled={isLoading}
        >
          <Terminal className="w-4 h-4 mr-2" />
          File Path
        </Button>
      </div>

      {mode === 'upload' ? (
        <div
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onDrop={handleDrop}
          className={`drop-zone p-12 text-center cursor-pointer transition-all duration-300 ${
            isDragging ? 'active' : ''
          } ${isLoading ? 'opacity-50 pointer-events-none' : ''}`}
        >
          <input
            type="file"
            onChange={handleFileChange}
            className="hidden"
            id="file-upload"
            accept=".log,.txt"
            disabled={isLoading}
          />
          <label htmlFor="file-upload" className="cursor-pointer">
            <motion.div
              animate={isDragging ? { scale: 1.05 } : { scale: 1 }}
              className="flex flex-col items-center gap-4"
            >
              <div className="w-16 h-16 rounded-full bg-primary/10 flex items-center justify-center border border-primary/30">
                <FileText className="w-8 h-8 text-primary" />
              </div>
              <div>
                <p className="text-foreground font-sans font-medium mb-1">
                  {isDragging ? 'Drop file here...' : 'Drag & drop your log file'}
                </p>
                <p className="text-muted-foreground text-sm">
                  or click to browse • .log, .txt files
                </p>
              </div>
            </motion.div>
          </label>
        </div>
      ) : (
        <form onSubmit={handlePathSubmit} className="space-y-4">
          <div className="space-y-2">
            <label className="text-sm text-muted-foreground font-sans">
              Enter file path or URL
            </label>
            <div className="flex gap-2">
              <div className="flex-1 relative">
                <Terminal className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                <Input
                  type="text"
                  value={filePath}
                  onChange={(e) => setFilePath(e.target.value)}
                  placeholder="C:\logs\auth.log or /var/log/auth.log"
                  className="pl-10 bg-input border-border/50 focus:border-primary"
                  disabled={isLoading}
                />
              </div>
              <Button type="submit" disabled={!filePath.trim() || isLoading}>
                <ArrowRight className="w-4 h-4" />
              </Button>
            </div>
          </div>
          <p className="text-xs text-muted-foreground">
            Provide the full path to a log file on the server
          </p>
        </form>
      )}
    </motion.div>
  );
}
