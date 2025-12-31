
const DEFAULT_API_BASE_URL = import.meta.env.VITE_API_BASE_URL || '/api';
const API_BASE_URL = DEFAULT_API_BASE_URL.replace(/\/$/, '');

export interface TimelineEvent {
  time: string;
  ip: string;
  action: string;
  status: string;
}

export interface Finding {
  type: string;
  ip: string;
  attempts?: number;
  intents?: string[];
  severity: number;
  confidence: number;
  evidence?: string[] | Record<string, number>;
}

export interface AnalysisReport {
  log_type: string;
  risk_score: number;
  risk_level: 'LOW' | 'MEDIUM' | 'HIGH';
  summary: string;
  findings: Finding[];
  top_suspicious_ips: [string, number][];
  statistics: {
    total_events: number;
    unique_ips: number;
    attackers: number;
  };
  timeline: TimelineEvent[];
}

export async function analyzePath(filePath: string): Promise<AnalysisReport> {
  const pathParam = encodeURIComponent(filePath).replace(/%3A/g, ':');

  const response = await fetch(`${API_BASE_URL}/analyze/path?path=${pathParam}`, {
    method: 'POST',
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: 'Unknown error' }));
    throw new Error(error.detail || 'Failed to analyze file');
  }

  return response.json();
}

export async function uploadFile(file: File): Promise<AnalysisReport> {
  const formData = new FormData();
  formData.append('file', file);

  const response = await fetch(`${API_BASE_URL}/analyze/upload`, {
    method: 'POST',
    body: formData,
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: 'Unknown error' }));
    throw new Error(error.detail || 'Failed to upload file');
  }

  return response.json();
} 

