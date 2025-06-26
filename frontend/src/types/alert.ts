export interface Alert {
  id: string;
  title: string;
  message: string;
  severity: 'high' | 'medium' | 'low';
  timestamp: string;
  deviceId?: string;
  resolved?: boolean;
} 