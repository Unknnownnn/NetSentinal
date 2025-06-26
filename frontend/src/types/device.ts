export interface Port {
  port: number;
  service: string;
  state: string;
}

export interface Device {
  id: string;
  ip: string;
  mac: string;
  vendor: string;
  hostname: string;
  device_type: 'Computer' | 'Mobile Device' | 'Smart TV' | 'Gaming Console' | 'IoT Device' | 'Unknown';
  status: 'active' | 'inactive';
  suspicious: boolean;
  lastSeen: string;
  traffic: {
    packets: number;
    bytes: number;
  };
  ports: Array<{
    port: number;
    service: string;
    state: string;
  }>;
  activity?: Activity[];
}

export interface Activity {
  event: string;
  timestamp: string;
  details?: string;
} 