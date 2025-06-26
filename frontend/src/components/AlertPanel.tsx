'use client';

import React, { useEffect, useState } from 'react';
import { Device } from '../types/device';

interface Alert {
  id: string;
  title: string;
  message: string;
  severity: 'low' | 'medium' | 'high';
  timestamp: string;
  deviceId: string;
}

interface AlertPanelProps {
  devices: Device[];
}

const AlertPanel: React.FC<AlertPanelProps> = ({ devices }) => {
  const [alerts, setAlerts] = useState<Alert[]>([]);

  useEffect(() => {
    // Generate alerts based on suspicious devices
    const newAlerts: Alert[] = devices
      .filter(device => device.suspicious)
      .map(device => ({
        id: `${device.mac}-${Date.now()}`,
        title: 'Suspicious Activity',
        message: `Suspicious activity detected on ${device.hostname} (${device.ip})`,
        severity: 'high',
        timestamp: new Date().toISOString(),
        deviceId: device.mac
      }));

    if (newAlerts.length > 0) {
      setAlerts(prev => [...newAlerts, ...prev]);
    }
  }, [devices]);

  if (alerts.length === 0) {
    return (
      <div className="text-center py-8 text-gray-400">
        <p>No active alerts</p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {alerts.map(alert => (
        <div
          key={alert.id}
          className={`p-4 rounded-lg ${
            alert.severity === 'high'
              ? 'bg-red-900/50 border border-red-700'
              : alert.severity === 'medium'
              ? 'bg-yellow-900/50 border border-yellow-700'
              : 'bg-blue-900/50 border border-blue-700'
          }`}
        >
          <div className="flex items-start justify-between">
            <div>
              <h3 className="text-lg font-semibold">{alert.title}</h3>
              <p className="text-sm text-gray-300">{alert.message}</p>
            </div>
            <span
              className={`px-2 py-1 text-xs rounded ${
                alert.severity === 'high'
                  ? 'bg-red-700 text-red-100'
                  : alert.severity === 'medium'
                  ? 'bg-yellow-700 text-yellow-100'
                  : 'bg-blue-700 text-blue-100'
              }`}
            >
              {alert.severity}
            </span>
          </div>
          <div className="mt-2 text-xs text-gray-400">
            {new Date(alert.timestamp).toLocaleString()}
          </div>
        </div>
      ))}
    </div>
  );
};

export default AlertPanel; 