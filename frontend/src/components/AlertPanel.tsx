'use client';

import React, { useEffect, useState } from 'react';
import { Device } from '../types/device';

interface SecurityAlert {
  id: string;
  type: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  message: string;
  timestamp: string;
  details: Record<string, any>;
  resolved: boolean;
}

interface SystemStatus {
  cpu_usage: number;
  memory_usage: number;
  active_devices: number;
  security_alerts: number;
  quarantined_devices: number;
  blocked_devices: number;
}

interface AlertPanelProps {
  devices: Device[];
}

const AlertPanel: React.FC<AlertPanelProps> = ({ devices }) => {
  const [securityAlerts, setSecurityAlerts] = useState<SecurityAlert[]>([]);
  const [systemStatus, setSystemStatus] = useState<SystemStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [scanning, setScanning] = useState<string | null>(null);
  const [scanResults, setScanResults] = useState<Record<string, any>>({});

  const fetchSecurityAlerts = async () => {
    try {
      const response = await fetch('http://localhost:8000/api/security/alerts');
      if (response.ok) {
        const data = await response.json();
        setSecurityAlerts(data.alerts || []);
      } else {
        setError('Failed to fetch security alerts');
      }
    } catch (err) {
      setError('Error connecting to NetSentinel API');
      console.error('Alert fetch error:', err);
    }
  };

  const fetchSystemStatus = async () => {
    try {
      const response = await fetch('http://localhost:8000/api/system/status');
      if (response.ok) {
        const data = await response.json();
        setSystemStatus(data);
      }
    } catch (err) {
      console.error('System status fetch error:', err);
    }
  };

  useEffect(() => {
    const loadData = async () => {
      setLoading(true);
      await Promise.all([fetchSecurityAlerts(), fetchSystemStatus()]);
      setLoading(false);
    };

    loadData();

    // Set up polling for real-time updates
    const interval = setInterval(() => {
      fetchSecurityAlerts();
      fetchSystemStatus();
    }, 10000); // Update every 10 seconds

    return () => clearInterval(interval);
  }, []);

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case 'critical':
        return '🚨';
      case 'high':
        return '⚠️';
      case 'medium':
        return '⚡';
      case 'low':
        return 'ℹ️';
      default:
        return '📋';
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical':
        return 'bg-red-900/50 border-red-600 text-red-100';
      case 'high':
        return 'bg-red-800/50 border-red-500 text-red-100';
      case 'medium':
        return 'bg-yellow-800/50 border-yellow-500 text-yellow-100';
      case 'low':
        return 'bg-blue-800/50 border-blue-500 text-blue-100';
      default:
        return 'bg-gray-800/50 border-gray-500 text-gray-100';
    }
  };

  const getAlertTypeTitle = (type: string) => {
    const titles: Record<string, string> = {
      'port_scan': 'Port Scan Detected',
      'connection_burst': 'Connection Burst',
      'data_exfiltration': 'Data Exfiltration',
      'dns_tunneling': 'DNS Tunneling',
      'arp_spoofing': 'ARP Spoofing',
      'rogue_device': 'Rogue Device',
      'anomalous_behavior': 'Anomalous Behavior',
      'beacon_pattern': 'Beacon Pattern',
      'brute_force': 'Brute Force Attack',
      'mitm_attack': 'Man-in-the-Middle',
      'test': 'Security Test'
    };
    return titles[type] || type.replace('_', ' ').toUpperCase();
  };

  const formatTimestamp = (timestamp: string) => {
    try {
      return new Date(timestamp).toLocaleString();
    } catch {
      return timestamp;
    }
  };

  const dismissAlert = async (alertId: string) => {
    // In a real implementation, you'd call an API to dismiss the alert
    setSecurityAlerts(prev => 
      prev.map(alert => 
        alert.id === alertId ? { ...alert, resolved: true } : alert
      )
    );
  };

  const scanDeviceVulnerabilities = async (deviceIp: string) => {
    setScanning(deviceIp);
    try {
      const response = await fetch('http://localhost:8000/api/security/scan-vulnerabilities', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip: deviceIp })
      });
      
      if (response.ok) {
        const result = await response.json();
        setScanResults(prev => ({ ...prev, [deviceIp]: result.vulnerability_scan }));
      } else {
        console.error('Vulnerability scan failed');
      }
    } catch (err) {
      console.error('Vulnerability scan error:', err);
    } finally {
      setScanning(null);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center py-8">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div>
        <span className="ml-2 text-gray-300">Loading security alerts...</span>
      </div>
    );
  }

  if (error) {
    return (
      <div className="text-center py-8">
        <div className="text-red-400 mb-2">⚠️ {error}</div>
        <button 
          onClick={() => window.location.reload()} 
          className="text-blue-400 hover:text-blue-300 underline"
        >
          Retry
        </button>
      </div>
    );
  }

  const activeAlerts = securityAlerts.filter(alert => !alert.resolved);
  const resolvedAlerts = securityAlerts.filter(alert => alert.resolved);

  return (
    <div className="space-y-6">
      {/* System Status Overview */}
      {systemStatus && (
        <div className="bg-gray-800/50 border border-gray-600 rounded-lg p-4">
          <h3 className="text-lg font-semibold mb-3 flex items-center">
            <span className="mr-2">📊</span>
            System Status
          </h3>
          <div className="grid grid-cols-2 md:grid-cols-3 gap-4 text-sm">
            <div className="flex justify-between">
              <span className="text-gray-400">Active Devices:</span>
              <span className="text-green-400">{systemStatus.active_devices}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-400">Security Alerts:</span>
              <span className={systemStatus.security_alerts > 0 ? "text-red-400" : "text-green-400"}>
                {systemStatus.security_alerts}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-400">Quarantined:</span>
              <span className={systemStatus.quarantined_devices > 0 ? "text-yellow-400" : "text-green-400"}>
                {systemStatus.quarantined_devices}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-400">Blocked:</span>
              <span className={systemStatus.blocked_devices > 0 ? "text-red-400" : "text-green-400"}>
                {systemStatus.blocked_devices}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-400">CPU Usage:</span>
              <span className={systemStatus.cpu_usage > 80 ? "text-red-400" : "text-green-400"}>
                {systemStatus.cpu_usage.toFixed(1)}%
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-400">Memory Usage:</span>
              <span className={systemStatus.memory_usage > 80 ? "text-red-400" : "text-green-400"}>
                {systemStatus.memory_usage.toFixed(1)}%
              </span>
            </div>
          </div>
        </div>
      )}

      {/* Quick Vulnerability Scanner */}
      <div className="bg-gray-800/50 border border-gray-600 rounded-lg p-4">
        <h3 className="text-lg font-semibold mb-3 flex items-center">
          <span className="mr-2">🔍</span>
          Vulnerability Scanner
        </h3>
        <div className="space-y-3">
          <p className="text-sm text-gray-400">Scan devices for security vulnerabilities</p>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
            {devices.slice(0, 6).map(device => (
              <button
                key={device.mac}
                onClick={() => scanDeviceVulnerabilities(device.ip)}
                disabled={scanning === device.ip}
                className="flex items-center justify-between p-2 text-sm bg-gray-700 hover:bg-gray-600 disabled:bg-gray-800 rounded border border-gray-600 transition-colors"
              >
                <span className="truncate">
                  {device.hostname || device.ip} 
                  {scanResults[device.ip] && (
                    <span className={`ml-2 text-xs ${
                      scanResults[device.ip].risk_score > 50 ? 'text-red-400' : 
                      scanResults[device.ip].risk_score > 20 ? 'text-yellow-400' : 'text-green-400'
                    }`}>
                      (Risk: {scanResults[device.ip].risk_score})
                    </span>
                  )}
                </span>
                {scanning === device.ip ? (
                  <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-blue-500"></div>
                ) : (
                  <span className="text-blue-400">Scan</span>
                )}
              </button>
            ))}
          </div>
          {devices.length > 6 && (
            <p className="text-xs text-gray-500">Showing first 6 devices. More available in Device List.</p>
          )}
        </div>
      </div>

      {/* Active Alerts */}
      <div>
        <h3 className="text-lg font-semibold mb-3 flex items-center">
          <span className="mr-2">🚨</span>
          Active Security Alerts ({activeAlerts.length})
        </h3>
        
        {activeAlerts.length === 0 ? (
          <div className="text-center py-8 text-gray-400 bg-gray-800/30 rounded-lg border border-gray-600">
            <div className="text-4xl mb-2">✅</div>
            <p>No active security alerts</p>
            <p className="text-sm">Your network appears to be secure</p>
          </div>
        ) : (
          <div className="space-y-3">
            {activeAlerts.map(alert => (
              <div
                key={alert.id}
                className={`p-4 rounded-lg border ${getSeverityColor(alert.severity)}`}
              >
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <div className="flex items-center mb-2">
                      <span className="text-xl mr-2">{getSeverityIcon(alert.severity)}</span>
                      <h4 className="text-lg font-semibold">
                        {getAlertTypeTitle(alert.type)}
                      </h4>
                      <span className={`ml-2 px-2 py-1 text-xs rounded-full font-semibold ${
                        alert.severity === 'critical' ? 'bg-red-600 text-white' :
                        alert.severity === 'high' ? 'bg-red-500 text-white' :
                        alert.severity === 'medium' ? 'bg-yellow-500 text-black' :
                        'bg-blue-500 text-white'
                      }`}>
                        {alert.severity.toUpperCase()}
                      </span>
                    </div>
                    <p className="text-sm mb-2">{alert.message}</p>
                    
                    {/* Alert Details */}
                    {alert.details && Object.keys(alert.details).length > 0 && (
                      <div className="mt-3 p-2 bg-black/20 rounded text-xs">
                        <strong>Details:</strong>
                        <ul className="mt-1 space-y-1">
                          {Object.entries(alert.details).map(([key, value]) => (
                            <li key={key} className="flex justify-between">
                              <span className="capitalize">{key.replace('_', ' ')}:</span>
                              <span className="font-mono">
                                {Array.isArray(value) ? value.join(', ') : String(value)}
                              </span>
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}
                    
                    <div className="mt-2 text-xs text-gray-400">
                      {formatTimestamp(alert.timestamp)}
                    </div>
                  </div>
                  
                  <button
                    onClick={() => dismissAlert(alert.id)}
                    className="ml-4 px-3 py-1 bg-gray-700 hover:bg-gray-600 text-xs rounded transition-colors"
                    title="Dismiss alert"
                  >
                    Dismiss
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Resolved Alerts (collapsible) */}
      {resolvedAlerts.length > 0 && (
        <details className="bg-gray-800/30 rounded-lg border border-gray-600">
          <summary className="p-4 cursor-pointer hover:bg-gray-700/30 transition-colors">
            <span className="font-semibold">📋 Resolved Alerts ({resolvedAlerts.length})</span>
          </summary>
          <div className="p-4 pt-0 space-y-2">
            {resolvedAlerts.slice(0, 10).map(alert => (
              <div
                key={alert.id}
                className="p-3 rounded border border-gray-600 bg-gray-700/30 opacity-75"
              >
                <div className="flex items-center justify-between">
                  <div>
                    <span className="text-sm font-medium">{getAlertTypeTitle(alert.type)}</span>
                    <p className="text-xs text-gray-400 mt-1">{alert.message}</p>
                  </div>
                  <div className="text-xs text-gray-400">
                    {formatTimestamp(alert.timestamp)}
                  </div>
                </div>
              </div>
            ))}
            {resolvedAlerts.length > 10 && (
              <div className="text-center text-xs text-gray-400 pt-2">
                ... and {resolvedAlerts.length - 10} more resolved alerts
              </div>
            )}
          </div>
        </details>
      )}
    </div>
  );
};

export default AlertPanel; 