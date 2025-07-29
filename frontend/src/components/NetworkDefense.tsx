import React, { useState, useEffect } from 'react';

interface NetworkDefenseProps {
  onDefenseAction?: (action: string, target: string) => void;
}

interface VulnerabilityResult {
  ip: string;
  ports: Array<{
    port: number;
    state: string;
    service: string;
  }>;
  os_info: string;
  risk_level: string;
  timestamp: string;
}

const NetworkDefense: React.FC<NetworkDefenseProps> = ({ onDefenseAction }) => {
  const [pingTarget, setPingTarget] = useState('');
  const [pingResult, setPingResult] = useState<any>(null);
  const [scanTarget, setScanTarget] = useState('');
  const [scanResult, setScanResult] = useState<VulnerabilityResult | null>(null);
  const [loading, setLoading] = useState<string | null>(null);
  const [deauthTarget, setDeauthTarget] = useState('');
  const [gatewayMac, setGatewayMac] = useState('');

  const performPing = async () => {
    if (!pingTarget) return;
    
    setLoading('ping');
    try {
      const response = await fetch('http://localhost:8000/api/security/ping', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip: pingTarget, count: 4 })
      });

      if (response.ok) {
        const data = await response.json();
        setPingResult(data.ping_result);
      } else {
        alert('Ping failed');
      }
    } catch (error) {
      console.error('Ping error:', error);
      alert('Ping error');
    } finally {
      setLoading(null);
    }
  };

  const performVulnerabilityScan = async () => {
    if (!scanTarget) return;
    
    setLoading('scan');
    try {
      const response = await fetch('http://localhost:8000/api/security/scan-vulnerabilities', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip: scanTarget })
      });

      if (response.ok) {
        const data = await response.json();
        setScanResult(data.vulnerability_scan);
      } else {
        alert('Vulnerability scan failed');
      }
    } catch (error) {
      console.error('Scan error:', error);
      alert('Scan error');
    } finally {
      setLoading(null);
    }
  };

  const performDeauth = async () => {
    if (!deauthTarget || !gatewayMac) {
      alert('Please provide both target MAC and gateway MAC');
      return;
    }
    
    if (!confirm('Are you sure you want to deauthenticate this device? This will disconnect it from the network.')) {
      return;
    }
    
    setLoading('deauth');
    try {
      const response = await fetch('http://localhost:8000/api/security/deauth', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          target_mac: deauthTarget, 
          gateway_mac: gatewayMac,
          interface: null // Auto-detect
        })
      });

      if (response.ok) {
        const data = await response.json();
        alert('Deauthentication attack launched');
        onDefenseAction?.('deauth', deauthTarget);
      } else {
        alert('Deauthentication failed');
      }
    } catch (error) {
      console.error('Deauth error:', error);
      alert('Deauth error');
    } finally {
      setLoading(null);
    }
  };

  return (
    <div className="space-y-6">
      {/* Network Ping Tool */}
      <div className="bg-gray-800/50 border border-gray-600 rounded-lg p-4">
        <h3 className="text-lg font-semibold mb-4 flex items-center">
          <span className="mr-2">🏓</span>
          Network Ping
        </h3>
        
        <div className="space-y-3">
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">
              Target IP Address
            </label>
            <div className="flex space-x-2">
              <input
                type="text"
                value={pingTarget}
                onChange={(e) => setPingTarget(e.target.value)}
                placeholder="192.168.1.1"
                className="flex-1 px-3 py-2 bg-gray-700 border border-gray-600 rounded text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
              <button
                onClick={performPing}
                disabled={!pingTarget || loading === 'ping'}
                className="px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 text-white rounded transition-colors"
              >
                {loading === 'ping' ? 'Pinging...' : 'Ping'}
              </button>
            </div>
          </div>
          
          {pingResult && (
            <div className="p-3 bg-gray-700/50 rounded border border-gray-600">
              <h4 className="font-semibold mb-2">Ping Results:</h4>
              <div className="text-sm space-y-1">
                <div>Success: {pingResult.success ? '✅ Yes' : '❌ No'}</div>
                <div>Packets: {pingResult.packets_sent || 0} sent, {pingResult.packets_received || 0} received</div>
                {pingResult.avg_time && (
                  <div>Average Time: {pingResult.avg_time.toFixed(2)}ms</div>
                )}
                {pingResult.packet_loss !== undefined && (
                  <div>Packet Loss: {pingResult.packet_loss}%</div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Vulnerability Scanner */}
      <div className="bg-gray-800/50 border border-gray-600 rounded-lg p-4">
        <h3 className="text-lg font-semibold mb-4 flex items-center">
          <span className="mr-2">🔍</span>
          Vulnerability Scanner
        </h3>
        
        <div className="space-y-3">
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">
              Target IP Address
            </label>
            <div className="flex space-x-2">
              <input
                type="text"
                value={scanTarget}
                onChange={(e) => setScanTarget(e.target.value)}
                placeholder="192.168.1.100"
                className="flex-1 px-3 py-2 bg-gray-700 border border-gray-600 rounded text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
              <button
                onClick={performVulnerabilityScan}
                disabled={!scanTarget || loading === 'scan'}
                className="px-4 py-2 bg-orange-600 hover:bg-orange-700 disabled:bg-gray-600 text-white rounded transition-colors"
              >
                {loading === 'scan' ? 'Scanning...' : 'Scan'}
              </button>
            </div>
          </div>
          
          <div className="text-xs text-gray-400">
            ⚠️ Only scan devices you own or have permission to test
          </div>
          
          {scanResult && (
            <div className="p-3 bg-gray-700/50 rounded border border-gray-600">
              <h4 className="font-semibold mb-2">Vulnerability Scan Results:</h4>
              <div className="text-sm space-y-2">
                <div>Target: {scanResult.ip}</div>
                <div>Risk Level: 
                  <span className={`ml-1 px-2 py-1 rounded text-xs ${
                    scanResult.risk_level === 'high' ? 'bg-red-600' :
                    scanResult.risk_level === 'medium' ? 'bg-yellow-600' :
                    'bg-green-600'
                  }`}>
                    {scanResult.risk_level?.toUpperCase()}
                  </span>
                </div>
                {scanResult.os_info && <div>OS: {scanResult.os_info}</div>}
                
                {scanResult.ports && scanResult.ports.length > 0 && (
                  <div>
                    <div className="font-medium mt-2 mb-1">Open Ports:</div>
                    <div className="space-y-1">
                      {scanResult.ports.slice(0, 10).map((port, index) => (
                        <div key={index} className="flex justify-between text-xs">
                          <span>{port.port}/{port.service || 'unknown'}</span>
                          <span className={port.state === 'open' ? 'text-red-400' : 'text-green-400'}>
                            {port.state}
                          </span>
                        </div>
                      ))}
                      {scanResult.ports.length > 10 && (
                        <div className="text-xs text-gray-400">
                          ... and {scanResult.ports.length - 10} more ports
                        </div>
                      )}
                    </div>
                  </div>
                )}
                
                <div className="text-xs text-gray-400 mt-2">
                  Scanned: {new Date(scanResult.timestamp).toLocaleString()}
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* WiFi Deauthentication */}
      <div className="bg-red-900/20 border border-red-600 rounded-lg p-4">
        <h3 className="text-lg font-semibold mb-4 flex items-center">
          <span className="mr-2">⚡</span>
          WiFi Deauthentication
          <span className="ml-2 px-2 py-1 text-xs bg-red-600 rounded">ADVANCED</span>
        </h3>
        
        <div className="space-y-3">
          <div className="text-sm text-red-300 bg-red-900/30 p-2 rounded">
            ⚠️ WARNING: This feature forcibly disconnects devices from WiFi networks. 
            Use only for legitimate security purposes and on networks you own.
          </div>
          
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">
              Target Device MAC
            </label>
            <input
              type="text"
              value={deauthTarget}
              onChange={(e) => setDeauthTarget(e.target.value)}
              placeholder="AA:BB:CC:DD:EE:FF"
              className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-red-500"
            />
          </div>
          
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">
              Gateway/Router MAC
            </label>
            <input
              type="text"
              value={gatewayMac}
              onChange={(e) => setGatewayMac(e.target.value)}
              placeholder="00:11:22:33:44:55"
              className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-red-500"
            />
          </div>
          
          <button
            onClick={performDeauth}
            disabled={!deauthTarget || !gatewayMac || loading === 'deauth'}
            className="w-full px-4 py-2 bg-red-600 hover:bg-red-700 disabled:bg-gray-600 text-white rounded transition-colors font-semibold"
          >
            {loading === 'deauth' ? 'Launching Deauth...' : '⚡ Launch Deauthentication Attack'}
          </button>
        </div>
      </div>

      {/* Quick Actions Summary */}
      <div className="bg-gray-800/50 border border-gray-600 rounded-lg p-4">
        <h3 className="text-lg font-semibold mb-4 flex items-center">
          <span className="mr-2">⚡</span>
          Defense Actions Summary
        </h3>
        
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
          <div className="p-3 bg-blue-900/30 border border-blue-600 rounded">
            <div className="font-semibold text-blue-300">🏓 Network Ping</div>
            <div className="text-xs text-gray-400 mt-1">
              Test connectivity and response times to network devices
            </div>
          </div>
          
          <div className="p-3 bg-orange-900/30 border border-orange-600 rounded">
            <div className="font-semibold text-orange-300">🔍 Vulnerability Scan</div>
            <div className="text-xs text-gray-400 mt-1">
              Identify open ports and potential security weaknesses
            </div>
          </div>
          
          <div className="p-3 bg-red-900/30 border border-red-600 rounded">
            <div className="font-semibold text-red-300">⚡ WiFi Deauth</div>
            <div className="text-xs text-gray-400 mt-1">
              Force disconnect malicious devices from WiFi networks
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default NetworkDefense;
