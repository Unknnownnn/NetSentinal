import React, { useState, useEffect } from 'react';

interface QuarantinedDevice {
  mac: string;
  reason: string;
  timestamp: string;
}

interface BlockedDevice {
  mac: string;
  ip?: string;
  reason: string;
  timestamp: string;
}

interface SecurityAction {
  type: 'quarantine' | 'release' | 'block' | 'whitelist' | 'blacklist';
  target: string;
  reason?: string;
}

interface SecurityDashboardProps {
  onAction?: (action: SecurityAction) => void;
}

const SecurityDashboard: React.FC<SecurityDashboardProps> = ({ onAction }) => {
  const [quarantinedDevices, setQuarantinedDevices] = useState<QuarantinedDevice[]>([]);
  const [blockedDevices, setBlockedDevices] = useState<BlockedDevice[]>([]);
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState<string | null>(null);

  const fetchSecurityData = async () => {
    try {
      const [quarantinedResponse, blockedResponse] = await Promise.all([
        fetch('http://localhost:8000/api/security/quarantined'),
        fetch('http://localhost:8000/api/security/blocked')
      ]);

      if (quarantinedResponse.ok) {
        const quarantinedData = await quarantinedResponse.json();
        setQuarantinedDevices(quarantinedData.quarantined_devices || []);
      }

      if (blockedResponse.ok) {
        const blockedData = await blockedResponse.json();
        setBlockedDevices(blockedData.blocked_devices || []);
      }
    } catch (error) {
      console.error('Error fetching security data:', error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchSecurityData();
    const interval = setInterval(fetchSecurityData, 15000); // Update every 15 seconds
    return () => clearInterval(interval);
  }, []);

  const handleSecurityAction = async (action: SecurityAction) => {
    setActionLoading(action.target);
    
    try {
      let endpoint = '';
      let body: any = {};

      switch (action.type) {
        case 'quarantine':
          endpoint = '/api/security/quarantine';
          body = { mac: action.target, reason: action.reason || 'Manual quarantine' };
          break;
        case 'release':
          endpoint = '/api/security/release';
          body = { mac: action.target };
          break;
        case 'block':
          endpoint = '/api/security/block';
          body = { target_mac: action.target, target_ip: action.target, method: 'arp' };
          break;
        case 'whitelist':
          endpoint = '/api/security/whitelist';
          body = { mac: action.target };
          break;
        case 'blacklist':
          endpoint = '/api/security/blacklist';
          body = { mac: action.target };
          break;
      }

      const response = await fetch(`http://localhost:8000${endpoint}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
      });

      if (response.ok) {
        await fetchSecurityData(); // Refresh data
        onAction?.(action);
      } else {
        alert(`Failed to ${action.type} device`);
      }
    } catch (error) {
      console.error(`Error performing ${action.type}:`, error);
      alert(`Error performing ${action.type}`);
    } finally {
      setActionLoading(null);
    }
  };

  const QuickActions = () => {
    const [targetDevice, setTargetDevice] = useState('');
    const [reason, setReason] = useState('');

    return (
      <div className="bg-gray-800/50 border border-gray-600 rounded-lg p-4">
        <h3 className="text-lg font-semibold mb-4 flex items-center">
          <span className="mr-2">⚡</span>
          Quick Security Actions
        </h3>
        
        <div className="space-y-3">
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">
              Target Device (MAC Address)
            </label>
            <input
              type="text"
              value={targetDevice}
              onChange={(e) => setTargetDevice(e.target.value)}
              placeholder="AA:BB:CC:DD:EE:FF"
              className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>
          
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">
              Reason (optional)
            </label>
            <input
              type="text"
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              placeholder="Security concern, policy violation, etc."
              className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>
          
          <div className="flex flex-wrap gap-2">
            <button
              onClick={() => targetDevice && handleSecurityAction({ 
                type: 'quarantine', 
                target: targetDevice, 
                reason 
              })}
              disabled={!targetDevice || actionLoading === targetDevice}
              className="px-3 py-2 bg-yellow-600 hover:bg-yellow-700 disabled:bg-gray-600 text-white text-sm rounded transition-colors"
            >
              🔒 Quarantine
            </button>
            
            <button
              onClick={() => targetDevice && handleSecurityAction({ 
                type: 'block', 
                target: targetDevice, 
                reason 
              })}
              disabled={!targetDevice || actionLoading === targetDevice}
              className="px-3 py-2 bg-red-600 hover:bg-red-700 disabled:bg-gray-600 text-white text-sm rounded transition-colors"
            >
              ⛔ Block
            </button>
            
            <button
              onClick={() => targetDevice && handleSecurityAction({ 
                type: 'whitelist', 
                target: targetDevice 
              })}
              disabled={!targetDevice || actionLoading === targetDevice}
              className="px-3 py-2 bg-green-600 hover:bg-green-700 disabled:bg-gray-600 text-white text-sm rounded transition-colors"
            >
              ✅ Whitelist
            </button>
            
            <button
              onClick={() => targetDevice && handleSecurityAction({ 
                type: 'blacklist', 
                target: targetDevice 
              })}
              disabled={!targetDevice || actionLoading === targetDevice}
              className="px-3 py-2 bg-red-800 hover:bg-red-900 disabled:bg-gray-600 text-white text-sm rounded transition-colors"
            >
              ❌ Blacklist
            </button>
          </div>
        </div>
      </div>
    );
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center py-8">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div>
        <span className="ml-2 text-gray-300">Loading security data...</span>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Quick Actions */}
      <QuickActions />

      {/* Quarantined Devices */}
      <div className="bg-gray-800/50 border border-gray-600 rounded-lg p-4">
        <h3 className="text-lg font-semibold mb-4 flex items-center">
          <span className="mr-2">🔒</span>
          Quarantined Devices ({quarantinedDevices.length})
        </h3>
        
        {quarantinedDevices.length === 0 ? (
          <div className="text-center py-4 text-gray-400">
            No devices are currently quarantined
          </div>
        ) : (
          <div className="space-y-2">
            {quarantinedDevices.map((device, index) => (
              <div key={index} className="flex items-center justify-between p-3 bg-yellow-900/30 border border-yellow-600 rounded">
                <div>
                  <div className="font-mono text-sm">{device.mac}</div>
                  <div className="text-xs text-gray-400">{device.reason}</div>
                  <div className="text-xs text-gray-500">
                    {new Date(device.timestamp).toLocaleString()}
                  </div>
                </div>
                <button
                  onClick={() => handleSecurityAction({ type: 'release', target: device.mac })}
                  disabled={actionLoading === device.mac}
                  className="px-3 py-1 bg-green-600 hover:bg-green-700 disabled:bg-gray-600 text-white text-xs rounded transition-colors"
                >
                  {actionLoading === device.mac ? 'Releasing...' : 'Release'}
                </button>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Blocked Devices */}
      <div className="bg-gray-800/50 border border-gray-600 rounded-lg p-4">
        <h3 className="text-lg font-semibold mb-4 flex items-center">
          <span className="mr-2">⛔</span>
          Blocked Devices ({blockedDevices.length})
        </h3>
        
        {blockedDevices.length === 0 ? (
          <div className="text-center py-4 text-gray-400">
            No devices are currently blocked
          </div>
        ) : (
          <div className="space-y-2">
            {blockedDevices.map((device, index) => (
              <div key={index} className="flex items-center justify-between p-3 bg-red-900/30 border border-red-600 rounded">
                <div>
                  <div className="font-mono text-sm">{device.mac}</div>
                  {device.ip && <div className="text-xs text-gray-300">IP: {device.ip}</div>}
                  <div className="text-xs text-gray-400">{device.reason}</div>
                  <div className="text-xs text-gray-500">
                    {new Date(device.timestamp).toLocaleString()}
                  </div>
                </div>
                <div className="flex space-x-2">
                  <button
                    onClick={() => handleSecurityAction({ type: 'release', target: device.mac })}
                    disabled={actionLoading === device.mac}
                    className="px-3 py-1 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 text-white text-xs rounded transition-colors"
                  >
                    {actionLoading === device.mac ? 'Unblocking...' : 'Unblock'}
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Security Testing */}
      <div className="bg-gray-800/50 border border-gray-600 rounded-lg p-4">
        <h3 className="text-lg font-semibold mb-4 flex items-center">
          <span className="mr-2">🧪</span>
          Security Testing
        </h3>
        
        <div className="space-y-3">
          <p className="text-sm text-gray-300">
            Test NetSentinel's security detection capabilities:
          </p>
          
          <div className="flex flex-wrap gap-2">
            <button
              onClick={async () => {
                try {
                  const response = await fetch('http://localhost:8000/api/security/test-alert', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                      type: 'test',
                      severity: 'medium',
                      message: 'Manual security test from dashboard',
                      details: { source: 'dashboard', timestamp: new Date().toISOString() }
                    })
                  });
                  
                  if (response.ok) {
                    alert('Test alert generated successfully!');
                  } else {
                    alert('Failed to generate test alert');
                  }
                } catch (error) {
                  alert('Error generating test alert');
                }
              }}
              className="px-3 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded transition-colors"
            >
              🚨 Generate Test Alert
            </button>
            
            <button
              onClick={() => {
                const mac = `AA:BB:CC:DD:EE:${Math.floor(Math.random() * 256).toString(16).padStart(2, '0')}`;
                handleSecurityAction({ 
                  type: 'quarantine', 
                  target: mac, 
                  reason: 'Security test - simulated threat device' 
                });
              }}
              className="px-3 py-2 bg-yellow-600 hover:bg-yellow-700 text-white text-sm rounded transition-colors"
            >
              🔒 Test Quarantine
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default SecurityDashboard;
