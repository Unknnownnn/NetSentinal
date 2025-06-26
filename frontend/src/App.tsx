import React, { useEffect, useState } from 'react';
import { Device } from './types/device';
import NetworkMap from './components/NetworkMap';
import DeviceList from './components/DeviceList';
import AlertPanel from './components/AlertPanel';
import wsClient from './utils/websocket';

function App() {
  const [devices, setDevices] = useState<Device[]>([]);
  const [isScanning, setIsScanning] = useState(false);
  const [isAutoScan, setIsAutoScan] = useState(true);
  const [isConnected, setIsConnected] = useState(false);

  useEffect(() => {
    // Set up WebSocket event handlers
    wsClient.on('connection', (data: { status: string }) => {
      setIsConnected(data.status === 'connected');
    });

    wsClient.on('network_update', (data: { data: Device[] }) => {
      setDevices(data.data);
    });

    wsClient.on('scan_start', () => {
      setIsScanning(true);
    });

    wsClient.on('scan_complete', () => {
      setIsScanning(false);
    });

    wsClient.on('auto_scan_status', (data: { enabled: boolean }) => {
      setIsAutoScan(data.enabled);
    });

    // Connect to WebSocket
    wsClient.connect();

    // Cleanup on unmount
    return () => {
      wsClient.disconnect();
    };
  }, []);

  const handleScanClick = () => {
    wsClient.send({ type: 'manual_scan' });
  };

  const handleAutoScanToggle = () => {
    const newAutoScanState = !isAutoScan;
    wsClient.send({
      type: 'toggle_auto_scan',
      enabled: newAutoScanState
    });
    setIsAutoScan(newAutoScanState);
  };

  return (
    <div className="min-h-screen bg-gray-900 text-white">
      <header className="bg-gray-800 shadow-lg">
        <div className="max-w-7xl mx-auto px-4 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center">
              <h1 className="text-2xl font-bold">NetSentinel</h1>
              <div className="ml-4 flex items-center space-x-2">
                <button
                  onClick={handleScanClick}
                  className={`px-4 py-2 rounded-md bg-blue-600 hover:bg-blue-700 transition-colors ${
                    isScanning ? 'opacity-50 cursor-not-allowed' : ''
                  }`}
                  disabled={isScanning}
                >
                  {isScanning ? 'Scanning...' : 'Scan Network'}
                </button>
                <label className="flex items-center space-x-2 cursor-pointer">
                  <span>Auto-scan</span>
                  <div
                    className={`relative inline-block w-12 h-6 transition-colors duration-200 ease-in-out rounded-full ${
                      isAutoScan ? 'bg-green-600' : 'bg-gray-600'
                    }`}
                    onClick={handleAutoScanToggle}
                  >
                    <div
                      className={`absolute left-1 top-1 w-4 h-4 transition-transform duration-200 ease-in-out bg-white rounded-full transform ${
                        isAutoScan ? 'translate-x-6' : 'translate-x-0'
                      }`}
                    />
                  </div>
                </label>
              </div>
            </div>
            <div className="flex items-center space-x-2">
              <span
                className={`inline-block w-3 h-3 rounded-full ${
                  isConnected ? 'bg-green-500' : 'bg-red-500'
                }`}
              />
              <span className="text-sm">
                {isConnected ? 'Connected' : 'Disconnected'}
              </span>
            </div>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 py-6 space-y-6">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="bg-gray-800 rounded-lg shadow-lg p-4">
            <h2 className="text-xl font-semibold mb-4">Network Map</h2>
            <NetworkMap devices={devices} isScanning={isScanning} />
          </div>
          <div className="bg-gray-800 rounded-lg shadow-lg p-4">
            <h2 className="text-xl font-semibold mb-4">Alerts</h2>
            <AlertPanel devices={devices} />
          </div>
        </div>
        <div className="bg-gray-800 rounded-lg shadow-lg p-4">
          <h2 className="text-xl font-semibold mb-4">Connected Devices</h2>
          <DeviceList devices={devices} isScanning={isScanning} />
        </div>
      </main>
    </div>
  );
}

export default App;