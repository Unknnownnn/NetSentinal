import React, { useState, useEffect } from 'react';
import { Device } from './types/device';
import wsClient from './utils/websocket';
import NetworkMap from './components/NetworkMap';
import DeviceList from './components/DeviceList';
import AlertPanel from './components/AlertPanel';
import Layout from './components/Layout';
import FileScanner from './components/FileScanner';
import './App.css';

function App() {
  const [devices, setDevices] = useState<Device[]>([]);
  const [isScanning, setIsScanning] = useState(false);
  const [isAutoScan, setIsAutoScan] = useState(false);
  const [isConnected, setIsConnected] = useState(false);

  useEffect(() => {
    // Set up WebSocket event handlers
    wsClient.on('connection', (data: { status: string }) => {
      setIsConnected(data.status === 'connected');
    });

    wsClient.on('network_update', (data: { data: Device[] }) => {
      setDevices(data.data);
      if (!isAutoScan) {
        setIsScanning(false);
      }
    });

    wsClient.on('scan_start', () => {
      setIsScanning(true);
    });

    wsClient.on('scan_complete', () => {
      if (!isAutoScan) {
        setIsScanning(false);
      }
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
  }, [isAutoScan]);

  const handleScanClick = () => {
    wsClient.send({ type: 'manual_scan' });
  };

  const handleStopScanClick = () => {
    wsClient.send({ type: 'stop_scan' });
    setIsScanning(false);
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
      <header className="bg-gray-800 shadow">
        <div className="max-w-7xl mx-auto px-4 py-4">
          <div className="flex justify-between items-center">
            <h1 className="text-2xl font-bold">NetSentinel</h1>
            <div className="flex items-center space-x-4">
              <div className="flex items-center space-x-2">
                <button
                  onClick={handleAutoScanToggle}
                  className={`px-4 py-2 rounded-md text-sm font-medium ${
                    isAutoScan
                      ? 'bg-blue-600 text-white'
                      : 'bg-gray-700 text-gray-300'
                  }`}
                >
                  Auto Scan: {isAutoScan ? 'On' : 'Off'}
                </button>
                {!isAutoScan && (
                  <>
                    <button
                      onClick={handleScanClick}
                      disabled={isScanning}
                      className={`px-4 py-2 rounded-md text-sm font-medium ${
                        isScanning
                          ? 'bg-gray-700 text-gray-400 cursor-not-allowed'
                          : 'bg-blue-600 text-white hover:bg-blue-700'
                      }`}
                    >
                      {isScanning ? 'Scanning...' : 'Scan Network'}
                    </button>
                    {isScanning && (
                      <button
                        onClick={handleStopScanClick}
                        className="px-4 py-2 rounded-md text-sm font-medium bg-red-600 text-white hover:bg-red-700"
                      >
                        Stop Scan
                      </button>
                    )}
                  </>
                )}
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
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 py-6 space-y-6">
        {/* Main row - Network Map and Security Alerts */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="bg-gray-800 rounded-lg shadow-lg p-4">
            <h2 className="text-xl font-semibold mb-4">Network Map</h2>
            <NetworkMap devices={devices} isScanning={isScanning} />
          </div>
          <div className="bg-gray-800 rounded-lg shadow-lg p-4">
            <h2 className="text-xl font-semibold mb-4">Security Alerts</h2>
            <AlertPanel devices={devices} />
            <div className="mt-4">
              <FileScanner />
            </div>
          </div>
        </div>

        {/* Connected Devices */}
        <div className="bg-gray-800 rounded-lg shadow-lg p-4">
          <h2 className="text-xl font-semibold mb-4">Connected Devices</h2>
          <DeviceList devices={devices} isScanning={isScanning} />
        </div>
      </main>
    </div>
  );
}

export default App;