'use client';

import React, { useState } from 'react';
import { Device } from '../types/device';
import { formatBytes } from '../utils/format';
import wsClient from '../utils/websocket';

interface DeviceListProps {
  devices: Device[];
  isScanning: boolean;
}

const getDeviceIcon = (deviceType: string): string => {
  switch (deviceType) {
    case 'Computer':
      return '💻';
    case 'Mobile Device':
      return '📱';
    case 'Smart TV':
      return '📺';
    case 'Gaming Console':
      return '🎮';
    case 'IoT Device':
      return '🏠';
    case 'Network Device':
      return '🌐';
    default:
      return '📱';
  }
};

const DeviceList: React.FC<DeviceListProps> = ({ devices, isScanning }) => {
  const [selectedDevice, setSelectedDevice] = useState<Device | null>(null);

  const handleDeviceClick = (device: Device) => {
    setSelectedDevice(device);
    // Request updated device info if type or vendor is unknown
    if (device.device_type === 'Unknown' || device.vendor === 'Unknown') {
      wsClient.send({
        type: 'get_device_info',
        mac: device.mac
      });
    }
  };

  // Listen for device info updates
  wsClient.on('device_info', (data: { data: Device }) => {
    if (selectedDevice && data.data.mac === selectedDevice.mac) {
      setSelectedDevice(data.data);
    }
  });

  const closeModal = () => {
    setSelectedDevice(null);
  };

  return (
    <div className="overflow-hidden">
      <div className="overflow-x-auto">
        <table className="min-w-full divide-y divide-gray-700">
          <thead>
            <tr>
              <th className="px-3 py-2 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                Device
              </th>
              <th className="px-3 py-2 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                Type
              </th>
              <th className="px-3 py-2 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                IP Address
              </th>
              <th className="px-3 py-2 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                MAC Address
              </th>
              <th className="px-3 py-2 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                Status
              </th>
              <th className="px-3 py-2 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                Traffic
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-700">
            {devices.map((device) => (
              <tr
                key={device.mac}
                onClick={() => handleDeviceClick(device)}
                className="hover:bg-gray-800 cursor-pointer transition-colors"
              >
                <td className="px-3 py-2 whitespace-nowrap">
                  <div className="flex items-center">
                    <span className="text-xl mr-2">{getDeviceIcon(device.device_type)}</span>
                    <div>
                      <div className="text-sm font-medium text-gray-200">
                        {device.hostname}
                        {device.suspicious && (
                          <span className="ml-2 text-xs text-red-500">!</span>
                        )}
                      </div>
                      <div className="text-xs text-gray-400">{device.vendor}</div>
                    </div>
                  </div>
                </td>
                <td className="px-3 py-2 whitespace-nowrap">
                  <div className="text-sm text-gray-300">{device.device_type}</div>
                </td>
                <td className="px-3 py-2 whitespace-nowrap">
                  <div className="text-sm text-gray-300">{device.ip}</div>
                </td>
                <td className="px-3 py-2 whitespace-nowrap">
                  <div className="text-sm text-gray-300">{device.mac}</div>
                </td>
                <td className="px-3 py-2 whitespace-nowrap">
                  <span className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${
                    device.status === 'active'
                      ? 'bg-green-900 text-green-200'
                      : 'bg-gray-700 text-gray-200'
                  }`}>
                    {device.status}
                  </span>
                </td>
                <td className="px-3 py-2 whitespace-nowrap text-sm text-gray-300">
                  {formatBytes(device.traffic?.bytes || 0)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Device Details Modal */}
      {selectedDevice && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
          <div className="bg-gray-800 rounded-lg max-w-2xl w-full p-6 relative">
            <button
              onClick={closeModal}
              className="absolute top-4 right-4 text-gray-400 hover:text-white"
            >
              ✕
            </button>
            <div className="flex items-center mb-4">
              <span className="text-2xl mr-3">{getDeviceIcon(selectedDevice.device_type)}</span>
              <h3 className="text-xl font-semibold text-white">Device Details</h3>
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div>
                <p className="text-sm text-gray-400">Hostname</p>
                <p className="text-base text-white">{selectedDevice.hostname}</p>
              </div>
              <div>
                <p className="text-sm text-gray-400">Device Type</p>
                <p className="text-base text-white">
                  {selectedDevice.device_type}
                  {selectedDevice.device_type === 'Unknown' && (
                    <span className="text-xs text-gray-400 ml-2">(Identifying...)</span>
                  )}
                </p>
              </div>
              <div>
                <p className="text-sm text-gray-400">IP Address</p>
                <p className="text-base text-white">{selectedDevice.ip}</p>
              </div>
              <div>
                <p className="text-sm text-gray-400">MAC Address</p>
                <p className="text-base text-white">{selectedDevice.mac}</p>
              </div>
              <div>
                <p className="text-sm text-gray-400">Vendor</p>
                <p className="text-base text-white">
                  {selectedDevice.vendor}
                  {selectedDevice.vendor === 'Unknown' && (
                    <span className="text-xs text-gray-400 ml-2">(Looking up...)</span>
                  )}
                </p>
              </div>
              <div>
                <p className="text-sm text-gray-400">Status</p>
                <p className="text-base text-white">{selectedDevice.status}</p>
              </div>
              <div>
                <p className="text-sm text-gray-400">Traffic</p>
                <p className="text-base text-white">
                  {formatBytes(selectedDevice.traffic?.bytes || 0)}
                </p>
              </div>
              <div>
                <p className="text-sm text-gray-400">Last Seen</p>
                <p className="text-base text-white">
                  {new Date(selectedDevice.lastSeen).toLocaleString()}
                </p>
              </div>
              <div className="col-span-2">
                <p className="text-sm text-gray-400 mb-2">Open Ports</p>
                <div className="grid grid-cols-3 gap-2">
                  {selectedDevice.ports.map((port) => (
                    <div
                      key={port.port}
                      className="bg-gray-700 rounded p-2 text-sm"
                    >
                      <p className="text-white">{port.port}</p>
                      <p className="text-gray-400 text-xs">{port.service}</p>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default DeviceList; 