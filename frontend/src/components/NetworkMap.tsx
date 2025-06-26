'use client';

import React, { useEffect, useRef } from 'react';
import { Device } from '../types/device';

interface NetworkMapProps {
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
    default:
      return '📱';
  }
};

const NetworkMap: React.FC<NetworkMapProps> = ({ devices, isScanning }) => {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const animationFrameRef = useRef<number>();
  const angleRef = useRef<number>(0);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    // Set canvas size with device pixel ratio for sharp rendering
    const dpr = window.devicePixelRatio || 1;
    const rect = canvas.getBoundingClientRect();
    canvas.width = rect.width * dpr;
    canvas.height = rect.height * dpr;
    ctx.scale(dpr, dpr);

    const centerX = rect.width / 2;
    const centerY = rect.height / 2;
    const radius = Math.min(centerX, centerY) * 0.7;

    const draw = () => {
      ctx.clearRect(0, 0, canvas.width, canvas.height);

      // Draw scanning animation
      if (isScanning) {
        angleRef.current += 0.03;
        ctx.beginPath();
        ctx.arc(centerX, centerY, radius + 10, angleRef.current, angleRef.current + Math.PI / 4);
        ctx.strokeStyle = '#3B82F6';
        ctx.lineWidth = 2;
        ctx.stroke();

        // Draw scanning pulse
        const pulseRadius = (radius + 10) * (1 + Math.sin(angleRef.current) * 0.1);
        ctx.beginPath();
        ctx.arc(centerX, centerY, pulseRadius, 0, Math.PI * 2);
        ctx.strokeStyle = 'rgba(59, 130, 246, 0.1)';
        ctx.lineWidth = 1;
        ctx.stroke();
      }

      // Draw router in center
      ctx.beginPath();
      ctx.arc(centerX, centerY, 25, 0, Math.PI * 2);
      ctx.fillStyle = '#1F2937';
      ctx.fill();
      ctx.strokeStyle = '#3B82F6';
      ctx.lineWidth = 3;
      ctx.stroke();

      // Draw router icon
      ctx.fillStyle = '#60A5FA';
      ctx.font = '16px system-ui';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillText('📡', centerX, centerY);

      // Draw devices
      devices.forEach((device, index) => {
        const angle = (index * 2 * Math.PI) / devices.length;
        const x = centerX + Math.cos(angle) * radius;
        const y = centerY + Math.sin(angle) * radius;

        // Draw connection line
        ctx.beginPath();
        ctx.moveTo(centerX, centerY);
        ctx.lineTo(x, y);
        ctx.strokeStyle = device.status === 'active' ? '#3B82F6' : '#4B5563';
        ctx.lineWidth = 1;
        ctx.stroke();

        // Draw device circle
        ctx.beginPath();
        ctx.arc(x, y, 20, 0, Math.PI * 2);
        ctx.fillStyle = device.status === 'active' ? '#1F2937' : '#111827';
        ctx.fill();
        ctx.strokeStyle = device.suspicious ? '#EF4444' : '#3B82F6';
        ctx.lineWidth = device.suspicious ? 3 : 2;
        ctx.stroke();

        // Draw device icon
        ctx.fillStyle = device.status === 'active' ? '#60A5FA' : '#4B5563';
        ctx.font = '14px system-ui';
        ctx.fillText(getDeviceIcon(device.device_type), x, y);

        // Draw device label
        const label = `${device.hostname}\n${device.ip}\n${device.device_type}`;
        const lines = label.split('\n');
        
        ctx.font = '12px system-ui';
        ctx.fillStyle = device.status === 'active' ? '#E5E7EB' : '#9CA3AF';
        
        lines.forEach((line, i) => {
          ctx.fillText(line, x, y + 35 + (i * 15));
        });

        // Draw suspicious indicator if needed
        if (device.suspicious) {
          ctx.beginPath();
          ctx.arc(x + 15, y - 15, 8, 0, Math.PI * 2);
          ctx.fillStyle = '#991B1B';
          ctx.fill();
          ctx.strokeStyle = '#F87171';
          ctx.lineWidth = 1.5;
          ctx.stroke();

          ctx.fillStyle = '#FFFFFF';
          ctx.font = '12px system-ui';
          ctx.fillText('⚠', x + 15, y - 15);
        }
      });

      animationFrameRef.current = requestAnimationFrame(draw);
    };

    draw();

    return () => {
      if (animationFrameRef.current) {
        cancelAnimationFrame(animationFrameRef.current);
      }
    };
  }, [devices, isScanning]);

  return (
    <div className="map-container">
      {devices.length === 0 ? (
        <div className="flex items-center justify-center h-[600px] text-gray-400">
          <span className="text-base">No devices to display</span>
        </div>
      ) : (
        <canvas
          ref={canvasRef}
          style={{ width: '100%', height: '600px' }}
          className="transition-opacity duration-300"
        />
      )}
    </div>
  );
};

export default NetworkMap; 