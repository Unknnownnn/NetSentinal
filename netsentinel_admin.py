#!/usr/bin/env python3
"""
NetSentinel Administration Tool
Simple command-line interface for managing NetSentinel
"""

import requests
import json
import argparse
import sys
import time
from datetime import datetime

class NetSentinelAdmin:
    def __init__(self, host="127.0.0.1", port=8000):
        self.base_url = f"http://{host}:{port}/api"
        self.session = requests.Session()
    
    def test_connection(self):
        """Test connection to NetSentinel API"""
        try:
            response = self.session.get(f"{self.base_url}/system/status")
            if response.status_code == 200:
                print("✓ Connected to NetSentinel API")
                return True
            else:
                print(f"✗ API returned status {response.status_code}")
                return False
        except requests.exceptions.ConnectionError:
            print("✗ Cannot connect to NetSentinel API")
            print("  Make sure NetSentinel is running on the specified host/port")
            return False
    
    def get_devices(self):
        """Get list of all discovered devices"""
        try:
            response = self.session.get(f"{self.base_url}/devices")
            if response.status_code == 200:
                devices = response.json().get("devices", [])
                print(f"\n📱 Discovered Devices ({len(devices)} total):")
                print("-" * 80)
                for device in devices:
                    status = "🟢" if device.get("is_active") else "🔴"
                    vendor = device.get("vendor", "Unknown")[:20]
                    device_type = device.get("device_type", "Unknown")[:15]
                    print(f"{status} {device['ip']:15} {device['mac']:18} {vendor:20} {device_type}")
                return devices
            else:
                print(f"Failed to get devices: {response.status_code}")
                return []
        except Exception as e:
            print(f"Error getting devices: {e}")
            return []
    
    def get_security_status(self):
        """Get security alerts and status"""
        try:
            # Get alerts
            response = self.session.get(f"{self.base_url}/security/alerts")
            alerts = response.json().get("alerts", []) if response.status_code == 200 else []
            
            # Get quarantined devices
            response = self.session.get(f"{self.base_url}/security/quarantined")
            quarantined = response.json().get("quarantined_devices", []) if response.status_code == 200 else []
            
            # Get blocked devices
            response = self.session.get(f"{self.base_url}/security/blocked")
            blocked = response.json().get("blocked_devices", []) if response.status_code == 200 else []
            
            print(f"\n🛡️  Security Status:")
            print("-" * 50)
            print(f"🚨 Active Alerts: {len(alerts)}")
            print(f"🔒 Quarantined Devices: {len(quarantined)}")
            print(f"⛔ Blocked Devices: {len(blocked)}")
            
            if alerts:
                print(f"\n🚨 Recent Alerts:")
                for alert in alerts[-5:]:  # Show last 5 alerts
                    timestamp = alert.get("timestamp", "Unknown")
                    alert_type = alert.get("type", "Unknown")
                    message = alert.get("message", "No details")
                    print(f"  {timestamp} [{alert_type}] {message}")
            
            return {"alerts": alerts, "quarantined": quarantined, "blocked": blocked}
            
        except Exception as e:
            print(f"Error getting security status: {e}")
            return {}
    
    def ping_device(self, ip, count=4):
        """Ping a specific device"""
        try:
            data = {"ip": ip, "count": count}
            response = self.session.post(f"{self.base_url}/security/ping", json=data)
            if response.status_code == 200:
                result = response.json().get("ping_result", {})
                print(f"\n🏓 Ping Results for {ip}:")
                print(f"  Success: {result.get('success', False)}")
                print(f"  Packets: {result.get('packets_sent', 0)} sent, {result.get('packets_received', 0)} received")
                if result.get('avg_time'):
                    print(f"  Average Time: {result.get('avg_time'):.2f}ms")
            else:
                print(f"Ping failed: {response.status_code}")
        except Exception as e:
            print(f"Error pinging device: {e}")
    
    def quarantine_device(self, mac, reason="Admin action"):
        """Quarantine a device"""
        try:
            data = {"mac": mac, "reason": reason}
            response = self.session.post(f"{self.base_url}/security/quarantine", json=data)
            if response.status_code == 200:
                print(f"✓ Device {mac} quarantined successfully")
            else:
                print(f"Failed to quarantine device: {response.status_code}")
        except Exception as e:
            print(f"Error quarantining device: {e}")
    
    def release_quarantine(self, mac):
        """Release device from quarantine"""
        try:
            data = {"mac": mac}
            response = self.session.post(f"{self.base_url}/security/release", json=data)
            if response.status_code == 200:
                print(f"✓ Device {mac} released from quarantine")
            else:
                print(f"Failed to release device: {response.status_code}")
        except Exception as e:
            print(f"Error releasing device: {e}")
    
    def inject_test_device(self):
        """Inject a test suspicious device for security testing"""
        import random
        
        fake_mac = ":".join([f"{random.randint(0, 255):02x}" for _ in range(6)])
        fake_ip = f"192.168.1.{random.randint(100, 200)}"
        
        print(f"\n🧪 Injecting test suspicious device:")
        print(f"   MAC: {fake_mac}")
        print(f"   IP: {fake_ip}")
        
        # First quarantine it as suspicious
        try:
            data = {"mac": fake_mac, "reason": "Test suspicious device - unusual behavior detected"}
            response = self.session.post(f"{self.base_url}/security/quarantine", json=data)
            if response.status_code == 200:
                print(f"✓ Test device quarantined")
            else:
                print(f"✗ Failed to quarantine test device: {response.status_code}")
        except Exception as e:
            print(f"✗ Error quarantining test device: {e}")
        
        print(f"💡 This simulates NetSentinel detecting a suspicious device.")
        print(f"   Check 'security' command to see the quarantined device.")

    def get_system_status(self):
        """Get system performance status"""
        try:
            response = self.session.get(f"{self.base_url}/system/status")
            if response.status_code == 200:
                status = response.json()
                print(f"\n💻 System Status:")
                print("-" * 30)
                print(f"CPU Usage: {status.get('cpu_usage', 0):.1f}%")
                print(f"Memory Usage: {status.get('memory_usage', 0):.1f}%")
                print(f"Disk Usage: {status.get('disk_usage', 0):.1f}%")
                print(f"Active Devices: {status.get('active_devices', 0)}")
                print(f"Security Alerts: {status.get('security_alerts', 0)}")
                return status
            else:
                print(f"Failed to get system status: {response.status_code}")
                return {}
        except Exception as e:
            print(f"Error getting system status: {e}")
            return {}
    
    def monitor_realtime(self, duration=60):
        """Monitor system in real-time for specified duration"""
        print(f"🔍 Monitoring NetSentinel for {duration} seconds...")
        print("Press Ctrl+C to stop early")
        
        start_time = time.time()
        try:
            while time.time() - start_time < duration:
                # Clear screen (works on Windows and Unix)
                import os
                os.system('cls' if os.name == 'nt' else 'clear')
                
                print(f"NetSentinel Real-time Monitor - {datetime.now().strftime('%H:%M:%S')}")
                print("=" * 60)
                
                # Get current status
                self.get_system_status()
                self.get_security_status()
                
                print(f"\nUpdating in 5 seconds... ({int(duration - (time.time() - start_time))}s remaining)")
                time.sleep(5)
                
        except KeyboardInterrupt:
            print("\n\nMonitoring stopped by user.")
    
    def interactive_mode(self):
        """Interactive command mode"""
        print("\n🎛️  NetSentinel Interactive Mode")
        print("Type 'help' for available commands, 'quit' to exit")
        
        while True:
            try:
                command = input("\nnetsentinel> ").strip().lower()
                
                if command == 'quit' or command == 'exit':
                    break
                elif command == 'help':
                    print("""
Available commands:
  devices     - List all discovered devices
  security    - Show security status and alerts
  status      - Show system performance status
  ping <ip>   - Ping a device
  quarantine <mac> [reason] - Quarantine a device
  release <mac> - Release device from quarantine
  monitor [seconds] - Real-time monitoring
  help        - Show this help
  quit        - Exit interactive mode
                    """)
                elif command == 'devices':
                    self.get_devices()
                elif command == 'security':
                    self.get_security_status()
                elif command == 'status':
                    self.get_system_status()
                elif command.startswith('ping '):
                    parts = command.split()
                    if len(parts) >= 2:
                        self.ping_device(parts[1])
                    else:
                        print("Usage: ping <ip_address>")
                elif command.startswith('quarantine '):
                    parts = command.split(maxsplit=2)
                    if len(parts) >= 2:
                        reason = parts[2] if len(parts) > 2 else "Interactive admin action"
                        self.quarantine_device(parts[1], reason)
                    else:
                        print("Usage: quarantine <mac_address> [reason]")
                elif command.startswith('release '):
                    parts = command.split()
                    if len(parts) >= 2:
                        self.release_quarantine(parts[1])
                    else:
                        print("Usage: release <mac_address>")
                elif command.startswith('monitor'):
                    parts = command.split()
                    duration = int(parts[1]) if len(parts) > 1 else 60
                    self.monitor_realtime(duration)
                elif command.startswith('test'):
                    # Hidden test command for security testing
                    self.inject_test_device()
                elif command == '':
                    continue
                else:
                    print(f"Unknown command: {command}. Type 'help' for available commands.")
                    
            except KeyboardInterrupt:
                print("\nUse 'quit' to exit.")
            except Exception as e:
                print(f"Error: {e}")

def main():
    parser = argparse.ArgumentParser(description="NetSentinel Administration Tool")
    parser.add_argument("--host", default="127.0.0.1", help="NetSentinel host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="NetSentinel port (default: 8000)")
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Status command
    subparsers.add_parser("status", help="Show system status")
    
    # Devices command  
    subparsers.add_parser("devices", help="List discovered devices")
    
    # Security command
    subparsers.add_parser("security", help="Show security status")
    
    # Ping command
    ping_parser = subparsers.add_parser("ping", help="Ping a device")
    ping_parser.add_argument("ip", help="IP address to ping")
    ping_parser.add_argument("--count", type=int, default=4, help="Number of ping packets")
    
    # Quarantine command
    quarantine_parser = subparsers.add_parser("quarantine", help="Quarantine a device")
    quarantine_parser.add_argument("mac", help="MAC address to quarantine")
    quarantine_parser.add_argument("--reason", default="Admin action", help="Reason for quarantine")
    
    # Release command
    release_parser = subparsers.add_parser("release", help="Release device from quarantine")
    release_parser.add_argument("mac", help="MAC address to release")
    
    # Monitor command
    monitor_parser = subparsers.add_parser("monitor", help="Real-time monitoring")
    monitor_parser.add_argument("--duration", type=int, default=60, help="Monitoring duration in seconds")
    
    # Interactive command
    subparsers.add_parser("interactive", help="Start interactive mode")
    
    args = parser.parse_args()
    
    # Create admin instance
    admin = NetSentinelAdmin(args.host, args.port)
    
    # Test connection
    if not admin.test_connection():
        sys.exit(1)
    
    # Execute command
    if args.command == "status":
        admin.get_system_status()
    elif args.command == "devices":
        admin.get_devices()
    elif args.command == "security":
        admin.get_security_status()
    elif args.command == "ping":
        admin.ping_device(args.ip, args.count)
    elif args.command == "quarantine":
        admin.quarantine_device(args.mac, args.reason)
    elif args.command == "release":
        admin.release_quarantine(args.mac)
    elif args.command == "monitor":
        admin.monitor_realtime(args.duration)
    elif args.command == "interactive":
        admin.interactive_mode()
    else:
        # No command specified, show help and start interactive mode
        parser.print_help()
        print("\nStarting interactive mode...")
        admin.interactive_mode()

if __name__ == "__main__":
    main()
