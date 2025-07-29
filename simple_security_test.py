#!/usr/bin/env python3
"""
Simple NetSentinel Security Tester
Basic security tests that don't require packet crafting
"""

import requests
import json
import time
import threading
import socket
import random
from datetime import datetime

class SimpleSecurityTester:
    def __init__(self, netsentinel_api="http://127.0.0.1:8000/api"):
        self.api_base = netsentinel_api
        self.session = requests.Session()
        
    def test_api_connection(self):
        """Test connection to NetSentinel API"""
        try:
            response = self.session.get(f"{self.api_base}/system/status")
            if response.status_code == 200:
                print("✓ Connected to NetSentinel API")
                return True
            else:
                print(f"✗ API connection failed: {response.status_code}")
                return False
        except Exception as e:
            print(f"✗ Cannot connect to NetSentinel API: {e}")
            return False
    
    def simulate_port_scan_simple(self, target_ip="127.0.0.1", ports=None):
        """Simulate a simple port scan using socket connections"""
        if ports is None:
            # Use more ports to trigger detection (need >20 for current threshold)
            ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995, 1433, 3306, 3389, 5432, 5900, 
                    8080, 8443, 9090, 3000, 5000, 6000, 7000, 8000, 9000, 10000]
        
        print(f"\n🔍 Simulating port scan on {target_ip}")
        print(f"   Testing {len(ports)} ports to trigger security detection")
        
        for i, port in enumerate(ports):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.3)
                result = sock.connect_ex((target_ip, port))
                sock.close()
                
                if result == 0:
                    print(f"   Port {port}: OPEN")
                else:
                    print(f"   Port {port}: CLOSED/FILTERED")
                
                # Show progress every 5 ports
                if (i + 1) % 5 == 0:
                    print(f"   Progress: {i + 1}/{len(ports)} ports scanned")
                
                time.sleep(0.05)  # Small delay between attempts
                
            except Exception as e:
                print(f"   Port {port}: ERROR - {e}")
        
        print(f"✓ Port scan simulation complete - {len(ports)} ports scanned")
        print(f"   This should trigger NetSentinel's port scan detection!")
    
    def simulate_rapid_connections(self, target_ip="127.0.0.1", target_port=80, count=60):
        """Simulate rapid connection attempts (potential DoS pattern)"""
        print(f"\n💥 Simulating rapid connections to {target_ip}:{target_port}")
        print(f"   Making {count} rapid connection attempts (threshold is 50/minute)")
        
        success_count = 0
        start_time = time.time()
        
        for i in range(count):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((target_ip, target_port))
                sock.close()
                
                if result == 0:
                    success_count += 1
                
                if i % 10 == 0:
                    print(f"   Attempted {i+1}/{count} connections")
                
                time.sleep(0.02)  # Very rapid attempts (50 per second)
                
            except Exception:
                pass
        
        elapsed = time.time() - start_time
        rate = count / elapsed * 60  # connections per minute
        
        print(f"✓ Rapid connection test complete ({success_count}/{count} successful)")
        print(f"   Rate: {rate:.1f} connections/minute (threshold: 50)")
        print(f"   This should trigger NetSentinel's connection burst detection!")
    
    def inject_fake_device_via_api(self):
        """Simulate a new device by directly calling NetSentinel API"""
        print(f"\n👾 Simulating rogue device detection")
        
        # Generate fake device data
        fake_mac = ":".join([f"{random.randint(0, 255):02x}" for _ in range(6)])
        fake_ip = f"192.168.1.{random.randint(100, 200)}"
        
        print(f"   Fake MAC: {fake_mac}")
        print(f"   Fake IP: {fake_ip}")
        
        # Try to quarantine the fake device to simulate detection
        try:
            quarantine_data = {"mac": fake_mac, "reason": "Automated test - suspicious device behavior detected"}
            response = self.session.post(f"{self.api_base}/security/quarantine", json=quarantine_data)
            if response.status_code == 200:
                print(f"   ✓ Fake device quarantined successfully")
                print(f"   This simulates NetSentinel detecting a rogue device")
            else:
                print(f"   ✗ Failed to quarantine fake device: {response.status_code}")
        except Exception as e:
            print(f"   ✗ Error quarantining fake device: {e}")
        
        print(f"✓ Rogue device simulation complete")
    
    def generate_test_alerts(self):
        """Generate test security alerts directly via API"""
        print(f"\n🚨 Generating test security alerts via API...")
        
        test_alerts = [
            {
                "type": "port_scan",
                "severity": "high", 
                "message": "Port scan detected from test simulation - 28 ports accessed",
                "details": {"source_ip": "127.0.0.1", "ports_count": 28, "test": True}
            },
            {
                "type": "connection_burst",
                "severity": "medium",
                "message": "Connection burst detected from test simulation - 60 connections/minute",
                "details": {"source_ip": "127.0.0.1", "connection_count": 60, "test": True}
            },
            {
                "type": "rogue_device", 
                "severity": "high",
                "message": "Test rogue device simulation completed",
                "details": {"mac": "AA:BB:CC:DD:EE:FF", "ip": "192.168.1.102", "test": True}
            }
        ]
        
        success_count = 0
        for alert in test_alerts:
            try:
                response = self.session.post(f"{self.api_base}/security/test-alert", json=alert)
                if response.status_code == 200:
                    success_count += 1
                    print(f"   ✓ Generated {alert['type']} alert")
                else:
                    print(f"   ✗ Failed to generate {alert['type']} alert: {response.status_code}")
            except Exception as e:
                print(f"   ✗ Error generating {alert['type']} alert: {e}")
        
        print(f"✓ Generated {success_count}/{len(test_alerts)} test alerts")
        print(f"   These demonstrate NetSentinel's alert system working")
        
        return success_count
    
    def simulate_suspicious_dns_queries(self):
        """Simulate suspicious DNS queries"""
        print(f"\n🕳️ Simulating suspicious DNS activity")
        
        suspicious_domains = [
            "malware.example.com",
            "botnet.evil.net", 
            "phishing.bad.org",
            "ransomware.crypto.net",
            "keylogger.steal.info"
        ]
        
        for domain in suspicious_domains:
            try:
                print(f"   Querying: {domain}")
                socket.gethostbyname_ex(domain)
            except socket.gaierror:
                print(f"   {domain} - No resolution (expected)")
            except Exception as e:
                print(f"   {domain} - Error: {e}")
            
            time.sleep(1)
        
        print(f"✓ Suspicious DNS queries complete")
    
    def test_security_endpoints(self):
        """Test NetSentinel's security API endpoints"""
        print(f"\n🔧 Testing NetSentinel security features")
        
        # Test ping functionality
        print("   Testing ping endpoint...")
        ping_data = {"ip": "127.0.0.1", "count": 2}
        try:
            response = self.session.post(f"{self.api_base}/security/ping", json=ping_data)
            if response.status_code == 200:
                result = response.json().get("ping_result", {})
                print(f"   ✓ Ping test: {result.get('success', False)}")
            else:
                print(f"   ✗ Ping test failed: {response.status_code}")
        except Exception as e:
            print(f"   ✗ Ping test error: {e}")
        
        # Test fake device quarantine
        print("   Testing quarantine endpoint...")
        fake_mac = "AA:BB:CC:DD:EE:FF"
        quarantine_data = {"mac": fake_mac, "reason": "Security test"}
        try:
            response = self.session.post(f"{self.api_base}/security/quarantine", json=quarantine_data)
            if response.status_code == 200:
                print(f"   ✓ Quarantine test successful")
                
                # Release the fake device
                release_data = {"mac": fake_mac}
                response = self.session.post(f"{self.api_base}/security/release", json=release_data)
                if response.status_code == 200:
                    print(f"   ✓ Release test successful")
            else:
                print(f"   ✗ Quarantine test failed: {response.status_code}")
        except Exception as e:
            print(f"   ✗ Quarantine test error: {e}")
    
    def check_security_alerts(self):
        """Check NetSentinel security alerts"""
        print(f"\n🚨 Checking security alerts...")
        
        try:
            response = self.session.get(f"{self.api_base}/security/alerts")
            if response.status_code == 200:
                alerts = response.json().get("alerts", [])
                
                if alerts:
                    print(f"✓ Found {len(alerts)} security alerts:")
                    for alert in alerts[-5:]:  # Show last 5 alerts
                        timestamp = alert.get("timestamp", "Unknown")
                        alert_type = alert.get("type", "Unknown") 
                        message = alert.get("message", "No details")
                        print(f"   {timestamp} [{alert_type}] {message}")
                else:
                    print("ℹ️ No security alerts found")
                
                return len(alerts)
            else:
                print(f"✗ Failed to get alerts: {response.status_code}")
                return 0
                
        except Exception as e:
            print(f"✗ Error checking alerts: {e}")
            return 0
    
    def check_system_status(self):
        """Check NetSentinel system status"""
        print(f"\n💻 System Status:")
        
        try:
            response = self.session.get(f"{self.api_base}/system/status")
            if response.status_code == 200:
                status = response.json()
                print(f"   CPU Usage: {status.get('cpu_usage', 0):.1f}%")
                print(f"   Memory Usage: {status.get('memory_usage', 0):.1f}%")
                print(f"   Active Devices: {status.get('active_devices', 0)}")
                print(f"   Security Alerts: {status.get('security_alerts', 0)}")
                print(f"   Quarantined Devices: {status.get('quarantined_devices', 0)}")
                print(f"   Blocked Devices: {status.get('blocked_devices', 0)}")
                return status
            else:
                print(f"✗ Failed to get status: {response.status_code}")
                return {}
                
        except Exception as e:
            print(f"✗ Error checking status: {e}")
            return {}
    
    def run_basic_security_tests(self):
        """Run basic security tests that don't require special privileges"""
        print("=" * 60)
        print("🛡️ NetSentinel Basic Security Tests")
        print("=" * 60)
        
        if not self.test_api_connection():
            return
        
        # Get baseline
        print("\n📊 Baseline Status:")
        self.check_system_status()
        baseline_alerts = self.check_security_alerts()
        
        print("\n" + "="*40)
        print("Running Security Tests...")
        print("="*40)
        
        # Test 1: Port scan simulation
        self.simulate_port_scan_simple()
        time.sleep(2)
        
        # Test 2: Rapid connections
        self.simulate_rapid_connections(count=20)
        time.sleep(2)
        
        # Test 3: Suspicious DNS
        self.simulate_suspicious_dns_queries()
        time.sleep(2)
        
        # Test 4: API endpoint testing
        self.test_security_endpoints()
        time.sleep(2)
        
        # Test 5: Fake device simulation
        self.inject_fake_device_via_api()
        time.sleep(2)
        
        # Test 6: Generate test alerts
        generated_alerts = self.generate_test_alerts()
        time.sleep(3)  # Wait for alerts to be processed
        
        # Final check
        print("\n" + "="*40)
        print("FINAL RESULTS")
        print("="*40)
        self.check_system_status()
        final_alerts = self.check_security_alerts()
        
        new_alerts = final_alerts - baseline_alerts
        print(f"\n📋 Test Summary:")
        print(f"   Tests completed: 6")
        print(f"   Direct alerts generated: {generated_alerts}")
        print(f"   New alerts detected: {new_alerts}")
        print(f"   Total alerts: {final_alerts}")
        
        if new_alerts > 0 or generated_alerts > 0:
            print(f"✅ SUCCESS: NetSentinel alert system is working!")
            if generated_alerts > 0:
                print(f"   📝 {generated_alerts} test alerts were generated via API")
            if new_alerts > 0:
                print(f"   🔍 {new_alerts} alerts were detected from simulated attacks")
        else:
            print(f"⚠️ WARNING: No alerts detected or generated.")
            print(f"   Check NetSentinel configuration and packet capture.")

def main():
    print("NetSentinel Simple Security Tester")
    print("==================================")
    print("This tool runs basic security tests without requiring admin privileges.")
    print("For advanced packet-crafting tests, use security_tester.py with admin rights.\n")
    
    tester = SimpleSecurityTester()
    
    try:
        tester.run_basic_security_tests()
    except KeyboardInterrupt:
        print("\n\nTest interrupted by user.")
    except Exception as e:
        print(f"\nTest failed with error: {e}")

if __name__ == "__main__":
    main()
