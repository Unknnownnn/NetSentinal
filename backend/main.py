import asyncio
import json
from typing import Dict, List, Tuple
from fastapi import FastAPI, WebSocket, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime, timedelta
import nmap
import psutil
import socket
from scapy.all import ARP, Ether, srp, sniff, IP, TCP, UDP, DNS, DNSQR, DNSRR, conf, DHCP, BOOTP, ICMP, sr1
import netifaces
from threading import Thread, Event
from concurrent.futures import ThreadPoolExecutor
from collections import defaultdict
import platform
import re
try:
    import winreg  # type: ignore
except Exception:
    winreg = None  # Non-Windows platforms don't have winreg
import requests
import hashlib
import base64
import websockets
import time

from oui_database import get_vendor_from_oui, get_device_type_from_vendor
from security_monitor import SecurityMonitor, NetworkDefense, VulnerabilityScanner
from config import get_config, update_config, SECURITY_CONFIG, DEFENSE_CONFIG, API_CONFIG
from pathlib import Path
import queue
import threading
from file_scanner import scanner as vt_scanner, VirusTotalScanner

# Import OUI database
from oui_database import get_vendor_from_oui, get_device_type_from_vendor, DEVICE_TYPE_PATTERNS

# Import security monitoring
from security_monitor import security_monitor, network_defense, vulnerability_scanner

# Initialize thread pool
thread_pool = ThreadPoolExecutor(max_workers=4)

# Global WebSocket state
websocket_server_active = False
connected_clients: List[WebSocket] = []

class VendorLookupService:
    """Background service for vendor lookups to avoid blocking the main event loop"""
    
    def __init__(self):
        self.lookup_queue = queue.Queue()
        self.result_callbacks = {}
        self.running = False
        self.worker_thread = None
        print("Vendor lookup service initialized successfully")
    
    def start(self):
        """Start the background vendor lookup service"""
        self.running = True
        self.worker_thread = threading.Thread(target=self._worker_loop, daemon=True)
        self.worker_thread.start()
        print("Vendor lookup service started")
    
    def stop(self):
        """Stop the background vendor lookup service"""
        self.running = False
        if self.worker_thread:
            self.worker_thread.join(timeout=5)
    
    def lookup_vendor_async(self, mac: str, callback=None) -> str:
        """Queue a vendor lookup request"""
        request_id = f"{mac}_{time.time()}"
        if callback:
            self.result_callbacks[request_id] = callback
        
        self.lookup_queue.put({
            'id': request_id,
            'mac': mac,
            'has_callback': callback is not None
        })
        return request_id
    
    def _worker_loop(self):
        """Main worker loop for processing vendor lookups"""
        while self.running:
            try:
                # Get request from queue with timeout
                request = self.lookup_queue.get(timeout=1)
                
                mac = request['mac']
                request_id = request['id']
                
                # Perform the lookup
                vendor, device_type = self._perform_lookup(mac)
                
                # Call callback if provided
                if request['has_callback'] and request_id in self.result_callbacks:
                    try:
                        self.result_callbacks[request_id](mac, vendor, device_type)
                        del self.result_callbacks[request_id]
                    except Exception as e:
                        print(f"Error in vendor lookup callback: {e}")
                
                self.lookup_queue.task_done()
                
            except queue.Empty:
                continue
            except Exception as e:
                print(f"Error in vendor lookup worker: {e}")
    
    def _perform_lookup(self, mac: str) -> tuple:
        """Perform the actual vendor lookup"""
        vendor_name = "Unknown"
        device_type = "Unknown"
        
        try:
            # Ensure MAC format is consistent
            clean_mac = mac.replace('-', ':').upper()
            
            # Use our improved OUI lookup methods
            vendor_name = self._oui_fallback_lookup(clean_mac)
            
            # Determine device type based on vendor patterns
            if vendor_name != "Unknown":
                vendor_name_lower = vendor_name.lower()
                for type_name, patterns in DEVICE_TYPE_PATTERNS.items():
                    if any(pattern in vendor_name_lower for pattern in patterns):
                        device_type = type_name
                        break
            
            return vendor_name, device_type
            
        except Exception as e:
            print(f"Error in vendor lookup for {mac}: {e}")
            return "Unknown", "Unknown"
    
    def _oui_fallback_lookup(self, mac: str) -> str:
        """Fallback OUI vendor lookup"""
        try:
            # First try common OUI database
            vendor = get_vendor_from_oui(mac)
            if vendor != "Unknown":
                print(f"Found vendor in common OUI database: {vendor}")
                return vendor
            
            # Try online API with timeout
            try:
                response = requests.get(f"https://api.macvendors.com/{mac}", timeout=2)
                if response.status_code == 200:
                    vendor = response.text.strip()
                    if vendor and not vendor.lower().startswith('not found') and vendor != "N/A":
                        print(f"Found vendor via API: {vendor}")
                        return vendor
            except Exception:
                pass  # Silently fail and continue
            
        except Exception as e:
            print(f"OUI fallback lookup failed for {mac}: {e}")
        
        return "Unknown"

# Initialize the vendor lookup service
vendor_service = VendorLookupService()

# Common ports for device identification
DEVICE_PORTS = {
    'Mobile Device': [62078, 62078, 5353, 137, 138],  # iOS & Android common ports
    'Smart TV': [3000, 3001, 8008, 8009, 7000],  # Smart TV ports
    'Gaming Console': [3074, 3075, 3076, 1935],  # Gaming ports
    'IoT Device': [8883, 1883, 80, 443, 8080],  # IoT common ports
    'Computer': [445, 139, 135, 22, 3389]  # Common computer ports
}

# DHCP Fingerprinting patterns
DHCP_SIGNATURES = {
    'Windows': ['MSFT', 'Windows'],
    'Linux': ['Linux', 'Ubuntu', 'Debian', 'Red Hat'],
    'Mobile Device': ['iPhone', 'iPad', 'Android', 'Samsung'],
    'IoT Device': ['ESP', 'Raspberry', 'Docker', 'Container'],
    'Smart TV': ['Samsung TV', 'LG TV', 'Roku', 'Apple TV'],
    'Gaming Console': ['Xbox', 'PlayStation', 'Nintendo']
}

# TTL signatures for OS detection
TTL_SIGNATURES = {
    64: ['Linux', 'Unix', 'IoT Device'],
    128: ['Windows'],
    255: ['Network Device', 'Router'],
    32: ['Windows Mobile'],
    48: ['Mobile Device']
}

# Service banner patterns
SERVICE_SIGNATURES = {
    'Windows': ['microsoft', 'windows', 'iis'],
    'Linux': ['ubuntu', 'debian', 'centos', 'red hat', 'apache'],
    'Mobile Device': ['mobile', 'android', 'ios'],
    'IoT Device': ['busybox', 'embedded', 'router']
}

# Enhanced port signatures for device type detection
PORT_SIGNATURES = {
    'Mobile Device': {
        'required': [62078],  # iOS sync
        'optional': [5353, 137, 138, 1234, 5000],  # mDNS, NetBIOS, common mobile apps
        'weight': 0.7
    },
    'Smart TV': {
        'required': [8008, 8009],  # Chromecast
        'optional': [3000, 3001, 7000, 9080, 9197],  # Common smart TV ports
        'weight': 0.8
    },
    'Gaming Console': {
        'required': [3074],  # Xbox Live
        'optional': [3075, 3076, 1935, 3478, 3479, 3480],  # PSN, Nintendo
        'weight': 0.9
    },
    'IoT Device': {
        'required': [8883, 1883],  # MQTT
        'optional': [80, 443, 8080, 8081, 2525],  # Web interfaces
        'weight': 0.6
    },
    'Computer': {
        'required': [445, 139],  # SMB
        'optional': [135, 22, 3389, 80, 443],  # RDP, SSH, Web
        'weight': 0.8
    },
    'Network Device': {
        'required': [23, 22],  # Telnet, SSH
        'optional': [80, 443, 161, 162, 514, 2000],  # SNMP, Syslog
        'weight': 0.9
    }
}

def get_oui_vendor_fallback(mac: str) -> str:
    """Fallback OUI vendor lookup using multiple methods"""
    try:
        # First try common OUI database
        vendor = get_vendor_from_oui(mac)
        if vendor != "Unknown":
            print(f"Found vendor in common OUI database: {vendor}")
            return vendor
        
        # Try online API as second fallback (with reduced timeout)
        try:
            response = requests.get(f"https://api.macvendors.com/{mac}", timeout=2)
            if response.status_code == 200:
                vendor = response.text.strip()
                if vendor and not vendor.lower().startswith('not found') and vendor != "N/A":
                    print(f"Found vendor via API: {vendor}")
                    return vendor
        except Exception as api_error:
            print(f"API lookup failed: {api_error}")
        
        # Try IEEE OUI database as third fallback
        response = requests.get(f"http://standards-oui.ieee.org/oui.txt", timeout=5)
        if response.status_code == 200:
            oui_data = response.text
            # Search for the OUI in the file
            oui = mac.replace(':', '').replace('-', '').replace('.', '').upper()[:6]
            for line in oui_data.split('\n'):
                if oui.upper() in line and '(hex)' in line:
                    parts = line.split('\t')
                    if len(parts) >= 3:
                        return parts[2].strip()
        
    except Exception as e:
        print(f"OUI fallback lookup failed for {mac}: {e}")
    
    return "Unknown"

def get_vendor_info_sync(mac: str) -> tuple:
    """Get vendor information from MAC address synchronously with multiple fallbacks"""
    vendor_name = "Unknown"
    device_type = "Unknown"
    
    try:
        # Ensure MAC format is consistent
        clean_mac = mac.replace('-', ':').upper()
        
        # Quick check in common OUI database first (fastest)
        vendor_name = get_vendor_from_oui(clean_mac)
        
        if vendor_name != "Unknown":
            print(f"Found vendor in common OUI database: {vendor_name}")
            # Determine device type based on vendor
            device_type = get_device_type_from_vendor(vendor_name)
        else:
            # For unknown vendors, just return Unknown immediately to avoid blocking
            # The vendor service will handle the lookup in background
            print(f"Vendor not in common database for {clean_mac}, will be looked up in background")
        
        return vendor_name, device_type
        
    except Exception as e:
        print(f"Error in get_vendor_info_sync for {mac}: {e}")
        return "Unknown", "Unknown"

def request_vendor_lookup_async(mac: str, update_callback=None):
    """Request an async vendor lookup that won't block the main thread"""
    return vendor_service.lookup_vendor_async(mac, update_callback)

def analyze_ttl(ttl: int) -> str:
    """Analyze TTL value to guess OS/device type"""
    # Find the closest TTL base value
    base_ttl = min(TTL_SIGNATURES.keys(), key=lambda x: abs(x - ttl))
    
    # If TTL is within reasonable range of base value (accounting for hops)
    if abs(base_ttl - ttl) <= 5:
        return TTL_SIGNATURES[base_ttl][0]
    return "Unknown"

def analyze_dhcp_fingerprint(packet) -> str:
    """Analyze DHCP packets for vendor class identifier"""
    try:
        if DHCP in packet:
            options = packet[DHCP].options
            for option in options:
                if isinstance(option, tuple) and option[0] == 'vendor_class_id':
                    vendor_id = option[1].decode('utf-8', errors='ignore').lower()
                    for device_type, patterns in DHCP_SIGNATURES.items():
                        if any(pattern.lower() in vendor_id for pattern in patterns):
                            return device_type
    except Exception as e:
        print(f"Error analyzing DHCP fingerprint: {e}")
    return "Unknown"

def analyze_service_banner(ip: str, ports: list) -> str:
    """Analyze service banners for device type hints"""
    try:
        nm = nmap.PortScanner()
        # Quick service scan on common ports
        nm.scan(ip, arguments=f'-sV -p{",".join(map(str, ports))} --version-intensity 5')
        
        if ip in nm.all_hosts():
            for port in nm[ip].all_tcp():
                if 'product' in nm[ip]['tcp'][port]:
                    banner = nm[ip]['tcp'][port]['product'].lower()
                    for device_type, patterns in SERVICE_SIGNATURES.items():
                        if any(pattern in banner for pattern in patterns):
                            return device_type
    except Exception as e:
        print(f"Error analyzing service banner: {e}")
    return "Unknown"

def identify_device_type_threaded(mac: str, hostname: str, ports: set, ip: str = None) -> tuple:
    """Enhanced device type identification using multiple methods"""
    try:
        # Start with vendor lookup
        vendor, device_type = get_vendor_info_sync(mac)
        
        # If device type is still unknown, try other methods
        if device_type == "Unknown":
            # Check hostname patterns
            hostname_lower = hostname.lower()
            for type_name, patterns in DEVICE_TYPE_PATTERNS.items():
                if any(pattern in hostname_lower for pattern in patterns):
                    device_type = type_name
                    break
        
        # If still unknown and we have ports, check port patterns
        if device_type == "Unknown" and ports:
            for type_name, device_ports in DEVICE_PORTS.items():
                if any(port in ports for port in device_ports):
                    device_type = type_name
                    break
        
        # If we have an IP, try service banner analysis
        if device_type == "Unknown" and ip and ports:
            device_type = analyze_service_banner(ip, list(ports)[:10])  # Limit to first 10 ports
        
        # Additional heuristics based on port characteristics
        if device_type == "Unknown":
            if any(port in ports for port in [62078, 5353]):  # iOS/Android ports
                device_type = "Mobile Device"
            elif len(ports) < 5 and all(port in [80, 443, 8080, 1883, 8883] for port in ports):
                device_type = "IoT Device"
            elif len(ports) > 10 and any(port in [22, 445, 139] for port in ports):
                device_type = "Computer"
        
        return vendor, device_type
    except Exception as e:
        print(f"Error in identify_device_type for MAC {mac}: {e}")
        return "Unknown", "Unknown"

def identify_device_type_sync(mac: str, hostname: str, ports: set, ip: str = None) -> tuple:
    """Synchronous device type identification - safe for any context"""
    try:
        # Use only sync vendor lookup
        vendor, device_type = get_vendor_info_sync(mac)
        
        # If device type is still unknown, try other methods
        if device_type == "Unknown":
            # Check hostname patterns
            hostname_lower = hostname.lower()
            for type_name, patterns in DEVICE_TYPE_PATTERNS.items():
                if any(pattern in hostname_lower for pattern in patterns):
                    device_type = type_name
                    break
        
        # If still unknown and we have ports, check port patterns
        if device_type == "Unknown" and ports:
            for type_name, device_ports in DEVICE_PORTS.items():
                if any(port in ports for port in device_ports):
                    device_type = type_name
                    break
        
        # Additional heuristics based on port characteristics
        if device_type == "Unknown":
            if any(port in ports for port in [62078, 5353]):  # iOS/Android ports
                device_type = "Mobile Device"
            elif len(ports) < 5 and all(port in [80, 443, 8080, 1883, 8883] for port in ports):
                device_type = "IoT Device"
            elif len(ports) > 10 and any(port in [22, 445, 139] for port in ports):
                device_type = "Computer"
        
        return vendor, device_type
        
    except Exception as e:
        print(f"Error in identify_device_type_sync for MAC {mac}: {e}")
        return "Unknown", "Unknown"

app = FastAPI(title="NetSentinel API")

# Enable CORS using configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=API_CONFIG["cors_origins"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Store device history
device_history: Dict[str, dict] = {}
# Store live packet data
packet_stats = defaultdict(lambda: {
    'packets': 0,
    'bytes': 0,
    'last_seen': None,
    'protocols': set(),
    'ports': set(),
    'dns_queries': set()  # Track DNS queries for better device identification
})

# Global flags
is_sniffing = False
sniffer_thread = None
auto_scan = False
mdns_thread = None
stop_scan_event = Event()

# Add traffic monitoring thresholds
TRAFFIC_THRESHOLDS = {
    'high_traffic': 1000000,  # 1MB/s
    'suspicious_ports': [22, 23, 3389, 445],  # SSH, Telnet, RDP, SMB
    'scan_threshold': 100,  # Number of different ports accessed in short time
    'connection_burst': 50,  # Number of connections in 1 minute
}

# Add alert history
alert_history = []

def get_windows_interfaces():
    """Get Windows interface information"""
    interfaces = {}
    
    # Get network interfaces from netifaces
    for interface in netifaces.interfaces():
        try:
            addrs = netifaces.ifaddresses(interface)
            if netifaces.AF_INET in addrs:
                ip_info = addrs[netifaces.AF_INET][0]
                # Try to get the friendly name from Windows registry
                friendly_name = None
                if platform.system() == "Windows" and re.match(r'{[\w-]+}', interface):
                    try:
                        key_path = r"SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}"
                        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path + "\\" + interface + "\\Connection", 0, winreg.KEY_READ) as key:
                            friendly_name = winreg.QueryValueEx(key, "Name")[0]
                    except:
                        friendly_name = interface

                interfaces[interface] = {
                    'name': friendly_name or interface,
                    'description': '',
                    'ip': ip_info.get('addr'),
                    'netmask': ip_info.get('netmask')
                }
        except Exception as e:
            print(f"Error processing interface {interface}: {str(e)}")
            continue
    
    return interfaces

def get_interface_name(guid: str) -> str:
    """Convert Windows interface GUID to interface name"""
    try:
        if platform.system() == "Windows":
            # Try to get from Windows registry
            try:
                key_path = r"SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}"
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path + "\\" + guid + "\\Connection", 0, winreg.KEY_READ) as key:
                    return winreg.QueryValueEx(key, "Name")[0]
            except:
                # If registry lookup fails, try interfaces list
                interfaces = get_windows_interfaces()
                if guid in interfaces:
                    return interfaces[guid]['name']
    except Exception as e:
        print(f"Error getting interface name: {str(e)}")
    return guid

def get_default_gateway():
    """Get the default gateway interface and IP"""
    try:
        gateways = netifaces.gateways()
        if 'default' in gateways and netifaces.AF_INET in gateways['default']:
            gateway_ip = gateways['default'][netifaces.AF_INET][0]
            interface = gateways['default'][netifaces.AF_INET][1]
            print(f"Found default gateway: {gateway_ip} on interface {interface}")
            
            # Get the friendly name for Windows interfaces
            if platform.system() == "Windows" and re.match(r'{[\w-]+}', interface):
                friendly_name = get_interface_name(interface)
                print(f"Using interface friendly name: {friendly_name}")
                return interface, gateway_ip, friendly_name
            
            return interface, gateway_ip, interface
    except Exception as e:
        print(f"Error getting default gateway: {str(e)}")
    return None, None, None

def packet_callback(packet):
    """Enhanced packet processing with additional device detection methods"""
    try:
        # Extract IP addresses and MAC addresses
        if ARP in packet:
            src_mac = packet[ARP].hwsrc
            src_ip = packet[ARP].psrc
            dst_mac = packet[ARP].hwdst
            dst_ip = packet[ARP].pdst
            
            update_device_info(src_ip, src_mac)
            if dst_mac != "00:00:00:00:00:00":
                update_device_info(dst_ip, dst_mac)
                
        elif IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            ttl = packet[IP].ttl
            
            # Store TTL for OS detection
            if src_ip in packet_stats:
                packet_stats[src_ip]['ttl'] = ttl
            
            if Ether in packet:
                src_mac = packet[Ether].src
                dst_mac = packet[Ether].dst
                update_device_info(src_ip, src_mac)
                update_device_info(dst_ip, dst_mac)
            
            # Update packet statistics
            packet_stats[src_ip]['packets'] += 1
            packet_stats[src_ip]['bytes'] += len(packet)
            packet_stats[src_ip]['last_seen'] = datetime.now()
            
            # Analyze DHCP packets
            if DHCP in packet:
                device_type = analyze_dhcp_fingerprint(packet)
                if device_type != "Unknown" and src_mac in device_history:
                    device_history[src_mac]['device_type'] = device_type
            
            # Track protocols and ports
            if TCP in packet or UDP in packet:
                proto = TCP if TCP in packet else UDP
                sport = packet[proto].sport
                dport = packet[proto].dport
                packet_stats[src_ip]['ports'].add(sport)
                packet_stats[dst_ip]['ports'].add(dport)
                
            # Process DNS packets
            if DNS in packet:
                process_dns_packet(packet, src_ip, dst_ip)
            
            # Security analysis
            security_monitor.analyze_packet(packet, src_ip, dst_ip, src_mac)
                
    except Exception as e:
        print(f"Error processing packet: {str(e)}")

def process_dns_packet(packet, src_ip, dst_ip):
    """Process DNS and mDNS packets for device discovery"""
    try:
        if packet.haslayer(DNS):
            # Process queries
            if packet.haslayer(DNSQR):
                query = packet[DNSQR].qname.decode('utf-8').lower()
                packet_stats[src_ip]['dns_queries'].add(query)
                
                # Look for device-specific patterns in DNS queries
                if any(pattern in query for pattern in [
                    'apple-mobile', 'iphone', 'ipad', 'android', 
                    'smarttv', 'roku', 'firetv', 'chromecast',
                    'playstation', 'xbox', 'nintendo',
                    'philips-hue', 'nest', 'iot'
                ]):
                    # Update device type based on DNS query
                    if src_ip in device_history:
                        device = device_history[src_ip]
                        if 'mobile' in query:
                            device['device_type'] = 'Mobile Device'
                        elif any(tv in query for tv in ['smarttv', 'roku', 'firetv']):
                            device['device_type'] = 'Smart TV'
                        elif any(game in query for game in ['playstation', 'xbox', 'nintendo']):
                            device['device_type'] = 'Gaming Console'
                        elif any(iot in query for iot in ['philips-hue', 'nest', 'iot']):
                            device['device_type'] = 'IoT Device'
            
            # Process responses
            if packet.haslayer(DNSRR):
                answer = packet[DNSRR].rdata
                if isinstance(answer, bytes):
                    answer = answer.decode('utf-8')
                # Update device hostname if found
                if src_ip in device_history:
                    device_history[src_ip]['hostname'] = answer.rstrip('.')
                    
    except Exception as e:
        print(f"Error processing DNS packet: {str(e)}")

def generate_alert(device_mac: str, alert_type: str, severity: str, details: str):
    """Generate and store an alert"""
    alert = {
        'timestamp': datetime.now().isoformat(),
        'device_mac': device_mac,
        'device_name': device_history.get(device_mac, {}).get('hostname', 'Unknown'),
        'type': alert_type,
        'severity': severity,
        'details': details
    }
    alert_history.append(alert)
    # Keep only last 1000 alerts
    if len(alert_history) > 1000:
        alert_history.pop(0)
    return alert

def check_device_alerts(device_mac: str, device_data: dict):
    """Check for suspicious activity and generate alerts"""
    alerts = []
    
    # Check traffic volume
    if device_data['traffic']['bytes'] > TRAFFIC_THRESHOLDS['high_traffic']:
        alerts.append(generate_alert(
            device_mac,
            'High Traffic',
            'warning',
            f"Device is generating high traffic: {device_data['traffic']['bytes']} bytes"
        ))
    
    # Check suspicious ports
    device_ports = set(port['port'] for port in device_data.get('ports', []))
    suspicious_ports = device_ports.intersection(TRAFFIC_THRESHOLDS['suspicious_ports'])
    if suspicious_ports:
        alerts.append(generate_alert(
            device_mac,
            'Suspicious Ports',
            'high',
            f"Device has suspicious ports open: {list(suspicious_ports)}"
        ))
    
    # Check for port scanning behavior
    if len(device_ports) > TRAFFIC_THRESHOLDS['scan_threshold']:
        alerts.append(generate_alert(
            device_mac,
            'Port Scanning',
            'high',
            f"Device accessed unusually high number of ports: {len(device_ports)}"
        ))
    
    return alerts

def update_device_info(ip: str, mac: str, skip_vendor_lookup: bool = False):
    """Update device information based on captured packets"""
    try:
        if mac not in device_history:
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except:
                hostname = "Unknown"
            
            ports = set()
            if ip in packet_stats:
                ports = packet_stats[ip]['ports']
            
            device_history[mac] = {
                'ip': ip,
                'hostname': hostname,
                'mac': mac,
                'vendor': "Unknown",
                'device_type': "Unknown",
                'last_seen': datetime.now().isoformat(),
                'status': 'active',
                'ports': [],
                'suspicious': False,
                'traffic': {
                    'packets': 0,
                    'bytes': 0,
                    'connections': defaultdict(int),
                    'last_minute_connections': 0
                }
            }
            
            if not skip_vendor_lookup:
                # Quick sync lookup for common vendors
                vendor, device_type = get_vendor_info_sync(mac)
                device_history[mac]['vendor'] = vendor
                device_history[mac]['device_type'] = device_type
                
                # If vendor is still unknown, queue a background lookup
                if vendor == "Unknown":
                    def vendor_update_callback(mac_addr, found_vendor, found_device_type):
                        """Callback to update device when vendor is found"""
                        if mac_addr in device_history:
                            device_history[mac_addr]['vendor'] = found_vendor
                            device_history[mac_addr]['device_type'] = found_device_type
                            print(f"Background vendor lookup completed: {mac_addr} -> {found_vendor} ({found_device_type})")
                    
                    request_vendor_lookup_async(mac, vendor_update_callback)
                
        else:
            device = device_history[mac]
            device['last_seen'] = datetime.now().isoformat()
            device['ip'] = ip
            
            if ip in packet_stats:
                device['traffic']['packets'] = packet_stats[ip]['packets']
                device['traffic']['bytes'] = packet_stats[ip]['bytes']
                
                new_ports = []
                for port in packet_stats[ip]['ports']:
                    service = get_service_name(port)
                    new_ports.append({
                        'port': port,
                        'service': service,
                        'state': 'open'
                    })
                device['ports'] = new_ports
                
                alerts = check_device_alerts(mac, device)
                if alerts:
                    device['suspicious'] = True
                    schedule_alert_notification(alerts)
                
    except Exception as e:
        print(f"Error updating device info: {str(e)}")

def schedule_alert_notification(alerts):
    """Schedule alert notification safely"""
    global websocket_server_active
    
    # Don't try to send if no WebSocket server is active
    if not websocket_server_active or not connected_clients:
        return
        
    try:
        # Try to get the current event loop
        try:
            loop = asyncio.get_running_loop()
            # Verify we have valid WebSocket connections before creating task
            if connected_clients:
                # Check if any clients are still connected
                valid_clients = []
                for client in connected_clients:
                    try:
                        # Only include clients that appear to be properly connected
                        if hasattr(client, 'client_state') and client.client_state.name == 'CONNECTED':
                            valid_clients.append(client)
                    except:
                        pass
                
                if valid_clients:
                    # Event loop is running and we have valid clients, create task
                    asyncio.create_task(notify_clients_alerts(alerts))
        except RuntimeError:
            # No event loop running, skip WebSocket notifications silently
            pass
            
    except Exception as e:
        # Silently handle WebSocket errors to prevent spam
        pass

def schedule_device_notification(device_mac: str):
    """Schedule device update notification safely"""
    global websocket_server_active
    
    # Don't try to send if no WebSocket server is active
    if not websocket_server_active or not connected_clients:
        return
        
    try:
        # Try to get the current event loop
        try:
            loop = asyncio.get_running_loop()
            # Verify we have valid WebSocket connections before creating task
            if connected_clients:
                # Check if any clients are still connected
                valid_clients = []
                for client in connected_clients:
                    try:
                        # Only include clients that appear to be properly connected
                        if hasattr(client, 'client_state') and client.client_state.name == 'CONNECTED':
                            valid_clients.append(client)
                    except:
                        pass
                
                if valid_clients:
                    # Event loop is running and we have valid clients, create task
                    asyncio.create_task(notify_device_update(device_mac))
        except RuntimeError:
            # No event loop running, skip WebSocket notifications silently
            pass
            
    except Exception as e:
        # Silently handle WebSocket errors to prevent spam
        pass

def get_service_name(port: int) -> str:
    """Get service name for common ports"""
    common_ports = {
        80: 'http',
        443: 'https',
        22: 'ssh',
        21: 'ftp',
        23: 'telnet',
        445: 'smb',
        3389: 'rdp',
        8080: 'http-proxy',
        53: 'dns',
        67: 'dhcp',
        68: 'dhcp',
        137: 'netbios',
        138: 'netbios',
        139: 'netbios',
        161: 'snmp',
        162: 'snmp'
    }
    return common_ports.get(port, 'unknown')

def start_packet_capture(interface: str):
    """Start packet capture on specified interface"""
    global is_sniffing
    is_sniffing = True
    
    def sniffer():
        try:
            print(f"Starting packet capture on interface {interface}")
            # On Windows, we need to use the interface GUID
            if platform.system() == "Windows":
                interfaces = get_windows_interfaces()
                interface_to_use = None
                
                # First try to find by name
                for guid, info in interfaces.items():
                    if info['name'] == interface:
                        interface_to_use = guid
                        break
                
                # If not found by name, try using the interface directly
                if not interface_to_use:
                    if interface in interfaces:
                        interface_to_use = interface
                    else:
                        # Try to find any valid interface
                        for guid, info in interfaces.items():
                            if info['ip'] and not info['ip'].startswith('127.'):
                                print(f"Using alternative interface: {info['name']} ({guid})")
                                interface_to_use = guid
                                break
                
                if not interface_to_use:
                    print("No suitable network interface found. Available interfaces:")
                    for guid, info in interfaces.items():
                        print(f"  - {info['name']} ({guid}): {info.get('ip', 'No IP')}")
                    return
                
                print(f"Using network interface: {interfaces[interface_to_use]['name']} ({interface_to_use})")
                sniff(iface=interface_to_use, prn=packet_callback, store=0, 
                      filter="ip or arp", stop_filter=lambda _: not is_sniffing)
            else:
                # For non-Windows systems
                sniff(iface=interface, prn=packet_callback, store=0, 
                      filter="ip or arp", stop_filter=lambda _: not is_sniffing)
                
        except Exception as e:
            print(f"Error in packet capture: {str(e)}")
            print("Available interfaces:")
            interfaces = get_windows_interfaces()
            for guid, info in interfaces.items():
                print(f"  - {info['name']} ({guid}): {info.get('ip', 'No IP')}")
    
    global sniffer_thread
    if sniffer_thread is None or not sniffer_thread.is_alive():
        sniffer_thread = Thread(target=sniffer)
        sniffer_thread.daemon = True
        sniffer_thread.start()

async def get_network_info():
    """Get local network information"""
    try:
        interface_guid, gateway_ip, interface_name = get_default_gateway()
        
        if interface_guid and gateway_ip:
            # Get interface information
            if platform.system() == "Windows":
                interfaces = get_windows_interfaces()
                if interface_guid in interfaces:
                    iface_info = interfaces[interface_guid]
                    if iface_info['ip'] and iface_info['netmask']:
                        print(f"Using interface {interface_name} with IP {iface_info['ip']}")
                        return {
                            'interface': interface_name,
                            'ip': iface_info['ip'],
                            'netmask': iface_info['netmask'],
                            'gateway': gateway_ip
                        }
            
            # Fallback to netifaces
            addrs = netifaces.ifaddresses(interface_guid)
            if netifaces.AF_INET in addrs:
                ip = addrs[netifaces.AF_INET][0]['addr']
                netmask = addrs[netifaces.AF_INET][0]['netmask']
                print(f"Using interface {interface_name} with IP {ip}")
                return {
                    'interface': interface_name,
                    'ip': ip,
                    'netmask': netmask,
                    'gateway': gateway_ip
                }
        
        # Fallback: try all interfaces
        interfaces = get_windows_interfaces()
        for guid, info in interfaces.items():
            if info['ip'] and not info['ip'].startswith('127.'):
                print(f"Fallback: using interface {info['name']} with IP {info['ip']}")
                return {
                    'interface': info['name'],
                    'ip': info['ip'],
                    'netmask': info['netmask'],
                    'gateway': None
                }
    except Exception as e:
        print(f"Error getting network info: {str(e)}")
    return None

async def scan_network():
    """Enhanced network scanning with multiple techniques"""
    try:
        print("Starting network scan process...")
        network_info = await get_network_info()
        if not network_info:
            print("No suitable network interface found")
            return []
        
        print(f"Using interface: {network_info['interface']} ({network_info['ip']})")
        
        # Start packet capture if not already running
        start_packet_capture(network_info['interface'])
        
        # Perform multiple ARP scans with different techniques
        network = f"{network_info['ip']}/24"
        print(f"Scanning network: {network}")
        
        try:
            # Standard ARP scan
            print("Performing ARP scan...")
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=network), timeout=2, verbose=False)
            print(f"ARP scan found {len(ans)} devices")
            for sent, recv in ans:
                update_device_info(recv.psrc, recv.src, skip_vendor_lookup=True)
            
            if stop_scan_event.is_set():
                print("Scan stopped by user")
                return list(device_history.values())
            
            # Targeted scans for mobile device ports
            print("Performing targeted port scans...")
            for port in [62078, 5353, 137, 138]:  # Common mobile device ports
                if stop_scan_event.is_set():
                    break
                print(f"Scanning port {port}...")
                ans, _ = srp(
                    Ether(dst="ff:ff:ff:ff:ff:ff")/
                    IP(dst=network)/
                    UDP(dport=port),
                    timeout=1,
                    verbose=False
                )
                for sent, recv in ans:
                    if IP in recv and Ether in recv:
                        update_device_info(recv[IP].src, recv[Ether].src, skip_vendor_lookup=True)
            
            if stop_scan_event.is_set():
                print("Scan stopped by user")
                return list(device_history.values())
            
            # mDNS discovery
            print("Performing mDNS discovery...")
            mdns_query = (
                IP(dst="224.0.0.251")/
                UDP(sport=5353, dport=5353)/
                DNS(
                    qr=0, opcode=0, aa=0, rd=0, ra=0,
                    qd=DNSQR(qname="_services._dns-sd._udp.local", qtype="PTR")
                )
            )
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/mdns_query, timeout=2, verbose=False)
            for sent, recv in ans:
                if IP in recv and Ether in recv:
                    update_device_info(recv[IP].src, recv[Ether].src, skip_vendor_lookup=True)
            
        except Exception as e:
            print(f"Error during network scanning: {str(e)}")
        
        if stop_scan_event.is_set():
            print("Scan stopped by user")
            return list(device_history.values())
        
        # Add a small delay to allow for packet processing
        print("Processing captured packets...")
        await asyncio.sleep(2)
        
        # After scan is complete, queue vendor lookups for all devices with unknown vendors
        if not stop_scan_event.is_set():
            print("Queuing background vendor lookups...")
            for mac in list(device_history.keys()):
                device = device_history[mac]
                if device['vendor'] == "Unknown":
                    def create_callback(device_mac):
                        def vendor_callback(mac_addr, found_vendor, found_device_type):
                            if mac_addr in device_history:
                                device_history[mac_addr]['vendor'] = found_vendor
                                device_history[mac_addr]['device_type'] = found_device_type
                                print(f"Scan vendor lookup complete: {mac_addr} -> {found_vendor}")
                        return vendor_callback
                    
                    request_vendor_lookup_async(mac, create_callback(mac))
        
        # Convert device history to list and return
        devices = list(device_history.values())
        print(f"Scan complete. Found {len(devices)} devices")
        return devices
        
    except Exception as e:
        print(f"Error in scan_network: {str(e)}")
        return []

async def safe_notify_clients_alerts(alerts):
    """Safely notify all connected clients of new alerts with proper error handling"""
    if not connected_clients:
        return
        
    disconnected_clients = []
    for client in list(connected_clients):  # Create a copy to avoid modification during iteration
        try:
            # Simply try to send and catch any exceptions
            await client.send_json({
                'type': 'alerts',
                'data': alerts
            })
        except Exception as e:
            print(f"Error sending alert to client: {e}")
            disconnected_clients.append(client)
    
    # Remove disconnected clients
    for client in disconnected_clients:
        if client in connected_clients:
            connected_clients.remove(client)
            print(f"Removed disconnected client. Remaining: {len(connected_clients)}")

async def notify_clients_alerts(alerts):
    """Notify all connected clients of new alerts"""
    try:
        print(f"notify_clients_alerts called with {len(alerts)} alerts, {len(connected_clients)} clients")
        
        if not connected_clients:
            print("No connected clients to notify")
            return
            
        await safe_notify_clients_alerts(alerts)
    except Exception as e:
        print(f"Error in notify_clients_alerts: {e}")

async def notify_device_update(device_mac: str):
    """Notify all connected clients of device updates"""
    if device_mac not in device_history:
        print(f"Device {device_mac} not found in history")
        return
        
    if not connected_clients:
        print("No connected clients for device update")
        return
        
    device = device_history[device_mac]
    disconnected_clients = []
    
    print(f"Sending device update for {device_mac} to {len(connected_clients)} clients")
    
    for client in list(connected_clients):  # Create a copy to avoid modification during iteration
        try:
            # Check if WebSocket is still open before sending
            if hasattr(client, 'client_state') and client.client_state.name != 'CONNECTED':
                print(f"WebSocket client not connected (state: {client.client_state.name}), marking for removal")
                disconnected_clients.append(client)
                continue
                
            await client.send_json({
                'type': 'device_info',
                'data': device
            })
            print(f"Successfully sent device update for {device_mac}")
        except Exception as e:
            print(f"Error sending device update to client for {device_mac}: {e}")
            disconnected_clients.append(client)
    
    # Remove disconnected clients
    for client in disconnected_clients:
        if client in connected_clients:
            connected_clients.remove(client)
            print(f"Removed disconnected client. Remaining: {len(connected_clients)}")
            
    # Update server active status if no clients left
    global websocket_server_active
    if len(connected_clients) == 0:
        websocket_server_active = False
        print("No more WebSocket clients, marking server as inactive")

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    global websocket_server_active
    try:
        print("New WebSocket connection attempt")
        await websocket.accept()
        connected_clients.append(websocket)
        websocket_server_active = True  # Mark server as active
        print(f"Client connected. Total clients: {len(connected_clients)}")
        
        # Send initial connection confirmation
        await websocket.send_json({
            'type': 'connection_status',
            'status': 'connected'
        })
        
        # Send initial alerts
        await websocket.send_json({
            'type': 'alerts',
            'data': alert_history[-100:]  # Send last 100 alerts
        })
        
        # Initial scan without auto-update
        try:
            stop_scan_event.clear()  # Reset stop event
            print("Starting initial network scan...")
            devices = await scan_network()
            
            # Verify WebSocket is still connected before sending
            if websocket in connected_clients:
                try:
                    # Check WebSocket state before sending
                    if hasattr(websocket, 'client_state') and websocket.client_state.name != 'CONNECTED':
                        print("WebSocket disconnected during initial scan, skipping update")
                        return
                        
                    await websocket.send_json({
                        'type': 'network_update',
                        'data': devices
                    })
                    print("Initial scan completed and results sent to client")
                except Exception as send_error:
                    print(f"Error sending initial scan results: {send_error}")
                    # Remove client from connected list if send failed
                    if websocket in connected_clients:
                        connected_clients.remove(websocket)
            else:
                print("Client disconnected during initial scan")
                
        except Exception as e:
            print(f"Error during initial scan: {str(e)}")
        
        while True:
            try:
                message = await asyncio.wait_for(
                    websocket.receive_text(),
                    timeout=30.0
                )
                
                try:
                    data = json.loads(message)
                except json.JSONDecodeError:
                    continue
                
                message_type = data.get('type', '')
                print(f"Received message type: {message_type}")
                
                if message_type == 'ping':
                    if websocket in connected_clients:
                        await websocket.send_json({'type': 'pong'})
                
                elif message_type == 'manual_scan':
                    print("Manual scan requested - initiating scan...")
                    stop_scan_event.clear()  # Reset stop event
                    
                    # Notify scan start immediately
                    if websocket in connected_clients:
                        await websocket.send_json({
                            'type': 'scan_start'
                        })
                    
                    # Start scan in background task
                    async def perform_scan():
                        try:
                            devices = await scan_network()
                            
                            # Verify WebSocket is still connected before sending
                            if websocket in connected_clients:
                                try:
                                    # Check WebSocket state before sending
                                    if hasattr(websocket, 'client_state') and websocket.client_state.name != 'CONNECTED':
                                        print("WebSocket disconnected during manual scan, skipping results")
                                        return
                                        
                                    await websocket.send_json({
                                        'type': 'network_update',
                                        'data': devices
                                    })
                                    await websocket.send_json({
                                        'type': 'scan_complete'
                                    })
                                    print("Manual scan completed and results sent to client")
                                except Exception as send_error:
                                    print(f"Error sending manual scan results: {send_error}")
                                    # Remove client from connected list if send failed
                                    if websocket in connected_clients:
                                        connected_clients.remove(websocket)
                            else:
                                print("Client disconnected during manual scan")
                                
                        except Exception as e:
                            print(f"Error during manual scan: {str(e)}")
                    
                    asyncio.create_task(perform_scan())
                
                elif message_type == 'stop_scan':
                    print("Stop scan requested")
                    stop_scan_event.set()  # Set stop event
                    if websocket in connected_clients:
                        await websocket.send_json({
                            'type': 'scan_stopped'
                        })
                
                elif message_type == 'toggle_auto_scan':
                    global auto_scan
                    auto_scan = data.get('enabled', False)
                    print(f"Auto scan toggled: {auto_scan}")
                    if auto_scan:
                        stop_scan_event.clear()
                    else:
                        stop_scan_event.set()
                    if websocket in connected_clients:
                        await websocket.send_json({
                            'type': 'auto_scan_status',
                            'enabled': auto_scan
                        })
                
                elif message_type == 'get_device_info':
                    device_mac = data.get('mac')
                    print(f"Device info requested for MAC: {device_mac}")
                    if device_mac in device_history and websocket in connected_clients:
                        device = device_history[device_mac]
                        
                        # If vendor is unknown, queue a background lookup
                        if device['vendor'] == "Unknown" or device['device_type'] == "Unknown":
                            print(f"Starting background vendor lookup for MAC: {device_mac}")
                            
                            def vendor_callback(mac_addr, found_vendor, found_device_type):
                                """Callback to update device info safely"""
                                try:
                                    if mac_addr in device_history:
                                        device_history[mac_addr]['vendor'] = found_vendor
                                        device_history[mac_addr]['device_type'] = found_device_type
                                        print(f"Background lookup complete - Vendor: {found_vendor}, Type: {found_device_type}")
                                        
                                        # Only schedule notification if we have active WebSocket connections
                                        if websocket_server_active and connected_clients:
                                            schedule_device_notification(mac_addr)
                                except Exception as e:
                                    print(f"Error in vendor callback for {mac_addr}: {e}")
                            
                            request_vendor_lookup_async(device_mac, vendor_callback)
                        
                        await websocket.send_json({
                            'type': 'device_info',
                            'data': device
                        })
                
                elif message_type == 'get_device_traffic':
                    device_mac = data.get('mac')
                    if device_mac in device_history and websocket in connected_clients:
                        device = device_history[device_mac]
                        await websocket.send_json({
                            'type': 'device_traffic',
                            'mac': device_mac,
                            'data': {
                                'traffic': device['traffic'],
                                'ports': device['ports'],
                                'connections': dict(device['traffic']['connections'])
                            }
                        })
                
            except asyncio.TimeoutError:
                try:
                    if websocket in connected_clients:
                        await websocket.send_json({'type': 'ping'})
                except:
                    break
                
                if auto_scan and not stop_scan_event.is_set() and websocket in connected_clients:
                    try:
                        print("Auto scan triggered")
                        devices = await scan_network()
                        
                        # Verify WebSocket is still connected before sending
                        if websocket in connected_clients:
                            try:
                                # Check WebSocket state before sending
                                if hasattr(websocket, 'client_state') and websocket.client_state.name != 'CONNECTED':
                                    print("WebSocket disconnected during auto scan, skipping results")
                                    break
                                    
                                await websocket.send_json({
                                    'type': 'network_update',
                                    'data': devices
                                })
                                print("Auto scan completed and results sent to client")
                            except Exception as send_error:
                                print(f"Error sending auto scan results: {send_error}")
                                # Remove client from connected list if send failed
                                if websocket in connected_clients:
                                    connected_clients.remove(websocket)
                                break
                        else:
                            print("Client disconnected during auto scan")
                            break
                            
                    except Exception as e:
                        print(f"Error during auto scan: {str(e)}")
                
            except websockets.exceptions.ConnectionClosed:
                print("Connection closed by client")
                break
            
            except Exception as e:
                print(f"Error handling WebSocket message: {str(e)}")
                if "disconnect" in str(e).lower() or "connection" in str(e).lower():
                    break
                continue
                
    except Exception as e:
        print(f"WebSocket error during setup: {str(e)}")
        
    finally:
        if websocket in connected_clients:
            connected_clients.remove(websocket)
            print(f"Client disconnected. Remaining clients: {len(connected_clients)}")
        
        # Update server active status
        if len(connected_clients) == 0:
            websocket_server_active = False
            print("No more WebSocket clients, marking server as inactive")
        
        try:
            await websocket.close()
        except:
            pass

@app.get("/api/devices")
async def get_devices():
    """Get current network devices"""
    devices = await scan_network()
    return {"devices": devices}

@app.get("/api/interfaces")
async def get_interfaces():
    """Get available network interfaces"""
    if platform.system() == "Windows":
        return {"interfaces": get_windows_interfaces()}
    return {"interfaces": {}}

@app.get("/api/history")
async def get_device_history():
    """Get device history"""
    return {"history": device_history}

@app.post("/api/security/ping")
async def ping_device(request: dict):
    """Ping a specific device"""
    ip = request.get('ip')
    count = request.get('count', 4)
    
    if not ip:
        return {"error": "IP address required"}
    
    try:
        result = network_defense.ping_device(ip, count)
        return {"ping_result": result}
    except Exception as e:
        print(f"Error pinging device: {e}")
        return {"error": f"Failed to ping device: {str(e)}"}

@app.post("/api/security/deauth")
async def deauth_device(request: dict):
    """Deauthenticate a device from the network"""
    target_mac = request.get('target_mac')
    gateway_mac = request.get('gateway_mac')
    interface = request.get('interface')
    
    if not target_mac or not gateway_mac:
        return {"error": "Target MAC and Gateway MAC required"}
    
    try:
        result = network_defense.deauth_device(target_mac, gateway_mac, interface)
        return {"deauth_result": result}
    except Exception as e:
        print(f"Error deauthenticating device: {e}")
        return {"error": f"Failed to deauthenticate device: {str(e)}"}

@app.post("/api/security/block")
async def block_device(request: dict):
    """Block a device using various methods"""
    target_ip = request.get('target_ip')
    target_mac = request.get('target_mac') 
    gateway_ip = request.get('gateway_ip')
    method = request.get('method', 'arp')
    
    if not target_ip or not target_mac:
        return {"error": "Target IP and MAC required"}
    
    try:
        if method == 'arp':
            result = network_defense.block_device_arp(target_ip, target_mac, gateway_ip)
        else:
            result = {"error": "Unknown blocking method"}
        
        return {"block_result": result}
    except Exception as e:
        print(f"Error blocking device: {e}")
        return {"error": f"Failed to block device: {str(e)}"}

@app.post("/api/security/quarantine")
async def quarantine_device(request: dict):
    """Quarantine a suspicious device"""
    mac = request.get('mac')
    reason = request.get('reason', 'Manual quarantine')
    
    if not mac:
        return {"error": "MAC address required"}
    
    try:
        result = network_defense.quarantine_device(mac, reason)
        
        # Also update device status in history
        if mac in device_history:
            device_history[mac]['quarantined'] = True
            device_history[mac]['quarantine_reason'] = reason
        
        return {"quarantine_result": result}
    except Exception as e:
        print(f"Error quarantining device: {e}")
        return {"error": f"Failed to quarantine device: {str(e)}"}

@app.post("/api/security/release")
async def release_quarantine(request: dict):
    """Release device from quarantine"""
    mac = request.get('mac')
    
    if not mac:
        return {"error": "MAC address required"}
    
    try:
        result = network_defense.release_quarantine(mac)
        
        # Update device status in history
        if mac in device_history:
            device_history[mac]['quarantined'] = False
            device_history[mac].pop('quarantine_reason', None)
        
        return {"release_result": result}
    except Exception as e:
        print(f"Error releasing quarantine: {e}")
        return {"error": f"Failed to release quarantine: {str(e)}"}

@app.get("/api/security/alerts")
async def get_security_alerts():
    """Get recent security alerts"""
    try:
        alerts = security_monitor.get_alerts()
        return {"alerts": alerts}
    except Exception as e:
        print(f"Error getting security alerts: {e}")
        return {"alerts": []}

@app.post("/api/security/whitelist")
async def whitelist_device(request: dict):
    """Add device to whitelist"""
    mac = request.get('mac')
    
    if not mac:
        return {"error": "MAC address required"}
    
    try:
        device_info = device_history.get(mac, {})
        security_monitor.register_device(mac, device_info, is_authorized=True)
        security_monitor.whitelist_device(mac)
        
        return {"message": f"Device {mac} added to whitelist"}
    except Exception as e:
        print(f"Error whitelisting device: {e}")
        return {"error": f"Failed to whitelist device: {str(e)}"}

@app.post("/api/security/blacklist") 
async def blacklist_device(request: dict):
    """Add device to blacklist"""
    mac = request.get('mac')
    
    if not mac:
        return {"error": "MAC address required"}
    
    try:
        security_monitor.blacklist_device(mac)
        
        # Also quarantine the device
        network_defense.quarantine_device(mac, "Blacklisted device")
        
        return {"message": f"Device {mac} added to blacklist"}
    except Exception as e:
        print(f"Error blacklisting device: {e}")
        return {"error": f"Failed to blacklist device: {str(e)}"}

@app.post("/api/security/scan-vulnerabilities")
async def scan_vulnerabilities(request: dict):
    """Scan device for vulnerabilities"""
    ip = request.get('ip')
    ports = request.get('ports')
    
    if not ip:
        return {"error": "IP address required"}
    
    try:
        result = await vulnerability_scanner.scan_device_vulnerabilities(ip, ports)
        return {"vulnerability_scan": result}
    except Exception as e:
        print(f"Error scanning vulnerabilities: {e}")
        return {"error": f"Failed to scan vulnerabilities: {str(e)}"}

@app.get("/api/security/vulnerability-results/{ip}")
async def get_vulnerability_results(ip: str):
    """Get vulnerability scan results for device"""
    try:
        results = vulnerability_scanner.get_scan_results(ip)
        return {"results": results}
    except Exception as e:
        print(f"Error getting vulnerability results: {e}")
        return {"results": {}}

@app.post("/api/security/test-alert")
async def create_test_alert(request: dict):
    """Create a test security alert for debugging"""
    alert_type = request.get('type', 'test')
    severity = request.get('severity', 'medium')
    message = request.get('message', 'Test security alert')
    details = request.get('details', {})
    
    try:
        # Generate test alert using security monitor
        security_monitor._generate_alert(alert_type, severity, message, details)
        
        return {"message": "Test alert generated", "type": alert_type}
    except Exception as e:
        print(f"Error creating test alert: {e}")
        return {"error": f"Failed to create test alert: {str(e)}"}

@app.get("/api/security/trust-score/{mac}")
async def get_trust_score(mac: str):
    """Get trust score for device"""
    try:
        score = security_monitor.get_device_trust_score(mac)
        return {"trust_score": score}
    except Exception as e:
        print(f"Error getting trust score: {e}")
        return {"trust_score": 0}

@app.get("/api/security/quarantined")
async def get_quarantined_devices():
    """Get list of quarantined devices"""
    try:
        devices = network_defense.get_quarantined_devices()
        return {"quarantined_devices": devices}
    except Exception as e:
        print(f"Error getting quarantined devices: {e}")
        return {"quarantined_devices": []}

@app.get("/api/security/blocked")
async def get_blocked_devices():
    """Get list of blocked devices"""
    try:
        devices = network_defense.get_blocked_devices()
        return {"blocked_devices": devices}
    except Exception as e:
        print(f"Error getting blocked devices: {e}")
        return {"blocked_devices": []}

async def probe_device(ip: str, mac: str) -> dict:
    """Actively probe a device to gather more information"""
    device_info = {
        'os_type': 'Unknown',
        'open_ports': set(),
        'response_time': None,
        'is_up': False
    }
    
    try:
        # Send ICMP ping to check if device is up and get response time
        print(f"Sending ping to {ip}")
        ping_packet = IP(dst=ip)/ICMP()
        start_time = time.time()
        reply = await asyncio.get_event_loop().run_in_executor(
            thread_pool,
            lambda: sr1(ping_packet, timeout=1, verbose=0)
        )
        if reply:
            device_info['is_up'] = True
            device_info['response_time'] = (time.time() - start_time) * 1000
            device_info['ttl'] = reply.ttl
        
        # Quick port scan for most common ports
        print(f"Scanning common ports for {ip}")
        nm = nmap.PortScanner()
        common_ports = ','.join(map(str, [80, 443, 22, 23, 445, 139, 135, 8080, 8883, 1883, 62078, 5353]))
        await asyncio.get_event_loop().run_in_executor(
            thread_pool,
            lambda: nm.scan(ip, arguments=f'-n -Pn -sS -p{common_ports} --max-retries 1 --min-rate 1000')
        )
        
        if ip in nm.all_hosts():
            for port in nm[ip].all_tcp():
                if nm[ip]['tcp'][port]['state'] == 'open':
                    device_info['open_ports'].add(port)
        
        # Try service detection on open ports
        if device_info['open_ports']:
            ports_str = ','.join(map(str, list(device_info['open_ports'])[:5]))  # Limit to 5 ports
            await asyncio.get_event_loop().run_in_executor(
                thread_pool,
                lambda: nm.scan(ip, arguments=f'-sV -p{ports_str} --version-intensity 5')
            )
            
            if ip in nm.all_hosts():
                for port in nm[ip]['tcp']:
                    if 'product' in nm[ip]['tcp'][port]:
                        device_info['service_' + str(port)] = nm[ip]['tcp'][port]['product']
        
        return device_info
    except Exception as e:
        print(f"Error probing device {ip}: {e}")
        return device_info

def calculate_device_type_confidence(device_info: dict, ports: set) -> List[Tuple[str, float]]:
    """Calculate confidence scores for each device type"""
    scores = []
    
    for device_type, signature in PORT_SIGNATURES.items():
        score = 0.0
        required_ports = set(signature['required'])
        optional_ports = set(signature['optional'])
        weight = signature['weight']
        
        # Check required ports
        if required_ports and required_ports.intersection(ports):
            score += 0.6 * weight
        
        # Check optional ports
        optional_matches = len(optional_ports.intersection(ports))
        if optional_matches:
            score += (0.4 * weight * optional_matches / len(optional_ports))
        
        # Adjust score based on TTL if available
        if 'ttl' in device_info:
            ttl = device_info['ttl']
            if device_type == 'Network Device' and ttl > 240:
                score += 0.2
            elif device_type == 'Computer' and 100 <= ttl <= 128:
                score += 0.2
            elif device_type == 'Mobile Device' and 30 <= ttl <= 64:
                score += 0.2
        
        # Adjust score based on response time
        if device_info.get('response_time'):
            if device_type == 'Network Device' and device_info['response_time'] < 10:
                score += 0.1
            elif device_type in ['Computer', 'Gaming Console'] and device_info['response_time'] < 20:
                score += 0.1
        
        # Check service banners
        for port, service in device_info.items():
            if port.startswith('service_') and isinstance(service, str):
                service_lower = service.lower()
                if device_type == 'IoT Device' and any(x in service_lower for x in ['busybox', 'embedded']):
                    score += 0.2
                elif device_type == 'Network Device' and any(x in service_lower for x in ['cisco', 'router']):
                    score += 0.2
                elif device_type == 'Computer' and any(x in service_lower for x in ['windows', 'ubuntu', 'apache']):
                    score += 0.2
        
        scores.append((device_type, min(score, 1.0)))
    
    return sorted(scores, key=lambda x: x[1], reverse=True)

@app.get("/api/config")
async def get_configuration():
    """Get current configuration"""
    return get_config()

@app.post("/api/config/{section}/{key}")
async def update_configuration(section: str, key: str, request: dict):
    """Update configuration value"""
    value = request.get('value')
    
    if update_config(section, key, value):
        return {"message": f"Updated {section}.{key} to {value}"}
    else:
        return {"error": f"Invalid section or key: {section}.{key}"}

@app.get("/api/config/{section}")
async def get_section_config(section: str):
    """Get configuration for specific section"""
    config = get_config()
    if section in config:
        return {section: config[section]}
    else:
        return {"error": f"Section '{section}' not found"}

@app.get("/api/system/status")
async def get_system_status():
    """Get system performance and status"""
    import psutil
    
    cpu_percent = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    
    return {
        "cpu_usage": cpu_percent,
        "memory_usage": memory.percent,
        "memory_available": memory.available,
        "disk_usage": disk.percent,
        "disk_free": disk.free,
        "active_devices": len(device_history),
        "security_alerts": len(security_monitor.get_alerts()),
        "quarantined_devices": len(network_defense.get_quarantined_devices()),
        "blocked_devices": len(network_defense.get_blocked_devices()),
    }

@app.post("/api/system/reset")
async def reset_system():
    """Reset system data (clear device history, alerts, etc.)"""
    global device_history
    device_history.clear()
    
    # Reset security monitoring
    security_monitor.clear_alerts()
    network_defense.clear_quarantine()
    network_defense.clear_blocks()
    
    return {"message": "System data reset successfully"}

@app.post("/api/security/hash-file")
async def hash_local_file(file: UploadFile = File(...)):
    """Calculate hashes for a local file without uploading to VirusTotal"""
    try:
        content = await file.read()
        
        # Calculate multiple hash types
        md5_hash = hashlib.md5(content).hexdigest()
        sha1_hash = hashlib.sha1(content).hexdigest()
        sha256_hash = hashlib.sha256(content).hexdigest()
        
        return {
            "filename": file.filename,
            "size": len(content),
            "hashes": {
                "md5": md5_hash,
                "sha1": sha1_hash,
                "sha256": sha256_hash
            }
        }
    except Exception as e:
        print(f"Error calculating file hashes: {e}")
        return {"error": str(e)}

@app.get("/api/security/virustotal-report/{file_id}")
async def get_virustotal_report(file_id: str, api_key: str):
    """Get VirusTotal file report using file hash (SHA-256, SHA-1, or MD5)"""
    try:
        if not api_key:
            return {"error": "API key is required"}
        
        url = f"https://www.virustotal.com/api/v3/files/{file_id}"
        headers = {
            "accept": "application/json",
            "x-apikey": api_key
        }
        
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            
            # Extract relevant information
            attributes = data.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            
            return {
                "file_id": file_id,
                "scan_date": attributes.get("last_analysis_date"),
                "stats": stats,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "undetected": stats.get("undetected", 0),
                "harmless": stats.get("harmless", 0),
                "timeout": stats.get("timeout", 0),
                "confirmed-timeout": stats.get("confirmed-timeout", 0),
                "failure": stats.get("failure", 0),
                "type-unsupported": stats.get("type-unsupported", 0),
                "total_scans": sum(stats.values()) if stats else 0,
                "detection_ratio": f"{stats.get('malicious', 0)}/{sum(stats.values())}" if stats else "0/0",
                "engines": attributes.get("last_analysis_results", {}),
                "file_info": {
                    "size": attributes.get("size"),
                    "type": attributes.get("type_description"),
                    "magic": attributes.get("magic"),
                    "md5": attributes.get("md5"),
                    "sha1": attributes.get("sha1"), 
                    "sha256": attributes.get("sha256"),
                    "names": attributes.get("names", [])
                },
                "permalink": f"https://www.virustotal.com/gui/file/{file_id}",
                "raw_response": data
            }
        elif response.status_code == 404:
            return {
                "file_id": file_id,
                "status": "not_found",
                "message": "File not found in VirusTotal database. This could mean the file has never been scanned before.",
                "suggestion": "Consider uploading the file to VirusTotal for analysis if you believe it should be scanned."
            }
        else:
            return {
                "error": f"VirusTotal API error: {response.status_code}",
                "message": response.text,
                "file_id": file_id
            }
            
    except requests.exceptions.RequestException as e:
        print(f"Network error querying VirusTotal: {e}")
        return {"error": f"Network error: {str(e)}"}
    except Exception as e:
        print(f"Error querying VirusTotal: {e}")
        return {"error": str(e)}

@app.post("/api/security/scan-file")
async def api_scan_file(file: UploadFile = File(...), api_key: str = Form(None)):
    """Upload a file to VirusTotal for scanning (api_key optional in form)."""
    try:
        content = await file.read()
        hashes = VirusTotalScanner().compute_hashes(content)

        # If API key provided, set it on the module scanner for lookup/upload
        if api_key:
            try:
                vt_scanner.set_api_key(api_key)
            except Exception as e:
                print(f"Warning: could not set vt api key: {e}")

        # If module scanner has an API key, try to upload
        if vt_scanner.api_key:
            try:
                upload_result = vt_scanner.upload_file(content, filename=file.filename)
            except Exception as e:
                upload_result = {"status": "error", "detail": str(e)}
        else:
            upload_result = {"status": "no_api_key", "detail": "No API key provided; computed hashes returned"}

        return {"hashes": hashes, "upload": upload_result}
    except Exception as e:
        print(f"Error in scan-file endpoint: {e}")
        return {"error": str(e)}

@app.get("/api/security/scan-hash/{hash_value}")
async def api_scan_hash(hash_value: str, api_key: str = None):
    """Lookup a file hash on VirusTotal. API key can be provided as query param."""
    try:
        if api_key:
            vt_scanner.set_api_key(api_key)

        if not vt_scanner.api_key:
            return {"status": "no_api_key", "detail": "Provide an API key to query VirusTotal"}

        result = vt_scanner.scan_hash(hash_value)
        return result
    except Exception as e:
        print(f"Error in scan-hash endpoint: {e}")
        return {"error": str(e)}

if __name__ == "__main__":
    # Start the vendor lookup service
    vendor_service.start()
    print("NetSentinel starting...")
    
    import uvicorn
    try:
        uvicorn.run(app, host=API_CONFIG["host"], port=API_CONFIG["port"])
    finally:
        # Stop the vendor service when shutting down
        vendor_service.stop()
        print("NetSentinel shutdown complete.")
