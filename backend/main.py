import asyncio
import json
from typing import Dict, List, Tuple
from fastapi import FastAPI, WebSocket
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
import winreg
import requests
import websockets
import time
from pathlib import Path
from mac_vendor_lookup import MacLookup

# Initialize MAC lookup and thread pool
mac_lookup = MacLookup()
thread_pool = ThreadPoolExecutor(max_workers=4)
try:
    mac_lookup.update_vendors()
except Exception as e:
    print(f"Warning: Could not update MAC vendor database: {e}")

# Enhanced device type patterns
DEVICE_PATTERNS = {
    'Mobile Device': [
        'apple', 'iphone', 'ipad', 'samsung mobile', 'xiaomi', 'oneplus', 'oppo', 
        'vivo', 'huawei', 'honor', 'realme', 'motorola', 'lg electronics mobile',
        'android', 'mobile'
    ],
    'Smart TV': [
        'samsung electronics tv', 'lg tv', 'vizio', 'sony tv', 'tcl', 'hisense', 
        'roku', 'philips tv', 'sharp tv', 'panasonic tv', 'smarttv', 'appletv'
    ],
    'Gaming Console': [
        'nintendo', 'sony interactive entertainment', 'microsoft xbox', 'playstation',
        'nintendo switch', 'xbox', 'ps4', 'ps5'
    ],
    'IoT Device': [
        'nest', 'ring', 'ecobee', 'philips lighting', 'arlo', 'amazon technologies',
        'google home', 'sonos', 'belkin', 'smartthings', 'hue', 'zigbee', 'zwave'
    ],
    'Network Device': [
        'cisco', 'netgear', 'tp-link', 'd-link', 'ubiquiti', 'mikrotik', 'aruba',
        'ruckus', 'juniper', 'fortinet', 'palo alto', 'router', 'switch', 'ap'
    ]
}

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

def get_vendor_info_sync(mac: str) -> tuple:
    """Get vendor information from MAC address synchronously"""
    try:
        vendor_name = mac_lookup.lookup(mac)
        vendor_name_lower = vendor_name.lower()
        
        # Determine device type based on vendor patterns
        device_type = "Unknown"
        for type_name, patterns in DEVICE_PATTERNS.items():
            if any(pattern in vendor_name_lower for pattern in patterns):
                device_type = type_name
                break
                
        return vendor_name, device_type
    except Exception as e:
        print(f"Error looking up vendor for MAC {mac}: {e}")
        return "Unknown", "Unknown"

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
            for type_name, patterns in DEVICE_PATTERNS.items():
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

async def identify_device_type(mac: str, hostname: str, ports: set, ip: str = None) -> tuple:
    """Enhanced device type identification using multiple methods and active probing"""
    try:
        # Start with vendor lookup
        vendor, initial_type = get_vendor_info_sync(mac)
        
        if ip:
            # Actively probe the device
            print(f"Probing device {ip} ({mac})")
            device_info = await probe_device(ip, mac)
            
            # Get confidence scores for each device type
            if device_info['is_up']:
                all_ports = ports.union(device_info['open_ports'])
                device_scores = calculate_device_type_confidence(device_info, all_ports)
                
                # If we have a high confidence score, use that device type
                if device_scores and device_scores[0][1] >= 0.7:
                    return vendor, device_scores[0][0]
                
                # If initial type matches one of top 3 scores, keep it
                top_types = [score[0] for score in device_scores[:3]]
                if initial_type in top_types:
                    return vendor, initial_type
                
                # Otherwise use the highest confidence type
                if device_scores:
                    return vendor, device_scores[0][0]
        
        # Fallback to initial type or Unknown
        return vendor, initial_type if initial_type != "Unknown" else "Computer"
        
    except Exception as e:
        print(f"Error in identify_device_type for MAC {mac}: {e}")
        return "Unknown", "Unknown"

app = FastAPI(title="NetSentinel API")

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Store connected clients
connected_clients: List[WebSocket] = []
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
                vendor, device_type = get_vendor_info_sync(mac)
                device_history[mac]['vendor'] = vendor
                device_history[mac]['device_type'] = device_type
                
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
                    asyncio.create_task(notify_clients_alerts(alerts))
                
    except Exception as e:
        print(f"Error updating device info: {str(e)}")

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
        
        # After scan is complete, perform vendor lookup for all devices
        if not stop_scan_event.is_set():
            print("Performing vendor lookups...")
            for mac in list(device_history.keys()):
                try:
                    vendor, device_type = identify_device_type(
                        mac,
                        device_history[mac]['hostname'],
                        device_history[mac].get('ports', set())
                    )
                    device_history[mac]['vendor'] = vendor
                    device_history[mac]['device_type'] = device_type
                except Exception as e:
                    print(f"Error looking up vendor for {mac}: {e}")
        
        # Convert device history to list and return
        devices = list(device_history.values())
        print(f"Scan complete. Found {len(devices)} devices")
        return devices
        
    except Exception as e:
        print(f"Error in scan_network: {str(e)}")
        return []

async def notify_clients_alerts(alerts):
    """Notify all connected clients of new alerts"""
    for client in connected_clients:
        try:
            await client.send_json({
                'type': 'alerts',
                'data': alerts
            })
        except:
            continue

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    try:
        print("New WebSocket connection attempt")
        await websocket.accept()
        connected_clients.append(websocket)
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
            if websocket in connected_clients:  # Check if client is still connected
                await websocket.send_json({
                    'type': 'network_update',
                    'data': devices
                })
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
                            if websocket in connected_clients:
                                await websocket.send_json({
                                    'type': 'network_update',
                                    'data': devices
                                })
                                await websocket.send_json({
                                    'type': 'scan_complete'
                                })
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
                        # Perform vendor lookup when device info is requested
                        if device['vendor'] == "Unknown" or device['device_type'] == "Unknown":
                            try:
                                print(f"Starting vendor lookup for MAC: {device_mac}")
                                vendor, device_type = await identify_device_type(
                                    device_mac,
                                    device['hostname'],
                                    device.get('ports', set())
                                )
                                device['vendor'] = vendor
                                device['device_type'] = device_type
                                print(f"Updated device info - Vendor: {vendor}, Type: {device_type}")
                            except Exception as e:
                                print(f"Error updating device info: {e}")
                        
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
                        await websocket.send_json({
                            'type': 'network_update',
                            'data': devices
                        })
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

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000) 