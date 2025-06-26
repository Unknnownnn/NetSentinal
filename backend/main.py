import asyncio
import json
from typing import Dict, List
from fastapi import FastAPI, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime
import nmap
import psutil
import socket
from scapy.all import ARP, Ether, srp, sniff, IP, TCP, UDP, DNS, DNSQR, DNSRR, conf
import netifaces
from threading import Thread
from collections import defaultdict
import platform
import re
import winreg
import requests
import websockets
import time
from pathlib import Path

# Load MAC vendors from JSON file
def load_mac_vendors():
    try:
        mac_vendors_path = Path(__file__).parent / 'mac-vendors.json'
        with open(mac_vendors_path, 'r') as f:
            # Skip the first line (comment) and parse the rest
            f.readline()  # Skip comment line
            vendors_data = json.load(f)
            
            # Convert to our format (MAC prefix -> Vendor name)
            mac_vendors = {}
            for vendor_name, prefixes in vendors_data.items():
                for prefix in prefixes:
                    mac_vendors[prefix.lower()] = vendor_name
            return mac_vendors
    except Exception as e:
        print(f"Error loading MAC vendors: {str(e)}")
        return {}

# Load MAC vendors at startup
MAC_VENDORS = load_mac_vendors()

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
auto_scan = True
mdns_thread = None

# Common ports for device identification
DEVICE_PORTS = {
    'Mobile Device': [62078, 62078, 5353, 137, 138],  # iOS & Android common ports
    'Smart TV': [3000, 3001, 8008, 8009, 7000],  # Smart TV ports
    'Gaming Console': [3074, 3075, 3076, 1935],  # Gaming ports
    'IoT Device': [8883, 1883, 80, 443, 8080],  # IoT common ports
    'Computer': [445, 139, 135, 22, 3389]  # Common computer ports
}

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
    """Enhanced packet processing for better device detection"""
    try:
        # Extract IP addresses and MAC addresses from various layers
        if ARP in packet:
            src_mac = packet[ARP].hwsrc
            src_ip = packet[ARP].psrc
            dst_mac = packet[ARP].hwdst
            dst_ip = packet[ARP].pdst
            
            # Update device info for both source and destination
            update_device_info(src_ip, src_mac)
            if dst_mac != "00:00:00:00:00:00":  # Ignore broadcast ARP requests
                update_device_info(dst_ip, dst_mac)
                
        elif IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            # Get MAC addresses from Ethernet layer
            if Ether in packet:
                src_mac = packet[Ether].src
                dst_mac = packet[Ether].dst
                update_device_info(src_ip, src_mac)
                update_device_info(dst_ip, dst_mac)
            
            # Update packet statistics
            packet_stats[src_ip]['packets'] += 1
            packet_stats[src_ip]['bytes'] += len(packet)
            packet_stats[src_ip]['last_seen'] = datetime.now()
            
            # Track protocols and ports
            if TCP in packet:
                sport = packet[TCP].sport
                dport = packet[TCP].dport
                packet_stats[src_ip]['ports'].add(sport)
                packet_stats[dst_ip]['ports'].add(dport)
                
            elif UDP in packet:
                sport = packet[UDP].sport
                dport = packet[UDP].dport
                packet_stats[src_ip]['ports'].add(sport)
                packet_stats[dst_ip]['ports'].add(dport)
                
                # Process DNS and mDNS packets
                if (sport == 53 or dport == 53 or  # DNS
                    sport == 5353 or dport == 5353):  # mDNS
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

def identify_device_type(mac: str, hostname: str, ports: set) -> tuple:
    """Enhanced device type identification"""
    mac = mac.replace(':', '').replace('-', '').lower()
    vendor = "Unknown"
    device_type = "Unknown"
    
    # Check MAC prefix against known vendors
    # Try different prefix lengths (6, 8, and 12 characters)
    for prefix_len in [6, 8, 12]:
        prefix = mac[:prefix_len]
        if prefix in MAC_VENDORS:
            vendor = MAC_VENDORS[prefix]
            break
    
    # Determine device type based on vendor name and common patterns
    vendor_lower = vendor.lower()
    if any(tv in vendor_lower for tv in ['tv', 'roku', 'vizio', 'samsung electronics', 'lg electronics']):
        device_type = 'Smart TV'
    elif any(mobile in vendor_lower for mobile in ['apple', 'iphone', 'ipad', 'samsung mobile', 'xiaomi', 'oneplus', 'oppo', 'vivo']):
        if any(port in ports for port in DEVICE_PORTS['Mobile Device']):
            device_type = 'Mobile Device'
        else:
            device_type = 'Computer'
    elif any(game in vendor_lower for game in ['nintendo', 'sony computer entertainment', 'microsoft xbox']):
        device_type = 'Gaming Console'
    elif any(iot in vendor_lower for iot in ['nest', 'ring', 'philips', 'ecobee', 'arlo']):
        device_type = 'IoT Device'
    
    # Check hostname patterns if device type is still unknown
    hostname_lower = hostname.lower()
    if device_type == "Unknown":
        if any(pattern in hostname_lower for pattern in [
            'iphone', 'ipad', 'android', 'galaxy', 'pixel', 'mobile',
            'phone', 'tablet', 'oneplus', 'xiaomi', 'huawei'
        ]):
            device_type = 'Mobile Device'
        elif any(pattern in hostname_lower for pattern in [
            'tv', 'roku', 'firetv', 'appletv', 'smarttv', 'bravia',
            'samsung-tv', 'lg-tv', 'vizio'
        ]):
            device_type = 'Smart TV'
        elif any(pattern in hostname_lower for pattern in [
            'xbox', 'playstation', 'ps4', 'ps5', 'nintendo',
            'switch', 'gaming'
        ]):
            device_type = 'Gaming Console'
        elif any(pattern in hostname_lower for pattern in [
            'echo', 'alexa', 'nest', 'hue', 'ring', 'cam',
            'thermostat', 'smartthings', 'iot'
        ]):
            device_type = 'IoT Device'
    
    # Check port patterns if still unknown
    if device_type == "Unknown":
        for device_type_name, device_ports in DEVICE_PORTS.items():
            if any(port in ports for port in device_ports):
                device_type = device_type_name
                break
    
    return vendor, device_type

def update_device_info(ip: str, mac: str):
    """Update device information based on captured packets"""
    try:
        if mac not in device_history:
            # Try to get hostname
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except:
                hostname = "Unknown"
            
            # Get ports from packet stats
            ports = set()
            if ip in packet_stats:
                ports = packet_stats[ip]['ports']
            
            # Identify device type and vendor
            vendor, device_type = identify_device_type(mac, hostname, ports)
            
            device_history[mac] = {
                'ip': ip,
                'hostname': hostname,
                'mac': mac,
                'vendor': vendor,
                'device_type': device_type,
                'last_seen': datetime.now().isoformat(),
                'status': 'active',
                'ports': [],
                'suspicious': False,
                'traffic': {
                    'packets': 0,
                    'bytes': 0
                }
            }
        else:
            # Update existing device
            device_history[mac]['last_seen'] = datetime.now().isoformat()
            device_history[mac]['ip'] = ip
            if ip in packet_stats:
                device_history[mac]['traffic'] = {
                    'packets': packet_stats[ip]['packets'],
                    'bytes': packet_stats[ip]['bytes']
                }
                # Update ports from packet stats
                new_ports = []
                for port in packet_stats[ip]['ports']:
                    service = get_service_name(port)
                    new_ports.append({
                        'port': port,
                        'service': service,
                        'state': 'open'
                    })
                device_history[mac]['ports'] = new_ports
                
                # Re-identify device type based on updated ports
                vendor, device_type = identify_device_type(
                    mac, 
                    device_history[mac]['hostname'],
                    packet_stats[ip]['ports']
                )
                device_history[mac]['vendor'] = vendor
                device_history[mac]['device_type'] = device_type
                
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
        network_info = await get_network_info()
        if not network_info:
            print("No suitable network interface found")
            return []
        
        # Start packet capture if not already running
        start_packet_capture(network_info['interface'])
        
        # Notify clients that scanning has started
        for client in connected_clients:
            try:
                await client.send_json({
                    'type': 'scan_start'
                })
            except:
                pass
        
        # Perform multiple ARP scans with different techniques
        network = f"{network_info['ip']}/24"
        print(f"Scanning network: {network}")
        
        try:
            # Standard ARP scan
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=network), timeout=2, verbose=False)
            for sent, recv in ans:
                update_device_info(recv.psrc, recv.src)
            
            # Targeted scans for mobile device ports
            for port in [62078, 5353, 137, 138]:  # Common mobile device ports
                ans, _ = srp(
                    Ether(dst="ff:ff:ff:ff:ff:ff")/
                    IP(dst=network)/
                    UDP(dport=port),
                    timeout=1,
                    verbose=False
                )
                for sent, recv in ans:
                    if IP in recv and Ether in recv:
                        update_device_info(recv[IP].src, recv[Ether].src)
            
            # mDNS discovery
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
                    update_device_info(recv[IP].src, recv[Ether].src)
            
        except Exception as e:
            print(f"Error in network scan: {str(e)}")
        
        # Add a small delay to allow for packet processing
        await asyncio.sleep(2)
        
        # Convert device history to list and return
        devices = list(device_history.values())
        print(f"Scan complete. Found {len(devices)} devices")
        return devices
        
    except Exception as e:
        print(f"Error in scan_network: {str(e)}")
        return []

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    connected_clients.append(websocket)
    print(f"Client connected. Total clients: {len(connected_clients)}")
    
    try:
        while True:
            try:
                # Check connection state before receiving
                if websocket.client_state.DISCONNECTED:
                    print("WebSocket disconnected, ending connection")
                    break
                
                # Use a timeout for receive to avoid blocking indefinitely
                data = await asyncio.wait_for(websocket.receive_json(), timeout=30)
                
                if data.get('type') == 'ping':
                    if not websocket.client_state.DISCONNECTED:
                        await websocket.send_json({'type': 'pong'})
                elif data.get('type') == 'manual_scan':
                    # Perform immediate scan
                    devices = await scan_network()
                    if not websocket.client_state.DISCONNECTED:
                        await websocket.send_json({
                            'type': 'network_update',
                            'data': devices
                        })
                elif data.get('type') == 'toggle_auto_scan':
                    global auto_scan
                    auto_scan = data.get('enabled', True)
                    if not websocket.client_state.DISCONNECTED:
                        await websocket.send_json({
                            'type': 'auto_scan_status',
                            'enabled': auto_scan
                        })
                
                # Only perform automatic scan if enabled
                if auto_scan and not websocket.client_state.DISCONNECTED:
                    try:
                        devices = await scan_network()
                        await websocket.send_json({
                            'type': 'network_update',
                            'data': devices
                        })
                    except Exception as e:
                        print(f"Error during auto scan: {str(e)}")
                        
                await asyncio.sleep(10)  # Wait between scans
                
            except asyncio.TimeoutError:
                # Connection is still alive, just no message received
                continue
            except websockets.exceptions.ConnectionClosed:
                print("Connection closed by client")
                break
            except Exception as e:
                print(f"Error handling WebSocket message: {str(e)}")
                # Only break if it's a connection-related error
                if "disconnect" in str(e).lower() or "connection" in str(e).lower():
                    break
                continue
            
    except Exception as e:
        print(f"WebSocket error: {str(e)}")
    finally:
        # Cleanup
        if websocket in connected_clients:
            connected_clients.remove(websocket)
            print(f"Client disconnected. Remaining clients: {len(connected_clients)}")
        
        # Ensure the websocket is closed
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

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000) 