#!/usr/bin/env python3
"""
Standalone Vendor Lookup Service for NetSentinel
Runs independently to avoid any conflicts with the main application
"""

import requests
import time
import json
import threading
import queue
from typing import Dict, Tuple, Optional
import socket

# Comprehensive OUI database for instant lookups
VENDOR_DATABASE = {
    # Apple devices
    '28:CF:E9': 'Apple', '00:03:93': 'Apple', '00:05:02': 'Apple', '00:0A:27': 'Apple',
    '00:0A:95': 'Apple', '00:0D:93': 'Apple', '00:11:24': 'Apple', '00:14:51': 'Apple',
    '00:16:CB': 'Apple', '00:17:F2': 'Apple', '00:19:E3': 'Apple', '00:1B:63': 'Apple',
    '00:1E:C2': 'Apple', '00:21:E9': 'Apple', '00:22:41': 'Apple', '00:23:12': 'Apple',
    '00:23:32': 'Apple', '00:23:6C': 'Apple', '00:23:DF': 'Apple', '00:24:36': 'Apple',
    '00:25:00': 'Apple', '00:25:4B': 'Apple', '00:25:BC': 'Apple', '00:26:08': 'Apple',
    '00:26:4A': 'Apple', '00:26:B0': 'Apple', '00:26:BB': 'Apple', '04:0C:CE': 'Apple',
    '04:15:52': 'Apple', '04:1E:64': 'Apple', '04:26:65': 'Apple', '04:48:9A': 'Apple',
    '04:4F:AA': 'Apple', '04:52:C7': 'Apple', '04:54:53': 'Apple', '04:69:F8': 'Apple',
    '04:DB:56': 'Apple', '04:E5:36': 'Apple', '04:F1:3E': 'Apple', '04:F7:E4': 'Apple',
    
    # Samsung devices
    '00:50:F2': 'Samsung', '00:12:FB': 'Samsung', '00:13:77': 'Samsung', '00:15:99': 'Samsung',
    '00:16:32': 'Samsung', '00:17:C9': 'Samsung', '00:1B:98': 'Samsung', '00:1C:43': 'Samsung',
    '00:1D:25': 'Samsung', '00:1E:7D': 'Samsung', '00:1F:CC': 'Samsung', '00:21:19': 'Samsung',
    '00:23:39': 'Samsung', '00:24:54': 'Samsung', '00:26:37': 'Samsung', '2C:3B:70': 'Samsung',
    '2C:44:01': 'Samsung', '2C:8A:72': 'Samsung', '30:07:4D': 'Samsung', '30:19:66': 'Samsung',
    
    # Intel devices
    '00:90:27': 'Intel', '00:02:B3': 'Intel', '00:12:F0': 'Intel', '00:13:02': 'Intel',
    '00:13:20': 'Intel', '00:15:17': 'Intel', '00:16:E3': 'Intel', '00:19:D1': 'Intel',
    
    # Dell devices
    '00:21:6A': 'Dell', '00:14:22': 'Dell', '00:1D:09': 'Dell', 'B8:AC:6F': 'Dell',
    '3C:A8:2A': 'Dell', '00:13:72': 'Dell', '00:1E:C9': 'Dell', '00:26:B9': 'Dell',
    
    # VMware
    '00:50:56': 'VMware', '00:0C:29': 'VMware', '00:1B:21': 'VMware', '00:05:69': 'VMware',
    
    # Microsoft
    '00:03:FF': 'Microsoft', '00:12:5A': 'Microsoft', '00:15:5D': 'Microsoft (Hyper-V)',
    
    # Google
    'FC:AA:14': 'Google', '00:1A:11': 'Google',
    
    # Oracle VirtualBox
    '08:00:27': 'Oracle VirtualBox',
    
    # QEMU/KVM
    '52:54:00': 'QEMU/KVM',
}

# Device type patterns based on vendor
DEVICE_TYPE_PATTERNS = {
    'Mobile Device': [
        'apple', 'iphone', 'ipad', 'samsung', 'xiaomi', 'oneplus', 'oppo', 
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

class StandaloneVendorService:
    """Standalone vendor lookup service that runs independently"""
    
    def __init__(self, port: int = 8001):
        self.port = port
        self.lookup_cache = {}
        self.request_queue = queue.Queue()
        self.response_cache = {}
        self.running = False
        self.worker_thread = None
        self.server_thread = None
        
    def start(self):
        """Start the vendor lookup service"""
        self.running = True
        self.worker_thread = threading.Thread(target=self._worker_loop, daemon=True)
        self.worker_thread.start()
        self.server_thread = threading.Thread(target=self._start_server, daemon=True)
        self.server_thread.start()
        print(f"Standalone Vendor Service started on port {self.port}")
        
    def stop(self):
        """Stop the service"""
        self.running = False
        if self.worker_thread:
            self.worker_thread.join(timeout=2)
        if self.server_thread:
            self.server_thread.join(timeout=2)
            
    def lookup_vendor(self, mac_address: str) -> Tuple[str, str]:
        """Lookup vendor for MAC address (blocking call)"""
        mac_clean = self._clean_mac(mac_address)
        
        # Check cache first
        if mac_clean in self.lookup_cache:
            return self.lookup_cache[mac_clean]
            
        # Try OUI database
        oui = mac_clean[:8]  # First 3 octets (XX:XX:XX format)
        if oui in VENDOR_DATABASE:
            vendor = VENDOR_DATABASE[oui]
            device_type = self._get_device_type(vendor)
            result = (vendor, device_type)
            self.lookup_cache[mac_clean] = result
            return result
            
        # Try online lookup
        try:
            vendor = self._online_lookup(mac_address)
            device_type = self._get_device_type(vendor)
            result = (vendor, device_type)
            self.lookup_cache[mac_clean] = result
            return result
        except Exception as e:
            print(f"Online lookup failed for {mac_address}: {e}")
            
        # Return unknown
        result = ("Unknown", "Unknown")
        self.lookup_cache[mac_clean] = result
        return result
        
    def lookup_vendor_async(self, mac_address: str, callback_url: Optional[str] = None) -> str:
        """Queue an async lookup request"""
        request_id = f"{mac_address}_{int(time.time() * 1000)}"
        self.request_queue.put({
            'id': request_id,
            'mac': mac_address,
            'callback_url': callback_url
        })
        return request_id
        
    def get_result(self, request_id: str) -> Optional[Tuple[str, str]]:
        """Get result of async lookup"""
        return self.response_cache.get(request_id)
        
    def _worker_loop(self):
        """Worker thread for processing async requests"""
        while self.running:
            try:
                request = self.request_queue.get(timeout=1)
                request_id = request['id']
                mac_address = request['mac']
                callback_url = request.get('callback_url')
                
                # Perform lookup
                vendor, device_type = self.lookup_vendor(mac_address)
                
                # Store result
                self.response_cache[request_id] = (vendor, device_type)
                
                # Call callback if provided
                if callback_url:
                    try:
                        response_data = {
                            'request_id': request_id,
                            'mac': mac_address,
                            'vendor': vendor,
                            'device_type': device_type
                        }
                        requests.post(callback_url, json=response_data, timeout=5)
                    except Exception as e:
                        print(f"Callback failed: {e}")
                        
                self.request_queue.task_done()
                
            except queue.Empty:
                continue
            except Exception as e:
                print(f"Worker error: {e}")
                
    def _start_server(self):
        """Simple HTTP server for API access"""
        from http.server import HTTPServer, BaseHTTPRequestHandler
        import urllib.parse
        
        class VendorHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path.startswith('/lookup/'):
                    mac = self.path.split('/')[-1]
                    vendor, device_type = self.server.vendor_service.lookup_vendor(mac)
                    
                    self.send_response(200)
                    self.send_header('Content-type', 'application/json')
                    self.send_header('Access-Control-Allow-Origin', '*')
                    self.end_headers()
                    
                    response = {
                        'mac': mac,
                        'vendor': vendor,
                        'device_type': device_type
                    }
                    self.wfile.write(json.dumps(response).encode())
                else:
                    self.send_response(404)
                    self.end_headers()
                    
            def do_POST(self):
                if self.path == '/lookup_async':
                    content_length = int(self.headers['Content-Length'])
                    post_data = self.rfile.read(content_length)
                    data = json.loads(post_data.decode())
                    
                    mac = data.get('mac')
                    callback_url = data.get('callback_url')
                    
                    request_id = self.server.vendor_service.lookup_vendor_async(mac, callback_url)
                    
                    self.send_response(200)
                    self.send_header('Content-type', 'application/json')
                    self.send_header('Access-Control-Allow-Origin', '*')
                    self.end_headers()
                    
                    response = {'request_id': request_id}
                    self.wfile.write(json.dumps(response).encode())
                else:
                    self.send_response(404)
                    self.end_headers()
                    
            def log_message(self, format, *args):
                # Suppress default logging
                pass
        
        try:
            server = HTTPServer(('localhost', self.port), VendorHandler)
            server.vendor_service = self
            server.serve_forever()
        except Exception as e:
            print(f"Server error: {e}")
            
    def _clean_mac(self, mac: str) -> str:
        """Clean and normalize MAC address"""
        return mac.replace('-', ':').replace('.', ':').upper()
        
    def _online_lookup(self, mac: str) -> str:
        """Try online vendor lookup"""
        try:
            # Try macvendors.com API
            response = requests.get(f"https://api.macvendors.com/{mac}", timeout=3)
            if response.status_code == 200:
                vendor = response.text.strip()
                if vendor and not vendor.lower().startswith('not found'):
                    return vendor
        except:
            pass
            
        try:
            # Try alternative API
            response = requests.get(f"https://macvendors.co/api/{mac}", timeout=3)
            if response.status_code == 200:
                data = response.json()
                if data.get('result', {}).get('company'):
                    return data['result']['company']
        except:
            pass
            
        return "Unknown"
        
    def _get_device_type(self, vendor: str) -> str:
        """Determine device type from vendor"""
        if vendor == "Unknown":
            return "Unknown"
            
        vendor_lower = vendor.lower()
        for device_type, patterns in DEVICE_TYPE_PATTERNS.items():
            if any(pattern in vendor_lower for pattern in patterns):
                return device_type
                
        return "Computer"  # Default fallback

def main():
    """Run the standalone vendor service"""
    print("Starting Standalone Vendor Lookup Service...")
    service = StandaloneVendorService()
    service.start()
    
    try:
        print("Service running. Test with:")
        print("  http://localhost:8001/lookup/2c:3b:70:e7:7a:a7")
        print("Press Ctrl+C to stop")
        
        # Keep running
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\nStopping service...")
        service.stop()
        print("Service stopped.")

if __name__ == "__main__":
    main()
