#!/usr/bin/env python3
"""
Client for the standalone vendor lookup service
Use this in your main NetSentinel application to avoid async conflicts
"""

import requests
import json
from typing import Tuple, Optional

class VendorLookupClient:
    """Client to communicate with the standalone vendor service"""
    
    def __init__(self, service_url: str = "http://localhost:8001"):
        self.service_url = service_url
        
    def lookup_vendor(self, mac_address: str) -> Tuple[str, str]:
        """Lookup vendor synchronously"""
        try:
            response = requests.get(f"{self.service_url}/lookup/{mac_address}", timeout=5)
            if response.status_code == 200:
                data = response.json()
                return data.get('vendor', 'Unknown'), data.get('device_type', 'Unknown')
        except Exception as e:
            print(f"Vendor lookup failed for {mac_address}: {e}")
            
        return "Unknown", "Unknown"
        
    def is_service_available(self) -> bool:
        """Check if the vendor service is running"""
        try:
            response = requests.get(f"{self.service_url}/lookup/00:00:00:00:00:00", timeout=2)
            return response.status_code == 200
        except:
            return False

# Simple function to use in your main application
def get_vendor_info_safe(mac_address: str) -> Tuple[str, str]:
    """Safe vendor lookup that won't cause async issues"""
    client = VendorLookupClient()
    
    if client.is_service_available():
        return client.lookup_vendor(mac_address)
    else:
        # Fallback to basic OUI lookup if service isn't available
        return fallback_vendor_lookup(mac_address)

def fallback_vendor_lookup(mac_address: str) -> Tuple[str, str]:
    """Fallback vendor lookup without external dependencies"""
    # Basic OUI database for most common vendors
    basic_ouis = {
        '2C:3B:70': ('Samsung', 'Mobile Device'),
        '00:50:56': ('VMware', 'Virtual Machine'),
        '00:0C:29': ('VMware', 'Virtual Machine'),
        '08:00:27': ('Oracle VirtualBox', 'Virtual Machine'),
        '52:54:00': ('QEMU/KVM', 'Virtual Machine'),
        '00:03:FF': ('Microsoft', 'Computer'),
        '00:15:5D': ('Microsoft Hyper-V', 'Virtual Machine'),
    }
    
    mac_clean = mac_address.replace('-', ':').replace('.', ':').upper()
    oui = mac_clean[:8]  # First 3 octets
    
    if oui in basic_ouis:
        return basic_ouis[oui]
    
    return "Unknown", "Unknown"

if __name__ == "__main__":
    # Test the client
    test_macs = [
        "2c:3b:70:e7:7a:a7",
        "2e:f6:dc:79:48:85", 
        "0a:af:4f:8c:64:e9"
    ]
    
    print("Testing Vendor Lookup Client...")
    client = VendorLookupClient()
    
    print(f"Service available: {client.is_service_available()}")
    
    for mac in test_macs:
        vendor, device_type = get_vendor_info_safe(mac)
        print(f"{mac} -> {vendor} ({device_type})")
