#!/usr/bin/env python3
"""
Test script for vendor lookup functionality
"""

import sys
import os
import time
sys.path.append(os.path.join(os.path.dirname(__file__), 'backend'))

# Test the vendor lookup function
def test_vendor_lookup():
    """Test the vendor lookup with the problematic MAC addresses"""
    
    # Import the function from main.py
    try:
        from main import get_vendor_info_sync, vendor_service, request_vendor_lookup_async
        
        # Start the vendor service
        vendor_service.start()
        print("Vendor service started for testing")
        
        # Test MAC addresses from the error
        test_macs = [
            "2c:3b:70:e7:7a:a7",
            "2e:f6:dc:79:48:85", 
            "0a:af:4f:8c:64:e9",
            "28:cf:e9:12:34:56",  # Apple test
            "00:50:56:12:34:56"   # VMware test
        ]
        
        print("Testing vendor lookup functionality...")
        print("=" * 50)
        
        # Test synchronous lookup (should be fast for common OUIs)
        print("\n1. Testing synchronous lookups:")
        for mac in test_macs:
            print(f"\nTesting MAC: {mac}")
            try:
                vendor, device_type = get_vendor_info_sync(mac)
                print(f"  Vendor: {vendor}")
                print(f"  Device Type: {device_type}")
                print(f"  ✓ Success")
            except Exception as e:
                print(f"  ✗ Error: {e}")
        
        # Test async lookup service
        print("\n\n2. Testing background lookup service:")
        lookup_results = {}
        
        def test_callback(mac_addr, found_vendor, found_device_type):
            lookup_results[mac_addr] = (found_vendor, found_device_type)
            print(f"  Async result for {mac_addr}: {found_vendor} ({found_device_type})")
        
        # Queue async lookups
        for mac in test_macs:
            print(f"Queuing async lookup for: {mac}")
            request_vendor_lookup_async(mac, test_callback)
        
        # Wait for results
        print("Waiting for async results (10 seconds max)...")
        for i in range(10):
            time.sleep(1)
            if len(lookup_results) >= len(test_macs):
                break
            print(f"  Waiting... ({len(lookup_results)}/{len(test_macs)} complete)")
        
        print(f"\nAsync lookup completed: {len(lookup_results)}/{len(test_macs)} results received")
        
        print("\n" + "=" * 50)
        print("Test completed.")
        
        # Stop the service
        vendor_service.stop()
        print("Vendor service stopped")
        
    except ImportError as e:
        print(f"Import error: {e}")
        print("Make sure you're running this from the NetSentinel directory")
    except Exception as e:
        print(f"Test error: {e}")

if __name__ == "__main__":
    test_vendor_lookup()
