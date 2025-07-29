#!/usr/bin/env python3
"""
Simple test for the vendor lookup improvements
"""
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), 'backend'))

def simple_test():
    try:
        from main import COMMON_OUIS
        print(f"Successfully imported COMMON_OUIS with {len(COMMON_OUIS)} entries")
        
        # Test a specific MAC
        test_mac = "2c:3b:70"
        if test_mac in COMMON_OUIS:
            print(f"Found {test_mac} -> {COMMON_OUIS[test_mac]}")
        else:
            print(f"{test_mac} not in common OUI database")
        
        # Test the vendor service import
        from main import VendorLookupService, vendor_service
        print("Successfully imported vendor service classes")
        
        # Quick test of vendor lookup function
        from main import get_vendor_info_sync
        vendor, device_type = get_vendor_info_sync("2c:3b:70:e7:7a:a7")
        print(f"Quick vendor lookup result: {vendor} ({device_type})")
        
        print("✓ All imports and basic functionality working!")
        
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    simple_test()
