#!/usr/bin/env python3
"""
Test script for Threat Intelligence integration
Tests AbuseIPDB API connectivity and IP reputation checking
"""

import sys
import os

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ThreatIntelligence import threat_intel
from ConfigManager import config

def test_threat_intelligence():
    """Test threat intelligence service"""
    print("="*60)
    print("  Threat Intelligence Service Test")
    print("="*60)
    
    # Check if enabled
    enabled = config.get('threat_intelligence.abuseipdb.enabled', False)
    api_key = config.get('threat_intelligence.abuseipdb.api_key', '')
    
    print(f"\nService Status: {'ENABLED' if enabled else 'DISABLED'}")
    print(f"API Key Configured: {'YES' if api_key else 'NO'}")
    
    if not enabled or not api_key:
        print("\n⚠️  Threat intelligence is disabled or API key not configured")
        print("\nTo enable:")
        print("1. Sign up at https://www.abuseipdb.com/")
        print("2. Get your API key")
        print("3. Edit config.yaml:")
        print("   threat_intelligence:")
        print("     abuseipdb:")
        print("       enabled: true")
        print("       api_key: 'YOUR_API_KEY_HERE'")
        return
    
    print("\n" + "-"*60)
    print("Testing IP Reputation Checks")
    print("-"*60)
    
    # Test with known malicious IP (example)
    test_ips = [
        ("8.8.8.8", "Google DNS (should be clean)"),
        ("127.0.0.1", "Localhost (private IP, should skip)"),
        ("192.168.1.1", "Private IP (should skip)"),
    ]
    
    for ip, description in test_ips:
        print(f"\n\nTesting: {ip}")
        print(f"Description: {description}")
        print("-" * 40)
        
        result = threat_intel.check_ip(ip)
        
        if result is None:
            print("✓ Skipped (private IP or service disabled)")
        else:
            print(f"Abuse Score: {result['abuse_score']}%")
            print(f"Known Threat: {'YES' if result['is_known_threat'] else 'NO'}")
            print(f"Total Reports: {result['total_reports']}")
            
            if result['threat_categories']:
                print(f"Categories: {', '.join(result['threat_categories'])}")
            else:
                print("Categories: None")
            
            if result['last_reported']:
                print(f"Last Reported: {result['last_reported']}")
    
    print("\n" + "="*60)
    print("  Test Complete!")
    print("="*60)
    print("\nNote: You can test with your own IPs by editing this script.")
    print("Add suspicious IPs to the test_ips list to see reputation data.")

if __name__ == "__main__":
    try:
        test_threat_intelligence()
    except KeyboardInterrupt:
        print("\n\nTest interrupted by user")
    except Exception as e:
        print(f"\n✗ Error during test: {e}")
        import traceback
        traceback.print_exc()
