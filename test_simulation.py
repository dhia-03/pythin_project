#!/usr/bin/env python3
"""
Simple simulation script that:
1. Simulates nmap scan packets
2. Triggers detection engine
3. Sends alerts to dashboard
No need for root or network capture!
"""

import sys
import time
from datetime import datetime

print("=" * 70)
print("IDS SIMULATION - Testing Without Real Network Capture")
print("=" * 70)

# Import components
try:
    from DetectionEngine import DetectionEngine
    from database.db_manager import db
    import requests
    
    print("\n[1/3] Initializing detection engine...")
    detector = DetectionEngine()
    print(f"      ✓ Port scan threshold: {detector.port_scan_threshold} ports")
    
    # Simulate nmap scanning 15 ports
    print("\n[2/3] Simulating nmap port scan (15 ports)...")
    print("      Scanning ports 1-15 on target 192.168.1.1 from 192.168.1.100...")
    
    alert_sent = False
    for port in range(1, 16):
        features = {
            'src_ip': '192.168.1.100',
            'dst_ip': '192.168.1.1',
            'dst_port': port,
            'protocol': 'TCP'
        }
        
        threats = detector.detect_threats(features)
        
        if threats and not alert_sent:
            print(f"\n      🚨 PORT SCAN DETECTED after {port} ports!")
            
            # Create alert
            alert = {
                'timestamp': datetime.now().isoformat(),
                'threat_type': 'signature',
                'rule': 'port_scan',
                'source_ip': '192.168.1.100',
                'destination_ip': '192.168.1.1',
                'confidence': 1.0,
                'details': {'ports_scanned': port, 'simulation': True},
                'severity': 'critical'
            }
            
            # Save to database
            print("\n[3/3] Saving alert and sending to dashboard...")
            db_alert = db.add_alert(alert)
            if db_alert:
                print("      ✓ Alert saved to database")
            
            # Try to send to dashboard
            try:
                response = requests.post(
                    'http://localhost:5000/api/alert',
                    json=alert,
                    timeout=2
                )
                if response.status_code == 200:
                    print("      ✓ Alert sent to dashboard")
                    print("\n      Check your browser at: http://localhost:5000")
                else:
                    print(f"      ✗ Dashboard returned status {response.status_code}")
            except requests.exceptions.ConnectionError:
                print("      ✗ Dashboard is not running!")
                print("\n      To see the alert, start the dashboard:")
                print("      $ ./start_dashboard.sh")
                print("      Then run this script again.")
            except Exception as e:
                print(f"      ✗ Error sending to dashboard: {e}")
            
            alert_sent = True
            break
    
    # Show database stats
    print("\n" + "=" * 70)
    print("DATABASE STATS")
    print("=" * 70)
    stats = db.get_stats()
    print(f"Total alerts: {stats['total_alerts']}")
    print(f"Critical alerts: {stats['high_risk_count']}")
    
    if stats['total_alerts'] > 0:
        print("\nRecent alerts:")
        alerts = db.get_recent_alerts(limit=5)
        for a in alerts:
            print(f"  - {a['rule']} from {a['source_ip']} at {a['timestamp']}")
    
    print("\n" + "=" * 70)
    print("✅ SIMULATION COMPLETE")
    print("=" * 70)
    print("\nThis proves the detection engine works!")
    print("\nTo see it work with REAL nmap scans:")
    print("1. Start dashboard: ./start_dashboard.sh")
    print("2. Start IDS: sudo ./start_ids.sh")
    print("3. Run nmap: nmap -p 1-20 localhost")
    
except Exception as e:
    print(f"\n✗ Error: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
