#!/usr/bin/env python3
"""
Complete end-to-end test for the IDS system
This will:
1. Test detection engine logic
2. Test dashboard connection
3. Send test alerts
4. Provide diagnostics
"""
import sys
import time

print("=" * 70)
print("IDS COMPLETE DIAGNOSTIC AND FIX")
print("=" * 70)

# Test 1: Detection Engine
print("\n[TEST 1] Testing Detection Engine Logic...")
print("-" * 70)
try:
    from DetectionEngine import DetectionEngine
    from TrafficAnalyzer import TrafficAnalyzer
    
    detector = DetectionEngine()
    print(f"✓ Detection Engine initialized")
    print(f"  - Port scan threshold: {detector.port_scan_threshold} ports")
    print(f"  - SYN flood threshold: {detector.syn_flood_threshold} packets/sec")
    print(f"  - DDoS threshold: {detector.ddos_threshold} requests/sec")
    
    # Simulate port scan
    print("\n  Testing port scan detection (simulating 15 ports)...")
    detected = False
    for port in range(1000, 1016):
        features = {
            'src_ip': '10.0.0.100',
            'dst_ip': '10.0.0.1',
            'dst_port': port,
            'protocol': 'TCP'
        }
        threats = detector.detect_threats(features)
        if threats:
            print(f"  ✓ Port scan DETECTED after {port - 999} ports!")
            print(f"    Threat: {threats[0]}")
            detected = True
            break
    
    if not detected:
        print("  ✗ Port scan NOT detected - threshold may be too high")
        print("  FIX: Lowering threshold to 5 ports...")
        detector.port_scan_threshold = 5
        
except Exception as e:
    print(f"✗ Detection Engine failed: {e}")
    sys.exit(1)

# Test 2: Dashboard Connection
print("\n[TEST 2] Testing Dashboard Connection...")
print("-" * 70)
try:
    import requests
    from datetime import datetime
    
    dashboard_url = "http://localhost:5000/api/alert"
    
    # Check if dashboard is running
    try:
        response = requests.get("http://localhost:5000", timeout=2)
        print(f"✓ Dashboard is running (status: {response.status_code})")
    except:
        print("✗ Dashboard is NOT running!")
        print("  FIX: Start the dashboard with: python app.py")
        print("  Note: You need to login first at http://localhost:5000/login")
        print("        Default credentials: admin / admin123")
    
    # Test sending alert
    print("\n  Testing alert sending...")
    test_alert = {
        'timestamp': datetime.now().isoformat(),
        'threat_type': 'signature',
        'rule': 'port_scan',
        'source_ip': '192.168.1.100',
        'destination_ip': '192.168.1.1',
        'confidence': 0.95,
        'details': {'test': True, 'ports_scanned': 15},
        'severity': 'critical'
    }
    
    try:
        response = requests.post(dashboard_url, json=test_alert, timeout=2)
        if response.status_code == 200:
            print(f"  ✓ Test alert sent successfully!")
            print(f"    Response: {response.json()}")
        else:
            print(f"  ✗ Alert failed with status {response.status_code}")
    except Exception as e:
        print(f"  ✗ Could not send alert: {e}")
        
except Exception as e:
    print(f"✗ Dashboard test failed: {e}")

# Test 3: Database
print("\n[TEST 3] Testing Database...")
print("-" * 70)
try:
    from database.db_manager import db
    
    stats = db.get_stats()
    print(f"✓ Database connected")
    print(f"  - Total alerts in DB: {stats['total_alerts']}")
    print(f"  - High risk alerts: {stats['high_risk_count']}")
    print(f"  - Distribution: {stats['distribution']}")
    
except Exception as e:
    print(f"✗ Database test failed: {e}")

# Summary
print("\n" + "=" * 70)
print("SUMMARY & INSTRUCTIONS")
print("=" * 70)
print("""
To run the IDS and detect nmap scans:

1. TERMINAL 1 - Start the Dashboard:
   $ cd /home/dhia/python_project
   $ source venv/bin/activate
   $ python app.py
   
   Then open browser to: http://localhost:5000/login
   Login with: admin / admin123

2. TERMINAL 2 - Start the IDS (requires sudo):
   $ cd /home/dhia/python_project
   $ sudo ./venv/bin/python Integration.py
   
   (Or: sudo python3 Integration.py)

3. TERMINAL 3 - Run nmap scan:
   $ nmap -sS localhost
   
   Or scan a range of ports:
   $ nmap -p 1-100 localhost
   
   You should see:
   - Alerts in Terminal 2 (IDS console)
   - Alerts appear in the web dashboard in real-time
   - Alerts saved to database

TROUBLESHOOTING:
- If no alerts appear, check the threshold (currently 10 ports)
- Make sure you're scanning ENOUGH ports to trigger detection
- Use: nmap -p 1-20 localhost  (scans 20 ports, triggers at 10)
- Check IDS is using correct network interface in config.yaml

Current thresholds:
  - Port scan: {detector.port_scan_threshold} unique ports
  - SYN flood: {detector.syn_flood_threshold} SYN packets/sec  
  - DDoS: {detector.ddos_threshold} requests/sec
""")

print("=" * 70)
