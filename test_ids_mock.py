from scapy.all import IP, TCP
from DetectionEngine import DetectionEngine
from AlertSystem import AlertSystem
import time

def test_enhanced_ids():
    """Test the enhanced IDS with realistic attack patterns"""
    
    detection_engine = DetectionEngine()
    alert_system = AlertSystem()
    
    print("🚀 Testing Enhanced IDS Detection...")
    print("=" * 50)
    
    # Test 1: Clear Port Scan (should trigger)
    print("\n🔍 TEST 1: Port Scan Detection")
    print("-" * 30)
    
    port_scan_detected = False
    
    for port in [22, 23, 25, 53, 80, 443, 8080, 3389, 5900, 1433]:  # 10 different ports
        packet = IP(src="192.168.1.100", dst="192.168.1.2") / TCP(sport=5000, dport=port, flags="S")
        
        features = {
            'src_ip': packet[IP].src,
            'dst_ip': packet[IP].dst,
            'src_port': packet[TCP].sport,
            'dst_port': packet[TCP].dport,
            'protocol': packet[IP].proto,
            'packet_size': len(packet),
            'tcp_flags': packet[TCP].flags
        }
        
        threats = detection_engine.detect_threats(features)
        
        if threats:
            for threat in threats:
                print(f"   🚨 DETECTED: {threat['rule']} from {features['src_ip']}")
                print(f"   📊 Threat details: {threat}")
                port_scan_detected = True
                
                # Use the correct method name
                alert_system.generate_alert(threat, features)
                
        else:
            print(f"   Scanning port {port}...")
    
    if not port_scan_detected:
        print("   ❌ Port scan was not detected!")
    else:
        print("   ✅ Port scan successfully detected!")
    
    # Test 2: SYN Flood (should trigger)
    print("\n🔍 TEST 2: SYN Flood Detection")
    print("-" * 30)
    
    syn_flood_detected = False
    
    for i in range(105):  # 105 SYN packets (above 100 threshold)
        packet = IP(src=f"10.0.0.{i % 50}", dst="192.168.1.2") / TCP(sport=10000+i, dport=80, flags="S")
        
        features = {
            'src_ip': packet[IP].src,
            'dst_ip': packet[IP].dst,
            'src_port': packet[TCP].sport,
            'dst_port': packet[TCP].dport,
            'protocol': packet[IP].proto,
            'packet_size': len(packet),
            'tcp_flags': packet[TCP].flags
        }
        
        threats = detection_engine.detect_threats(features)
        
        if threats:
            for threat in threats:
                if threat['rule'] == 'syn_flood':
                    print(f"   🚨 DETECTED: {threat['rule']} from multiple sources (packet {i+1})")
                    print(f"   📊 Threat details: {threat}")
                    syn_flood_detected = True
                    
                    # Use the correct method name
                    alert_system.generate_alert(threat, features)
                    break
    
    if not syn_flood_detected:
        print("   ❌ SYN flood was not detected!")
    else:
        print("   ✅ SYN flood successfully detected!")
    
    # Test 3: Normal traffic (should not trigger)
    print("\n🔍 TEST 3: Normal Traffic")
    print("-" * 30)
    
    normal_packets = [
        IP(src="192.168.1.10", dst="192.168.1.2") / TCP(sport=1234, dport=80, flags="S"),
        IP(src="192.168.1.10", dst="192.168.1.2") / TCP(sport=1234, dport=80, flags="A"),
        IP(src="192.168.1.11", dst="192.168.1.2") / TCP(sport=1235, dport=443, flags="S"),
    ]
    
    false_positives = 0
    for packet in normal_packets:
        features = {
            'src_ip': packet[IP].src,
            'dst_ip': packet[IP].dst,
            'src_port': packet[TCP].sport,
            'dst_port': packet[TCP].dport,
            'protocol': packet[IP].proto,
            'packet_size': len(packet),
            'tcp_flags': packet[TCP].flags
        }
        
        threats = detection_engine.detect_threats(features)
        if threats:
            false_positives += 1
            print(f"   ⚠️  False positive: {threats}")
    
    if false_positives == 0:
        print("   ✅ No false positives in normal traffic")
    else:
        print(f"   ❌ {false_positives} false positives detected")

    print("\n" + "=" * 50)
    print("🎉 ENHANCED IDS TEST SUMMARY:")
    print(f"   Port Scan Detection: {'✅ WORKING' if port_scan_detected else '❌ FAILED'}")
    print(f"   SYN Flood Detection: {'✅ WORKING' if syn_flood_detected else '❌ FAILED'}")
    print(f"   False Positives: {'✅ GOOD' if false_positives == 0 else '❌ POOR'}")
    print("📄 Check 'ids_alerts.log' for detailed alerts")

if __name__ == "__main__":
    test_enhanced_ids()