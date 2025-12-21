import sys
import time
from PacketCapture import PacketCapture
from TrafficAnalyzer import TrafficAnalyzer
from DetectionEngine import DetectionEngine
from AlertSystem import AlertSystem
from scapy.all import IP, TCP, UDP

# Initialize components
analyzer = TrafficAnalyzer()
detector = DetectionEngine()
alerter = AlertSystem(dashboard_url="http://172.27.252.208:5000/api/alert")

packet_count = 0

def process_packet(packet):
    global packet_count
    packet_count += 1
    
    # Heartbeat every 10 packets
    if packet_count % 10 == 0:
        print(f"[*] Processed {packet_count} packets...")

    features = analyzer.analyze_packet(packet)
    if not features:
        return

    threats = detector.detect_threats(features)
    for t in threats:
        # Printing to console helps us know the engine found it
        print(f"\n[!!!] {t['rule'].upper()} DETECTED from {packet[IP].src} [!!!]")
        alerter.generate_alert(t, {
            'src_ip': packet[IP].src,
            'dst_ip': packet[IP].dst
        })

capturer = PacketCapture()
# Use eth0 or "" to listen on all interfaces
INTERFACE = "eth0" 
capturer.start_capture(INTERFACE)

print(f"[+] IDS running on {INTERFACE}...")
print("[*] Press Ctrl+C once and wait a second to stop.")

try:
    while True:
        try:
            # We use a 0.1 timeout so the loop stays 'alive' and responsive to Ctrl+C
            pkt = capturer.packet_queue.get(timeout=0.1)
            process_packet(pkt)
        except Exception: # This catches the Empty queue timeout
            continue
except KeyboardInterrupt:
    print("\n[!] Stopping IDS...")
finally:
    capturer.stop()
    print("[+] Cleanup complete. Exit.")
    sys.exit(0)