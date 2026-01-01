#!/usr/bin/env python3
"""
Test DDoS detection with lower threshold
Temporarily modifies the threshold to make testing easier on the same machine
"""

import sys
import time
from PacketCapture import PacketCapture
from TrafficAnalyzer import TrafficAnalyzer
from DetectionEngine import DetectionEngine
from AlertSystem import AlertSystem
from ConfigManager import config
from scapy.all import IP

# Temporarily lower threshold for testing
print("=" * 60)
print("       DDoS Detection Test (Lower Threshold)")
print("=" * 60)
print(f"\nOriginal ddos_threshold: {config.get('detection.ddos_threshold')}")
print("Setting threshold to 30 for testing...")

# Initialize components
analyzer = TrafficAnalyzer()
detector = DetectionEngine()
detector.ddos_threshold = 30  # Lower threshold for testing
alerter = AlertSystem()

packet_count = 0

def process_packet(packet):
    global packet_count
    
    # Heartbeat every 10 packets
    if packet_count % 10 == 0:
        print(f"[*] Processed {packet_count} packets...")
    
    packet_count += 1

    features = analyzer.analyze_packet(packet)
    if not features:
        return

    threats = detector.detect_threats(features)
    for t in threats:
        print(f"\n[!!!] {t['rule'].upper()} DETECTED from {packet[IP].src} [!!!]")
        alerter.generate_alert(t, {
            'src_ip': packet[IP].src,
            'dst_ip': packet[IP].dst
        })

print(f"\nNew ddos_threshold: {detector.ddos_threshold} requests/sec")
print("\nNow run your DDoS simulation or hping3 command:")
print("  python3 simulate_ddos.py 172.27.252.208")
print("  OR")
print("  sudo hping3 -S -p 80 --faster 172.27.252.208")
print("\n" + "=" * 60 + "\n")

capturer = PacketCapture()
INTERFACE = config.get('network.interface', 'eth0')
capturer.start_capture(INTERFACE)

print(f"[+] IDS running on {INTERFACE} with ddos_threshold={detector.ddos_threshold}...")
print("[*] Press Ctrl+C once and wait a second to stop.\n")

try:
    while True:
        try:
            pkt = capturer.packet_queue.get(timeout=0.1)
            process_packet(pkt)
        except Exception:
            continue
except KeyboardInterrupt:
    print("\n[!] Stopping IDS...")
finally:
    capturer.stop()
    print("[+] Cleanup complete. Exit.")
    sys.exit(0)
