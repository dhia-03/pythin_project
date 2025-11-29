from PacketCapture import PacketCapture
from TrafficAnalyzer import TrafficAnalyzer
from DetectionEngine import DetectionEngine
from AlertSystem import AlertSystem
from scapy.all import IP, TCP, UDP, Ether
analyzer = TrafficAnalyzer()
detector = DetectionEngine()
alerter = AlertSystem()

def process_packet(packet):
    features = analyzer.analyze_packet(packet)
    if not features:
        return

    threats = detector.detect_threats(features)

    for t in threats:
        alerter.generate_alert(t, {
            'src_ip': packet[IP].src,
            'dst_ip': packet[IP].dst
        })

capturer = PacketCapture()
capturer.start_capture("eth0")

print("[+] IDS running... Press Ctrl+C to stop.")
try:
    while True:
        pkt = capturer.packet_queue.get()
        process_packet(pkt)
except KeyboardInterrupt:
    capturer.stop()
