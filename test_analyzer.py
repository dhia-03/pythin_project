from PacketCapture import PacketCapture
from TrafficAnalyzer import TrafficAnalyzer
import time

pcap = PacketCapture(interface="eth0")
analyzer = TrafficAnalyzer()

pcap.start_capture()

print("[+] Capturing for 10 seconds...")
start_time = time.time()

while time.time() - start_time < 10:
    if not pcap.packet_queue.empty():
        pkt = pcap.packet_queue.get()
        features = analyzer.analyze_packet(pkt)
        if features:
            print(features)

pcap.stop()
