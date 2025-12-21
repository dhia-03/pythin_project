from PacketCapture import PacketCapture
import time

pcap = PacketCapture(interface="eth0")  # change to wlan0 if needed

pcap.start_capture()

print("[+] Capturing packets for 10 seconds...")
time.sleep(10)

pcap.stop()

print("[+] Packets captured:", pcap.packet_queue.qsize())

# Display the first 5 packets
for i in range(min(5, pcap.packet_queue.qsize())):
    pkt = pcap.packet_queue.get()
    print(pkt.summary())
