from scapy.all import sniff, IP, TCP
import threading
import queue

class PacketCapture:
    """
    PacketCapture handles real-time packet sniffing using Scapy.
    Captured packets are pushed into a thread-safe queue for further processing
    by the Detection Engine.
    """

    def __init__(self, interface="eth0", queue_size=5000):
        self.interface = interface
        self.packet_queue = queue.Queue(maxsize=queue_size)
        self.stop_capture = threading.Event()
        self.capture_thread = None

    def packet_callback(self, packet):
        """
        Callback executed for each captured packet.
        Only captures IP + TCP traffic for now (can be extended later).
        """
        if IP in packet:
            try:
                self.packet_queue.put(packet, block=False)
            except queue.Full:
                print("[!] Warning: Packet queue is full. Dropping packet.")

    def start_capture(self):
        """
        Starts packet sniffing in a separate thread.
        """
        print(f"[+] Starting packet capture on interface {self.interface}...")

        def capture_thread():
            sniff(
                iface=self.interface,
                prn=self.packet_callback,
                filter="ip",     # BPF filter for performance
                store=False,
                stop_filter=lambda pkt: self.stop_capture.is_set(),
            )

        self.capture_thread = threading.Thread(target=capture_thread, daemon=True)
        self.capture_thread.start()

    def stop(self):
        """
        Stops packet capture cleanly.
        """
        print("[+] Stopping packet capture...")
        self.stop_capture.set()

        if self.capture_thread and self.capture_thread.is_alive():
            self.capture_thread.join()

        print("[+] Packet capture stopped.")
