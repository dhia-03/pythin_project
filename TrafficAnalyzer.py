from scapy.all import IP, TCP, UDP
from collections import defaultdict
import time

class TrafficAnalyzer:
    def __init__(self):
        self.flow_stats = defaultdict(lambda: {
            'packet_count': 0,
            'byte_count': 0,
            'start_time': None,
            'last_time': None
        })

    def analyze_packet(self, packet):
        # Only process IP packets
        if IP not in packet:
            return None

        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = None
        src_port = None
        dst_port = None

        # TCP Flow
        if TCP in packet:
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport

        # UDP Flow
        elif UDP in packet:
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        else:
            return None  # ignore non-TCP/UDP packets for now

        # Flow key uniquely identifies a connection/flow
        flow_key = (ip_src, ip_dst, src_port, dst_port, protocol)

        stats = self.flow_stats[flow_key]
        pkt_len = len(packet)
        pkt_time = packet.time

        # Update stats
        stats['packet_count'] += 1
        stats['byte_count'] += pkt_len

        if stats['start_time'] is None:
            stats['start_time'] = pkt_time

        stats['last_time'] = pkt_time

        return self.extract_features(packet, stats, protocol, ip_src, ip_dst)

    def extract_features(self, packet, stats, protocol, ip_src, ip_dst):
        duration = max(0.0001, stats['last_time'] - stats['start_time'])

        features = {
            'src_ip': ip_src,
            'dst_ip': ip_dst,
            'protocol': protocol,

            'packet_size': len(packet),
            'flow_duration': duration,

            'packet_rate': stats['packet_count'] / duration,
            'byte_rate': stats['byte_count'] / duration,

            'total_packets': stats['packet_count'],
            'total_bytes': stats['byte_count'],
        }

        # TCP-specific fields
        if TCP in packet:
            features.update({
                'tcp_flags': packet[TCP].flags,
                'window_size': packet[TCP].window
            })

        return features
