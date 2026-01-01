from scapy.all import IP, TCP, UDP

class TrafficAnalyzer:
    def __init__(self):
        pass

    def analyze_packet(self, packet):
        if IP not in packet:
            return None

        features = {
            'src_ip': packet[IP].src,
            'dst_ip': packet[IP].dst,
        }

        if packet.haslayer(TCP):
            features['dst_port'] = int(packet[TCP].dport)
            features['src_port'] = int(packet[TCP].sport)
            features['protocol'] = 'TCP'
            # Extract TCP flags - convert to string representation
            tcp_flags = packet[TCP].flags
            features['tcp_flags'] = str(tcp_flags)
        elif packet.haslayer(UDP):
            features['dst_port'] = int(packet[UDP].dport)
            features['src_port'] = int(packet[UDP].sport)
            features['protocol'] = 'UDP'
        else:
            return None

        return features