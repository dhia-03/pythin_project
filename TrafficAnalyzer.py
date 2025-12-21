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
            features['protocol'] = 'TCP'
        elif packet.haslayer(UDP):
            features['dst_port'] = int(packet[UDP].dport)
            features['protocol'] = 'UDP'
        else:
            return None

        return features