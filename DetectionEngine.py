import numpy as np
from sklearn.ensemble import IsolationForest
from collections import defaultdict, deque
import time

class DetectionEngine:
    def __init__(self):
        self.anomaly_detector = IsolationForest(
            contamination=0.1,
            random_state=42
        )
        self.signature_rules = self.load_signature_rules()
        self.is_trained = False
        
        # For port scan detection
        self.port_scan_tracker = defaultdict(lambda: defaultdict(set))  # src_ip -> dst_ip -> ports
        self.syn_flood_tracker = defaultdict(lambda: defaultdict(int))  # src_ip -> dst_ip -> count
        self.window_start = time.time()
        self.window_duration = 10  # 10-second window

    def load_signature_rules(self):
        return {
            'syn_flood': {
                'condition': lambda f, engine: engine._detect_syn_flood(f)
            },
            'port_scan': {
                'condition': lambda f, engine: engine._detect_port_scan(f)
            }
        }

    def _detect_syn_flood(self, features):
        """Detect SYN flood attacks"""
        src_ip = features.get('src_ip')
        dst_ip = features.get('dst_ip')
        
        if src_ip and dst_ip and features.get('tcp_flags') == 2:  # SYN flag
            key = f"{src_ip}_{dst_ip}"
            self.syn_flood_tracker[key] += 1
            
            # Check if we need to reset the window
            current_time = time.time()
            if current_time - self.window_start > self.window_duration:
                self.syn_flood_tracker.clear()
                self.window_start = current_time
            
            # Trigger if more than 100 SYN packets in the window
            if self.syn_flood_tracker[key] > 100:
                return True
        return False

    def _detect_port_scan(self, features):
        """Detect port scanning behavior"""
        src_ip = features.get('src_ip')
        dst_ip = features.get('dst_ip')
        dst_port = features.get('dst_port')
        
        if src_ip and dst_ip and dst_port:
            # Track unique ports per source-destination pair
            self.port_scan_tracker[src_ip][dst_ip].add(dst_port)
            
            # Check if we need to reset the window
            current_time = time.time()
            if current_time - self.window_start > self.window_duration:
                self.port_scan_tracker.clear()
                self.window_start = current_time
            
            # Trigger if more than 5 unique ports scanned in the window
            if len(self.port_scan_tracker[src_ip][dst_ip]) > 5:
                return True
        return False

    def detect_threats(self, features):
        threats = []

        # Signature-based detection
        for rule_name, rule in self.signature_rules.items():
            try:
                if rule['condition'](features, self):
                    threats.append({
                        'type': 'signature',
                        'rule': rule_name,
                        'confidence': 1.0,
                        'timestamp': time.time()
                    })
            except Exception as e:
                # Rule does not apply
                pass

        # Anomaly-based detection (if trained)
        if self.is_trained and all(k in features for k in ['packet_size', 'packet_rate', 'byte_rate']):
            try:
                X = np.array([[features['packet_size'], features['packet_rate'], features['byte_rate']]])
                score = self.anomaly_detector.score_samples(X)[0]

                if score < -0.5:
                    threats.append({
                        'type': 'anomaly',
                        'score': float(score),
                        'confidence': min(1.0, abs(score)),
                        'timestamp': time.time()
                    })
            except:
                pass

        return threats

    def train_anomaly_detector(self, normal_data):
        """Train on normal traffic features"""
        if normal_data:
            self.anomaly_detector.fit(normal_data)
            self.is_trained = True