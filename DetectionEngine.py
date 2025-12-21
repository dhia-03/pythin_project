import time
from collections import defaultdict
from ConfigManager import config

class DetectionEngine:
    def __init__(self):
        self.signature_rules = self.load_signature_rules()
        
        # State Trackers
        self.port_scan_tracker = defaultdict(set) # (src, dst) -> {ports}
        self.syn_tracker = defaultdict(int)       # dst_ip -> count
        self.request_tracker = defaultdict(int)   # dst_ip -> request_count
        self.failed_auth_tracker = defaultdict(int) # (src, dst, port) -> count
        
        self.last_clear_time = time.time()
        
        # Load thresholds from config
        self.port_scan_threshold = config.get('detection.port_scan_threshold', 10)
        self.syn_flood_threshold = config.get('detection.syn_flood_threshold', 100)
        self.ddos_threshold = config.get('detection.ddos_threshold', 100)
        self.brute_force_threshold = config.get('detection.brute_force_threshold', 5)

    def load_signature_rules(self):
        return {
            'port_scan': {'condition': self._detect_port_scan},
            'syn_flood': {'condition': self._detect_syn_flood},
            'ddos': {'condition': self._detect_ddos},
            # 'brute_force': {'condition': self._detect_brute_force} # Requires application layer data
        }

    def _cleanup_trackers(self):
        """Reset trackers every 1 second for rate-based rules, 60s for scan"""
        now = time.time()
        if now - self.last_clear_time > 1.0:
            self.syn_tracker.clear()
            self.request_tracker.clear()
            # We don't clear port scan or auth failures every second
            # Instead we could use a sliding window or separate timer
            # For simplicity in this demo, we clear high-frequency trackers frequently
            self.last_clear_time = now
            
        # Separate cleanup for longer-term trackers could be added here
        # E.g. clear port_scan_tracker every 60s

    def _detect_port_scan(self, features):
        src_ip = features.get('src_ip')
        dst_ip = features.get('dst_ip')
        dst_port = features.get('dst_port')
        
        if not (src_ip and dst_ip and dst_port):
            return False

        key = (src_ip, dst_ip)
        self.port_scan_tracker[key].add(dst_port)
        
        if len(self.port_scan_tracker[key]) > self.port_scan_threshold:
            # Check if we already alerted recently (optional optimization)
            return True
        return False

    def _detect_syn_flood(self, features):
        if features.get('protocol') == 'TCP' and features.get('tcp_flags') == 'S': # SYN flag
            dst_ip = features.get('dst_ip')
            self.syn_tracker[dst_ip] += 1
            
            if self.syn_tracker[dst_ip] > self.syn_flood_threshold:
                return True
        return False

    def _detect_ddos(self, features):
        dst_ip = features.get('dst_ip')
        if dst_ip:
            self.request_tracker[dst_ip] += 1
            if self.request_tracker[dst_ip] > self.ddos_threshold:
                return True
        return False

    def detect_threats(self, features):
        self._cleanup_trackers()
        threats = []
        
        for rule_name, rule in self.signature_rules.items():
            if rule['condition'](features):
                threats.append({
                    'type': 'signature',
                    'rule': rule_name,
                    'confidence': 1.0 if rule_name == 'port_scan' else 0.9,
                    'timestamp': time.time()
                })
        return threats