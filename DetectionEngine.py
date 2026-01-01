import time
from collections import defaultdict
from ConfigManager import config

class DetectionEngine:
    def __init__(self):
        self.signature_rules = self.load_signature_rules()
        
        # State Trackers
        self.port_scan_tracker = defaultdict(dict) # (src, dst) -> {port: timestamp}
        self.syn_tracker = defaultdict(int)       # dst_ip -> count
        self.request_tracker = defaultdict(int)   # dst_ip -> request_count
        self.failed_auth_tracker = defaultdict(int) # (src, dst, port) -> count
        
        self.last_clear_time = time.time()
        self.last_port_scan_clear = time.time()
        
        # Load thresholds from config
        self.port_scan_threshold = config.get('detection.port_scan_threshold', 10)
        self.syn_flood_threshold = config.get('detection.syn_flood_threshold', 100)
        self.ddos_threshold = config.get('detection.ddos_threshold', 100)
        self.brute_force_threshold = config.get('detection.brute_force_threshold', 5)
        
        # Time window for port scan detection (60 seconds)
        self.port_scan_window = 60

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
            self.last_clear_time = now
            
        # Clean up port scan tracker entries older than port_scan_window
        if now - self.last_port_scan_clear > 10.0:  # Check every 10 seconds
            for key in list(self.port_scan_tracker.keys()):
                # Remove ports accessed more than port_scan_window seconds ago
                self.port_scan_tracker[key] = {
                    port: timestamp for port, timestamp in self.port_scan_tracker[key].items()
                    if now - timestamp < self.port_scan_window
                }
                # Remove the key entirely if no ports remain
                if not self.port_scan_tracker[key]:
                    del self.port_scan_tracker[key]
            self.last_port_scan_clear = now

    def _detect_port_scan(self, features):
        src_ip = features.get('src_ip')
        dst_ip = features.get('dst_ip')
        dst_port = features.get('dst_port')
        tcp_flags = features.get('tcp_flags', '')
        
        if not (src_ip and dst_ip and dst_port):
            return False
        
        # Convert tcp_flags to string to ensure consistent checking
        tcp_flags_str = str(tcp_flags)
        
        # Only detect port scans on SYN packets (connection attempts)
        # This filters out:
        # - Response packets (SYN-ACK, ACK, etc.)
        # - Established connection traffic
        # - Server responses to our outbound connections
        # Check for pure SYN: must have 'S' and must NOT have 'A'
        has_syn = 'S' in tcp_flags_str
        has_ack = 'A' in tcp_flags_str
        
        if not has_syn or has_ack:
            # Not a pure SYN packet (either no SYN or it's a SYN-ACK/ACK)
            return False

        key = (src_ip, dst_ip)
        now = time.time()
        
        # Store timestamp for this port access
        self.port_scan_tracker[key][dst_port] = now
        
        # Count only ports accessed within the time window
        recent_ports = {
            port for port, timestamp in self.port_scan_tracker[key].items()
            if now - timestamp < self.port_scan_window
        }
        
        if len(recent_ports) > self.port_scan_threshold:
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