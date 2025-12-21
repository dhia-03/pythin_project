import time
from collections import defaultdict

class DetectionEngine:
    def __init__(self):
        self.signature_rules = self.load_signature_rules()
        # Key: (src_ip, dst_ip) -> Value: Set of unique ports
        self.port_scan_tracker = defaultdict(set)
        self.last_clear_time = time.time()

    def load_signature_rules(self):
        return {
            'port_scan': {'condition': self._detect_port_scan}
        }

    def _detect_port_scan(self, features):
        src_ip = features.get('src_ip')
        dst_ip = features.get('dst_ip')
        dst_port = features.get('dst_port')

        # Clean tracker every 60 seconds to prevent memory bloat
        if time.time() - self.last_clear_time > 60:
            self.port_scan_tracker.clear()
            self.last_clear_time = time.time()

        if src_ip and dst_ip and dst_port:
            key = (src_ip, dst_ip)
            self.port_scan_tracker[key].add(dst_port)
            
            # --- DEBUG PRINT ---
            # This will show up in your terminal for EVERY packet nmap sends
            count = len(self.port_scan_tracker[key])
            print(f"DEBUG Engine: IP {src_ip} has touched {count} unique ports")
            
            # TRIGGER: Lowered to 3 ports just for testing purposes
            if count > 3: 
                return True
        return False

    def detect_threats(self, features):
        threats = []
        for rule_name, rule in self.signature_rules.items():
            if rule['condition'](features):
                threats.append({
                    'type': 'signature',
                    'rule': rule_name,
                    'confidence': 1.0,
                    'timestamp': time.time()
                })
        return threats