from sklearn.ensemble import IsolationForest
import numpy as np

class DetectionEngine:
    def __init__(self):
        self.anomaly_detector = IsolationForest(
            contamination=0.1,
            random_state=42
        )
        self.signature_rules = self.load_signature_rules()
        self.is_trained = False

    def load_signature_rules(self):
        return {
            'syn_flood': {
                'condition': lambda f: (
                    'tcp_flags' in f and 
                    f['tcp_flags'] == 2 and   # SYN
                    f['packet_rate'] > 100
                )
            },
            'port_scan': {
                'condition': lambda f: (
                    f['packet_size'] < 100 and
                    f['packet_rate'] > 50
                )
            }
        }

    def train_anomaly_detector(self, normal_data):
        """
        Train on normal traffic features
        """
        X = np.array([[d['packet_size'], d['packet_rate'], d['byte_rate']] for d in normal_data])
        self.anomaly_detector.fit(X)
        self.is_trained = True

    def detect_threats(self, features):
        threats = []

        # Signature-based detection
        for rule_name, rule in self.signature_rules.items():
            try:
                if rule['condition'](features):
                    threats.append({
                        'type': 'signature',
                        'rule': rule_name,
                        'confidence': 1.0
                    })
            except:
                # Rule does not apply (e.g., UDP)
                pass

        # Anomaly-based detection
        if self.is_trained:
            X = np.array([[features['packet_size'], features['packet_rate'], features['byte_rate']]])
            score = self.anomaly_detector.score_samples(X)[0]

            if score < -0.5:
                threats.append({
                    'type': 'anomaly',
                    'score': float(score),
                    'confidence': min(1.0, abs(score))
                })

        return threats
