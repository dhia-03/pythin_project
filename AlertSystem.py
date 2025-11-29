import logging
import json
from datetime import datetime

class AlertSystem:
    def __init__(self, log_file="ids_alerts.log"):
        self.logger = logging.getLogger("IDS_Alerts")
        self.logger.setLevel(logging.INFO)

        handler = logging.FileHandler(log_file)
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

    def generate_alert(self, threat, packet_info=None):
        packet_info = packet_info or {}

        alert = {
            'timestamp': datetime.now().isoformat(),
            'threat_type': threat.get('type'),
            'rule': threat.get('rule', None),
            'source_ip': packet_info.get('src_ip'),
            'destination_ip': packet_info.get('dst_ip'),
            'confidence': threat.get('confidence', 0.0),
            'details': threat
        }

        # Write normal warning alert
        self.logger.warning(json.dumps(alert))

        # High-risk notifications
        if alert['confidence'] > 0.8:
            self.logger.critical(
                f"High confidence threat detected: {json.dumps(alert)}"
            )

            # Here you can add:
            # self.send_slack(alert)
            # self.send_email(alert)
            # self.send_telegram(alert)
            # self.forward_to_siem(alert)
