import logging
import json
import requests
from datetime import datetime

class AlertSystem:
    def __init__(self, log_file="ids_alerts.log", dashboard_url="http://172.27.252.208:5000/api/alert"):
        self.dashboard_url = dashboard_url
        self.logger = logging.getLogger("IDS_Alerts")
        self.logger.setLevel(logging.INFO)

        # File Logging
        handler = logging.FileHandler(log_file)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
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

        # 1. Log to the file (existing behavior)
        self.logger.warning(json.dumps(alert))
        print(f"[!] Alert Generated: {alert['rule'] or alert['threat_type']}")

        # 2. SEND TO DASHBOARD (The missing link)
        try:
            # We use a short timeout so the IDS doesn't lag if the dashboard is closed
            response = requests.post(self.dashboard_url, json=alert, timeout=0.5)
            if response.status_code == 200:
                print("    [+] Alert successfully sent to dashboard.")
        except Exception as e:
            print(f"    [-] Could not send alert to dashboard: {e}")

        # High-risk notifications
        if alert['confidence'] > 0.8:
            self.logger.critical(f"High confidence threat detected: {json.dumps(alert)}")