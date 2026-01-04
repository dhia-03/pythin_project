import logging
import json
import requests
from datetime import datetime

from ConfigManager import config
from database.db_manager import db
from NotificationService import notifier
from ThreatIntelligence import threat_intel

class AlertSystem:
    def __init__(self, log_file="ids_alerts.log"):
        self.dashboard_url = config.get('dashboard.url')
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
            'details': threat,
            'severity': 'low' # Default, will be updated by DB logic ideally, but good for now
        }
        
        # Enrich with threat intelligence
        source_ip = packet_info.get('src_ip')
        if source_ip:
            reputation = threat_intel.check_ip(source_ip)
            if reputation:
                alert['abuse_score'] = reputation.get('abuse_score', 0)
                alert['is_known_threat'] = reputation.get('is_known_threat', False)
                alert['threat_categories'] = reputation.get('threat_categories', [])
                alert['total_reports'] = reputation.get('total_reports', 0)
                
                if reputation.get('is_known_threat'):
                    print(f"    [!] Known malicious IP detected! Abuse score: {reputation['abuse_score']}%")
                    if reputation.get('threat_categories'):
                        print(f"    [!] Categories: {', '.join(reputation['threat_categories'])}")

        
        # Calculate severity locally for notification purposes before DB
        if alert['confidence'] > 0.8: alert['severity'] = 'critical'
        elif alert['confidence'] > 0.6: alert['severity'] = 'high'
        elif alert['confidence'] > 0.4: alert['severity'] = 'medium'

        # 1. Log to the file (existing behavior)
        self.logger.warning(json.dumps(alert))
        print(f"[!] Alert Generated: {alert['rule'] or alert['threat_type']}")

        # 2. SAVE TO DATABASE (New)
        db_alert = db.add_alert(alert)
        if db_alert:
            print("    [+] Alert saved to database.")

        # 3. SEND NOTIFICATIONS (New)
        notifier.send_alert(alert)

        # 4. SEND TO DASHBOARD
        try:
            # We use a short timeout so the IDS doesn't lag if the dashboard is closed
            # In production, this might be async
            response = requests.post(self.dashboard_url, json=alert, timeout=0.5)
            if response.status_code == 200:
                print("    [+] Alert successfully sent to dashboard.")
        except Exception as e:
            print(f"    [-] Could not send alert to dashboard: {e}")

        # High-risk notifications
        if alert['confidence'] > 0.8:
            self.logger.critical(f"High confidence threat detected: {json.dumps(alert)}")