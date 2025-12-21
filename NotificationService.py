import smtplib
import requests
import json
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from ConfigManager import config

class NotificationService:
    def __init__(self):
        self.email_config = config.get('notifications.email', {})
        self.slack_config = config.get('notifications.slack', {})
        self.discord_config = config.get('notifications.discord', {})

    def send_alert(self, alert):
        """Dispatch alert to enabled channels based on severity"""
        severity = alert.get('severity', 'low')
        
        # Determine if we should send based on severity (e.g., only high/critical for email)
        # For this demo, we'll send everything if enabled
        
        if self.email_config.get('enabled') and severity in ['high', 'critical']:
            self._send_email(alert)
            
        if self.slack_config.get('enabled'):
            self._send_slack(alert)
            
        if self.discord_config.get('enabled'):
            self._send_discord(alert)

    def _send_email(self, alert):
        try:
            msg = MIMEMultipart()
            msg['From'] = self.email_config.get('sender')
            msg['To'] = ", ".join(self.email_config.get('recipients', []))
            msg['Subject'] = f"[IDS ALERT] {alert['threat_type']} detected ({alert.get('severity', 'UNKNOWN').upper()})"
            
            body = f"""
            IDS Threat Detection
            --------------------
            Type: {alert['threat_type']}
            Rule: {alert.get('rule', 'N/A')}
            Severity: {alert.get('severity', 'UNKNOWN').upper()}
            Confidence: {alert.get('confidence', 0)*100:.1f}%
            
            Source: {alert.get('source_ip')}
            Target: {alert.get('destination_ip')}
            Time: {alert.get('timestamp')}
            
            Details:
            {json.dumps(alert.get('details', {}), indent=2)}
            """
            
            msg.attach(MIMEText(body, 'plain'))
            
            server = smtplib.SMTP(self.email_config.get('smtp_server'), self.email_config.get('smtp_port'))
            server.starttls()
            server.login(self.email_config.get('sender'), self.email_config.get('password'))
            server.send_message(msg)
            server.quit()
            print("    [+] Email notification sent")
        except Exception as e:
            print(f"    [-] Failed to send email: {e}")

    def _send_slack(self, alert):
        webhook = self.slack_config.get('webhook_url')
        if not webhook: return
        
        color = "#ff0000" if alert.get('confidence', 0) > 0.8 else "#ffcc00"
        
        payload = {
            "attachments": [{
                "color": color,
                "title": f"🚨 IDS Alert: {alert['threat_type']}",
                "fields": [
                    {"title": "Source IP", "value": alert.get('source_ip'), "short": True},
                    {"title": "Target IP", "value": alert.get('destination_ip'), "short": True},
                    {"title": "Confidence", "value": f"{alert.get('confidence', 0)*100:.1f}%", "short": True},
                    {"title": "Severity", "value": alert.get('severity', 'low').upper(), "short": True}
                ],
                "footer": f"Rule: {alert.get('rule', 'N/A')}"
            }]
        }
        
        try:
            requests.post(webhook, json=payload, timeout=2)
            print("    [+] Slack notification sent")
        except Exception as e:
            print(f"    [-] Failed to send Slack alert: {e}")

    def _send_discord(self, alert):
        webhook = self.discord_config.get('webhook_url')
        if not webhook: return
        
        color = 16711680 if alert.get('confidence', 0) > 0.8 else 16766720
        
        payload = {
            "embeds": [{
                "title": f"🚨 IDS Alert: {alert['threat_type']}",
                "color": color,
                "fields": [
                    {"name": "Source IP", "value": alert.get('source_ip', 'N/A'), "inline": True},
                    {"name": "Target IP", "value": alert.get('destination_ip', 'N/A'), "inline": True},
                    {"name": "Confidence", "value": f"{alert.get('confidence', 0)*100:.1f}%", "inline": True},
                    {"name": "Severity", "value": alert.get('severity', 'low').upper(), "inline": True}
                ],
                "timestamp": alert.get('timestamp')
            }]
        }

        try:
            requests.post(webhook, json=payload, timeout=2)
            print("    [+] Discord notification sent")
        except Exception as e:
            print(f"    [-] Failed to send Discord alert: {e}")

# Global instance
notifier = NotificationService()
