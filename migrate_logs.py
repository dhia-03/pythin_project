import json
import os
from datetime import datetime
from database.db_manager import db
from database.models import Alert

LOG_FILE = "ids_alerts.log"

def migrate():
    if not os.path.exists(LOG_FILE):
        print("[-] No log file found to migrate.")
        return

    print(f"[+] Migrating entries from {LOG_FILE} to database...")
    count = 0
    session = db.get_session()
    
    try:
        with open(LOG_FILE, 'r') as f:
            for line in f:
                try:
                    # Log format: 2025-12-21 21:05:00,123 - WARNING - {"timestamp": ...}
                    # We need to extract the JSON part
                    json_start = line.find('{')
                    if json_start == -1:
                        continue
                        
                    json_str = line[json_start:].strip()
                    data = json.loads(json_str)
                    
                    # Convert to DB Alert
                    confidence = data.get('confidence', 0.0)
                    severity = 'low'
                    if confidence > 0.8: severity = 'critical'
                    elif confidence > 0.6: severity = 'high'
                    elif confidence > 0.4: severity = 'medium'

                    alert = Alert(
                        timestamp=datetime.fromisoformat(data['timestamp']),
                        threat_type=data.get('threat_type'),
                        rule=data.get('rule'),
                        source_ip=data.get('source_ip'),
                        destination_ip=data.get('destination_ip'),
                        confidence=confidence,
                        details=json.dumps(data.get('details', {})),
                        severity=severity,
                        is_archived=True # Mark migrated alerts as archived/old
                    )
                    session.add(alert)
                    count += 1
                except Exception as e:
                    print(f"[-] Skipped malformed line: {e}")
        
        session.commit()
        print(f"[+] Successfully migrated {count} alerts to database.")
        
        # Rename old log file
        os.rename(LOG_FILE, f"{LOG_FILE}.bak")
        print(f"[+] Renamed {LOG_FILE} to {LOG_FILE}.bak")
        
    except Exception as e:
        session.rollback()
        print(f"[-] Migration failed: {e}")
    finally:
        session.close()

if __name__ == "__main__":
    migrate()
