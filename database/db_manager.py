import json
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session
from datetime import datetime, timedelta
from database.models import Base, Alert, BlockedIP, User
from ConfigManager import config
import os


class DBManager:
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(DBManager, cls).__new__(cls)
            cls._instance._init_db()
        return cls._instance

    def _init_db(self):
        db_path = config.get('database.path', 'ids_alerts.db')
        # Ensure we use absolute path if it's a file
        if not db_path.startswith('sqlite:///'):
             # If just a filename, prepend sqlite prefix
            db_conn_string = f"sqlite:///{db_path}"
        else:
            db_conn_string = db_path
            
        self.engine = create_engine(db_conn_string, connect_args={'check_same_thread': False})
        Base.metadata.create_all(self.engine)
        self.Session = scoped_session(sessionmaker(bind=self.engine))
        
        # Create default admin user if no users exist
        self.create_default_user()


    def get_session(self):
        return self.Session()

    def add_alert(self, alert_data):
        session = self.Session()
        try:
            # Determine severity if not present
            confidence = alert_data.get('confidence', 0.0)
            severity = 'low'
            if confidence > 0.8: severity = 'critical'
            elif confidence > 0.6: severity = 'high'
            elif confidence > 0.4: severity = 'medium'

            new_alert = Alert(
                timestamp=datetime.now(), # Use current time if not provided or valid
                threat_type=alert_data.get('threat_type'),
                rule=alert_data.get('rule'),
                source_ip=alert_data.get('source_ip'),
                destination_ip=alert_data.get('destination_ip'),
                confidence=confidence,
                details=json.dumps(alert_data.get('details', {})),
                severity=severity
            )
            session.add(new_alert)
            session.commit()
            return new_alert.to_dict()
        except Exception as e:
            session.rollback()
            print(f"[-] Error adding alert to DB: {e}")
            return None
        finally:
            session.close()

    def get_recent_alerts(self, limit=50):
        session = self.Session()
        try:
            alerts = session.query(Alert).order_by(Alert.timestamp.desc()).limit(limit).all()
            return [a.to_dict() for a in alerts]
        finally:
            session.close()
            
    def get_stats(self):
        """Get basics stats for dashboard"""
        session = self.Session()
        try:
            total = session.query(Alert).count()
            high_risk = session.query(Alert).filter(Alert.confidence > 0.8).count()
            
            # Group by threat type
            from sqlalchemy import func
            type_distribution = session.query(Alert.threat_type, func.count(Alert.id)).group_by(Alert.threat_type).all()
            
            return {
                'total_alerts': total,
                'high_risk_count': high_risk,
                'distribution': {t[0]: t[1] for t in type_distribution}
            }
        finally:
            session.close()
    
    # Authentication Methods
    def create_default_user(self):
        """Create default admin user if no users exist"""
        session = self.Session()
        try:
            user_count = session.query(User).count()
            if user_count == 0:
                admin = User(username='admin')
                admin.set_password('admin123')
                session.add(admin)
                session.commit()
                print("[+] Default admin user created (username: admin, password: admin123)")
        except Exception as e:
            session.rollback()
            print(f"[-] Error creating default user: {e}")
        finally:
            session.close()
    
    def get_user_by_username(self, username):
        """Get user by username"""
        session = self.Session()
        try:
            return session.query(User).filter(User.username == username).first()
        finally:
            session.close()
    
    def get_user_by_id(self, user_id):
        """Get user by ID (required by Flask-Login)"""
        session = self.Session()
        try:
            return session.query(User).filter(User.id == user_id).first()
        finally:
            session.close()
    
    def verify_user(self, username, password):
        """Verify user credentials"""
        user = self.get_user_by_username(username)
        if user and user.check_password(password):
            return user
        return None

# Global DB instance
db = DBManager()
