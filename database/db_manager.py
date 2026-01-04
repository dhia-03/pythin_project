import json
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session
from datetime import datetime, timedelta
from database.models import Base, Alert, BlockedIP, User, AuditLog, AlertAcknowledgment
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
                admin = User(username='admin', role='admin')
                admin.set_password('admin123')
                session.add(admin)
                session.commit()
                print("[+] Default admin user created (username: admin, password: admin123, role: admin)")
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
            user = session.query(User).filter(User.id == user_id).first()
            if user:
                session.refresh(user)
                session.expunge(user)
            return user
        finally:
            session.close()
    
    def verify_user(self, username, password):
        """Verify user credentials and update last_login"""
        session = self.Session()
        try:
            user = session.query(User).filter(User.username == username).first()
            if user and user.is_active and user.check_password(password):
                # Update last login
                user.last_login = datetime.utcnow()
                session.commit()
                # Refresh to load all attributes before detaching
                session.refresh(user)
                # Make the object usable outside the session
                session.expunge(user)
                return user
            return None
        except Exception as e:
            session.rollback()
            print(f"[-] Error during user verification: {e}")
            return None
        finally:
            session.close()
    
    # User Management Methods (RBAC)
    def create_user(self, username, password, role='viewer', email=None):
        """Create a new user with specified role"""
        session = self.Session()
        try:
            # Check if username already exists
            existing = session.query(User).filter(User.username == username).first()
            if existing:
                return None, "Username already exists"
            
            # Validate role
            valid_roles = ['admin', 'analyst']
            if role not in valid_roles:
                return None, f"Invalid role. Must be one of: {', '.join(valid_roles)}"
            
            user = User(username=username, role=role, email=email)
            user.set_password(password)
            session.add(user)
            session.commit()
            
            # Refresh to load all attributes before detaching
            session.refresh(user)
            # Make the object usable outside the session
            session.expunge(user)
            
            return user, None
        except Exception as e:
            session.rollback()
            print(f"[-] Error creating user: {e}")
            return None, str(e)
        finally:
            session.close()
    
    def update_user_role(self, user_id, new_role):
        """Update user's role"""
        session = self.Session()
        try:
            valid_roles = ['admin', 'analyst']
            if new_role not in valid_roles:
                return False, f"Invalid role. Must be one of: {', '.join(valid_roles)}"
            
            user = session.query(User).filter(User.id == user_id).first()
            if not user:
                return False, "User not found"
            
            user.role = new_role
            session.commit()
            return True, None
        except Exception as e:
            session.rollback()
            print(f"[-] Error updating user role: {e}")
            return False, str(e)
        finally:
            session.close()
    
    def list_users(self):
        """Get all users"""
        session = self.Session()
        try:
            users = session.query(User).all()
            return [u.to_dict() for u in users]
        finally:
            session.close()
    
    def deactivate_user(self, user_id):
        """Deactivate a user (soft delete)"""
        session = self.Session()
        try:
            user = session.query(User).filter(User.id == user_id).first()
            if not user:
                return False, "User not found"
            
            user.is_active = False
            session.commit()
            return True, None
        except Exception as e:
            session.rollback()
            print(f"[-] Error deactivating user: {e}")
            return False, str(e)
        finally:
            session.close()
    
    def activate_user(self, user_id):
        """Activate a user"""
        session = self.Session()
        try:
            user = session.query(User).filter(User.id == user_id).first()
            if not user:
                return False, "User not found"
            
            user.is_active = True
            session.commit()
            return True, None
        except Exception as e:
            session.rollback()
            print(f"[-] Error activating user: {e}")
            return False, str(e)
        finally:
            session.close()
    
    # Audit Logging
    def log_audit(self, user_id, username, action, details=None, ip_address=None):
        """Log user action for audit trail"""
        session = self.Session()
        try:
            log = AuditLog(
                user_id=user_id,
                username=username,
                action=action,
                details=json.dumps(details) if details else None,
                ip_address=ip_address
            )
            session.add(log)
            session.commit()
        except Exception as e:
            session.rollback()
            print(f"[-] Error logging audit: {e}")
        finally:
            session.close()
    
    def get_audit_logs(self, limit=100, user_id=None):
        """Get audit logs"""
        session = self.Session()
        try:
            query = session.query(AuditLog)
            if user_id:
                query = query.filter(AuditLog.user_id == user_id)
            logs = query.order_by(AuditLog.timestamp.desc()).limit(limit).all()
            return [log.to_dict() for log in logs]
        finally:
            session.close()
    
    # Alert Acknowledgment
    def acknowledge_alert(self, alert_id, user_id, username, notes=None):
        """Acknowledge an alert"""
        session = self.Session()
        try:
            # Check if already acknowledged
            existing = session.query(AlertAcknowledgment).filter(
                AlertAcknowledgment.alert_id == alert_id
            ).first()
            
            if existing:
                return False, "Alert already acknowledged"
            
            ack = AlertAcknowledgment(
                alert_id=alert_id,
                user_id=user_id,
                username=username,
                notes=notes
            )
            session.add(ack)
            session.commit()
            return True, None
        except Exception as e:
            session.rollback()
            print(f"[-] Error acknowledging alert: {e}")
            return False, str(e)
        finally:
            session.close()
    
    def get_alert_acknowledgment(self, alert_id):
        """Get acknowledgment info for an alert"""
        session = self.Session()
        try:
            ack = session.query(AlertAcknowledgment).filter(
                AlertAcknowledgment.alert_id == alert_id
            ).first()
            return ack.to_dict() if ack else None
        finally:
            session.close()
    
    def get_acknowledged_alert_ids(self):
        """Get set of all acknowledged alert IDs"""
        session = self.Session()
        try:
            acks = session.query(AlertAcknowledgment.alert_id).all()
            return {ack[0] for ack in acks}
        finally:
            session.close()

# Global DB instance
db = DBManager()
