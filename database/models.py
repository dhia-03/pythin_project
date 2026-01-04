from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Text, Boolean
from sqlalchemy.orm import declarative_base
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin

Base = declarative_base()

class Alert(Base):
    __tablename__ = 'alerts'

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    threat_type = Column(String(50), nullable=False)
    rule = Column(String(100))
    source_ip = Column(String(45))  # IPv6 compatible length
    destination_ip = Column(String(45))
    confidence = Column(Float)
    details = Column(Text)  # JSON stored as text
    severity = Column(String(20)) # low, medium, high, critical
    is_archived = Column(Boolean, default=False)
    
    # Threat Intelligence fields
    abuse_score = Column(Integer, default=0)  # 0-100 from AbuseIPDB
    is_known_threat = Column(Boolean, default=False)
    threat_categories = Column(Text)  # JSON array of categories
    total_reports = Column(Integer, default=0)  # Total abuse reports

    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat(),
            'threat_type': self.threat_type,
            'rule': self.rule,
            'source_ip': self.source_ip,
            'destination_ip': self.destination_ip,
            'confidence': self.confidence,
            'details': self.details,
            'severity': self.severity,
            'abuse_score': self.abuse_score,
            'is_known_threat': self.is_known_threat,
            'threat_categories': self.threat_categories,
            'total_reports': self.total_reports
        }

class BlockedIP(Base):
    __tablename__ = 'blocked_ips'
    
    id = Column(Integer, primary_key=True)
    ip_address = Column(String(45), unique=True, nullable=False)
    reason = Column(String(200))
    blocked_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime)
    is_active = Column(Boolean, default=True)

class User(Base, UserMixin):
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True)
    username = Column(String(80), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    email = Column(String(255), nullable=True)
    role = Column(String(20), default='viewer', nullable=False)  # admin, analyst, viewer
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=True)
    
    def set_password(self, password):
        """Hash and set the user's password"""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """Verify the password against the stored hash"""
        return check_password_hash(self.password_hash, password)
    
    def get_id(self):
        """Required by Flask-Login"""
        return str(self.id)
    
    def to_dict(self):
        """Convert user to dictionary (excluding password)"""
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'role': self.role,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_login': self.last_login.isoformat() if self.last_login else None,
            'is_active': self.is_active
        }

class AuditLog(Base):
    __tablename__ = 'audit_logs'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, nullable=False, index=True)
    username = Column(String(80))  # Denormalized for easy viewing
    action = Column(String(100), nullable=False)  # login, create_user, export_data, etc.
    details = Column(Text)  # JSON with additional info
    ip_address = Column(String(45))
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    
    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'username': self.username,
            'action': self.action,
            'details': self.details,
            'ip_address': self.ip_address,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None
        }

class AlertAcknowledgment(Base):
    __tablename__ = 'alert_acknowledgments'
    
    id = Column(Integer, primary_key=True)
    alert_id = Column(Integer, nullable=False, index=True)
    user_id = Column(Integer, nullable=False)
    username = Column(String(80))  # Denormalized
    notes = Column(Text)
    acknowledged_at = Column(DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'alert_id': self.alert_id,
            'user_id': self.user_id,
            'username': self.username,
            'notes': self.notes,
            'acknowledged_at': self.acknowledged_at.isoformat() if self.acknowledged_at else None
        }
