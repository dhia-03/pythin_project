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
            'severity': self.severity
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
    created_at = Column(DateTime, default=datetime.utcnow)
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
