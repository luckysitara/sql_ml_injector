"""
Database models for user authentication and session management.
"""

from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import secrets

db = SQLAlchemy()

class User(UserMixin, db.Model):
    """User model for authentication"""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_login = db.Column(db.DateTime)
    login_count = db.Column(db.Integer, default=0, nullable=False)
    
    # Relationships
    test_sessions = db.relationship('TestSession', backref='user', lazy=True, cascade='all, delete-orphan')
    api_keys = db.relationship('APIKey', backref='user', lazy=True, cascade='all, delete-orphan')
    
    def set_password(self, password):
        """Set password hash"""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """Check password against hash"""
        return check_password_hash(self.password_hash, password)
    
    def update_login(self):
        """Update login statistics"""
        self.last_login = datetime.utcnow()
        self.login_count += 1
        db.session.commit()
    
    def to_dict(self):
        """Convert user to dictionary"""
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'is_active': self.is_active,
            'is_admin': self.is_admin,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_login': self.last_login.isoformat() if self.last_login else None,
            'login_count': self.login_count
        }
    
    def __repr__(self):
        return f'<User {self.username}>'

class TestSession(db.Model):
    """Model to store SQL injection test sessions"""
    __tablename__ = 'test_sessions'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    target_url = db.Column(db.String(500), nullable=False)
    parameter = db.Column(db.String(100), nullable=False)
    method = db.Column(db.String(10), nullable=False)
    total_payloads = db.Column(db.Integer, nullable=False)
    vulnerabilities_found = db.Column(db.Integer, nullable=False)
    test_duration = db.Column(db.Float)  # Duration in seconds
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    results_json = db.Column(db.Text)  # Store full results as JSON
    
    def to_dict(self):
        """Convert test session to dictionary"""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'target_url': self.target_url,
            'parameter': self.parameter,
            'method': self.method,
            'total_payloads': self.total_payloads,
            'vulnerabilities_found': self.vulnerabilities_found,
            'test_duration': self.test_duration,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
    
    def __repr__(self):
        return f'<TestSession {self.id}: {self.target_url}>'

class APIKey(db.Model):
    """Model for API key management"""
    __tablename__ = 'api_keys'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    key_name = db.Column(db.String(100), nullable=False)
    key_hash = db.Column(db.String(255), nullable=False, unique=True)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_used = db.Column(db.DateTime)
    usage_count = db.Column(db.Integer, default=0, nullable=False)
    
    @staticmethod
    def generate_key():
        """Generate a new API key"""
        return secrets.token_urlsafe(32)
    
    def set_key(self, key):
        """Set API key hash"""
        self.key_hash = generate_password_hash(key)
    
    def check_key(self, key):
        """Check API key against hash"""
        return check_password_hash(self.key_hash, key)
    
    def update_usage(self):
        """Update API key usage statistics"""
        self.last_used = datetime.utcnow()
        self.usage_count += 1
        db.session.commit()
    
    def to_dict(self):
        """Convert API key to dictionary"""
        return {
            'id': self.id,
            'key_name': self.key_name,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_used': self.last_used.isoformat() if self.last_used else None,
            'usage_count': self.usage_count
        }
    
    def __repr__(self):
        return f'<APIKey {self.key_name}>'

def init_db(app):
    """Initialize database with app context"""
    db.init_app(app)
    
    with app.app_context():
        # Create all tables
        db.create_all()
        
        # Create default admin user if it doesn't exist
        admin_user = User.query.filter_by(username='admin').first()
        if not admin_user:
            admin_user = User(
                username='admin',
                email='admin@sqli-tester.local',
                is_admin=True
            )
            admin_user.set_password('admin123')  # Change this in production!
            db.session.add(admin_user)
            db.session.commit()
            print("Created default admin user: admin/admin123")
