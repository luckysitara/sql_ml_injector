"""
Flask application factory and configuration.
"""

from flask import Flask
from flask_cors import CORS
from flask_login import LoginManager
from app.models import db, User, init_db
import os

def create_app():
    """Create and configure the Flask application"""
    app = Flask(__name__)
    
    # Configuration
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
    app.config['DEBUG'] = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    
    # Database configuration
    database_url = os.environ.get('DATABASE_URL', 'sqlite:///sqli_tester.db')
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    # Enable CORS for API endpoints
    CORS(app)
    
    # Initialize database
    init_db(app)
    
    # Initialize Flask-Login
    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Please log in to access this page.'
    login_manager.login_message_category = 'info'
    
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))
    
    # Register blueprints
    from app.routes import main
    from app.auth import auth_bp
    
    app.register_blueprint(main)
    app.register_blueprint(auth_bp, url_prefix='/auth')
    
    return app
