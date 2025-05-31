"""
Authentication routes and utilities.
"""

from flask import Blueprint, request, jsonify, session, render_template, redirect, url_for, flash
from flask_login import login_user, logout_user, login_required, current_user
from app.models import User, APIKey, db
from functools import wraps
import logging

auth_bp = Blueprint('auth', __name__)
logger = logging.getLogger(__name__)

def admin_required(f):
    """Decorator to require admin privileges"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            return jsonify({'error': 'Admin privileges required'}), 403
        return f(*args, **kwargs)
    return decorated_function

def api_key_required(f):
    """Decorator to require valid API key"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        if not api_key:
            return jsonify({'error': 'API key required'}), 401
        
        # Check if API key exists and is active
        for key_obj in APIKey.query.filter_by(is_active=True).all():
            if key_obj.check_key(api_key):
                key_obj.update_usage()
                request.current_api_key = key_obj
                request.current_user = key_obj.user
                return f(*args, **kwargs)
        
        return jsonify({'error': 'Invalid API key'}), 401
    return decorated_function

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """User login"""
    if request.method == 'GET':
        return render_template('auth/login.html')
    
    data = request.get_json() if request.is_json else request.form
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        if request.is_json:
            return jsonify({'error': 'Username and password required'}), 400
        flash('Username and password required', 'error')
        return redirect(url_for('auth.login'))
    
    user = User.query.filter_by(username=username).first()
    
    if user and user.check_password(password) and user.is_active:
        login_user(user, remember=True)
        user.update_login()
        
        logger.info(f"User {username} logged in successfully")
        
        if request.is_json:
            return jsonify({
                'success': True,
                'message': 'Login successful',
                'user': user.to_dict()
            })
        
        flash('Login successful', 'success')
        return redirect(url_for('main.index'))
    
    logger.warning(f"Failed login attempt for username: {username}")
    
    if request.is_json:
        return jsonify({'error': 'Invalid credentials'}), 401
    
    flash('Invalid credentials', 'error')
    return redirect(url_for('auth.login'))

@auth_bp.route('/logout', methods=['POST', 'GET'])
@login_required
def logout():
    """User logout"""
    username = current_user.username
    logout_user()
    
    logger.info(f"User {username} logged out")
    
    if request.is_json:
        return jsonify({'success': True, 'message': 'Logout successful'})
    
    flash('Logout successful', 'success')
    return redirect(url_for('auth.login'))

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    """User registration"""
    if request.method == 'GET':
        return render_template('auth/register.html')
    
    data = request.get_json() if request.is_json else request.form
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    confirm_password = data.get('confirm_password')
    
    # Validation
    if not all([username, email, password, confirm_password]):
        error = 'All fields are required'
        if request.is_json:
            return jsonify({'error': error}), 400
        flash(error, 'error')
        return redirect(url_for('auth.register'))
    
    if password != confirm_password:
        error = 'Passwords do not match'
        if request.is_json:
            return jsonify({'error': error}), 400
        flash(error, 'error')
        return redirect(url_for('auth.register'))
    
    if len(password) < 6:
        error = 'Password must be at least 6 characters long'
        if request.is_json:
            return jsonify({'error': error}), 400
        flash(error, 'error')
        return redirect(url_for('auth.register'))
    
    # Check if user already exists
    if User.query.filter_by(username=username).first():
        error = 'Username already exists'
        if request.is_json:
            return jsonify({'error': error}), 400
        flash(error, 'error')
        return redirect(url_for('auth.register'))
    
    if User.query.filter_by(email=email).first():
        error = 'Email already exists'
        if request.is_json:
            return jsonify({'error': error}), 400
        flash(error, 'error')
        return redirect(url_for('auth.register'))
    
    # Create new user
    try:
        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
        logger.info(f"New user registered: {username}")
        
        if request.is_json:
            return jsonify({
                'success': True,
                'message': 'Registration successful',
                'user': user.to_dict()
            }), 201
        
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('auth.login'))
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Registration error: {str(e)}")
        
        error = 'Registration failed. Please try again.'
        if request.is_json:
            return jsonify({'error': error}), 500
        flash(error, 'error')
        return redirect(url_for('auth.register'))

@auth_bp.route('/profile')
@login_required
def profile():
    """User profile - Always return JSON for AJAX requests"""
    return jsonify({
        'user': current_user.to_dict(),
        'api_keys': [key.to_dict() for key in current_user.api_keys if key.is_active]
    })

@auth_bp.route('/api-keys', methods=['GET', 'POST'])
@login_required
def manage_api_keys():
    """Manage API keys"""
    if request.method == 'GET':
        api_keys = [key.to_dict() for key in current_user.api_keys if key.is_active]
        return jsonify({'api_keys': api_keys})
    
    # Create new API key
    data = request.get_json()
    key_name = data.get('key_name')
    
    if not key_name:
        return jsonify({'error': 'Key name is required'}), 400
    
    # Check if key name already exists for this user
    existing_key = APIKey.query.filter_by(user_id=current_user.id, key_name=key_name, is_active=True).first()
    if existing_key:
        return jsonify({'error': 'Key name already exists'}), 400
    
    try:
        # Generate new API key
        new_key = APIKey.generate_key()
        api_key = APIKey(user_id=current_user.id, key_name=key_name)
        api_key.set_key(new_key)
        
        db.session.add(api_key)
        db.session.commit()
        
        logger.info(f"New API key created for user {current_user.username}: {key_name}")
        
        return jsonify({
            'success': True,
            'message': 'API key created successfully',
            'api_key': new_key,  # Only return the actual key once
            'key_info': api_key.to_dict()
        }), 201
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"API key creation error: {str(e)}")
        return jsonify({'error': 'Failed to create API key'}), 500

@auth_bp.route('/api-keys/<int:key_id>', methods=['DELETE'])
@login_required
def delete_api_key(key_id):
    """Delete API key"""
    api_key = APIKey.query.filter_by(id=key_id, user_id=current_user.id).first()
    
    if not api_key:
        return jsonify({'error': 'API key not found'}), 404
    
    try:
        api_key.is_active = False
        db.session.commit()
        
        logger.info(f"API key deactivated for user {current_user.username}: {api_key.key_name}")
        
        return jsonify({'success': True, 'message': 'API key deleted successfully'})
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"API key deletion error: {str(e)}")
        return jsonify({'error': 'Failed to delete API key'}), 500

@auth_bp.route('/users')
@login_required
@admin_required
def list_users():
    """List all users (admin only)"""
    users = User.query.all()
    return jsonify({
        'users': [user.to_dict() for user in users]
    })

@auth_bp.route('/users/<int:user_id>/toggle-status', methods=['POST'])
@login_required
@admin_required
def toggle_user_status(user_id):
    """Toggle user active status (admin only)"""
    user = User.query.get_or_404(user_id)
    
    if user.id == current_user.id:
        return jsonify({'error': 'Cannot deactivate your own account'}), 400
    
    try:
        user.is_active = not user.is_active
        db.session.commit()
        
        status = 'activated' if user.is_active else 'deactivated'
        logger.info(f"User {user.username} {status} by admin {current_user.username}")
        
        return jsonify({
            'success': True,
            'message': f'User {status} successfully',
            'user': user.to_dict()
        })
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"User status toggle error: {str(e)}")
        return jsonify({'error': 'Failed to update user status'}), 500

@auth_bp.route('/change-password', methods=['POST'])
@login_required
def change_password():
    """Change user password"""
    data = request.get_json()
    current_password = data.get('current_password')
    new_password = data.get('new_password')
    confirm_password = data.get('confirm_password')
    
    if not all([current_password, new_password, confirm_password]):
        return jsonify({'error': 'All fields are required'}), 400
    
    if not current_user.check_password(current_password):
        return jsonify({'error': 'Current password is incorrect'}), 400
    
    if new_password != confirm_password:
        return jsonify({'error': 'New passwords do not match'}), 400
    
    if len(new_password) < 6:
        return jsonify({'error': 'Password must be at least 6 characters long'}), 400
    
    try:
        current_user.set_password(new_password)
        db.session.commit()
        
        logger.info(f"Password changed for user {current_user.username}")
        
        return jsonify({
            'success': True,
            'message': 'Password changed successfully'
        })
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Password change error: {str(e)}")
        return jsonify({'error': 'Failed to change password'}), 500
