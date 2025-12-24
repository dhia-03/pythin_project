from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from flask_socketio import SocketIO, emit
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
import json
import secrets
from ConfigManager import config
from database.db_manager import db
from permissions import role_required, permission_required, get_client_ip, ROLE_ADMIN, ROLE_ANALYST
import requests

app = Flask(__name__)

# Generate secure secret key or use configured one
secret_key = config.get('security.secret_key', None)
if not secret_key or secret_key.strip() == '':
    secret_key = secrets.token_hex(32)
app.config['SECRET_KEY'] = secret_key

# Initialize SocketIO
socketio = SocketIO(app, cors_allowed_origins="*")

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access the dashboard.'

@login_manager.user_loader
def load_user(user_id):
    """Load user by ID for Flask-Login"""
    return db.get_user_by_id(int(user_id))

# Authentication Routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handle user login"""
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        data = request.get_json() if request.is_json else request.form
        username = data.get('username')
        password = data.get('password')
        
        user = db.verify_user(username, password)
        if user:
            login_user(user, remember=True)
            # Log the login
            db.log_audit(user.id, user.username, 'login', {'method': 'password'}, get_client_ip())
            if request.is_json:
                return jsonify({'success': True, 'message': 'Login successful', 'role': user.role})
            return redirect(url_for('index'))
        else:
            if request.is_json:
                return jsonify({'success': False, 'message': 'Invalid username or password'}), 401
            flash('Invalid username or password', 'error')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    """Handle user logout"""
    db.log_audit(current_user.id, current_user.username, 'logout', None, get_client_ip())
    logout_user()
    return redirect(url_for('login'))

# Protected Dashboard Routes
@app.route('/')
@login_required
def index():
    """Main dashboard page"""
    return render_template('index.html', username=current_user.username, user_role=current_user.role)

@app.route('/users')
@login_required
@role_required([ROLE_ADMIN])
def user_management():
    """User management page (admin only)"""
    return render_template('user_management.html', username=current_user.username, user_role=current_user.role)

@app.route('/api/alert', methods=['POST'])
def receive_alert():
    """Receive alerts from IDS (no auth required for IDS to send alerts)"""
    data = request.json
    print(f"Received Alert: {data['threat_type']}")
    
    # Push to all connected clients immediately
    socketio.emit('new_alert', data)
    return jsonify({"status": "success"}), 200

@app.route('/api/stats', methods=['GET'])
@login_required
@permission_required('view_dashboard')
def get_stats():
    """Get alert statistics"""
    stats = db.get_stats()
    stats['status'] = 'Active'
    stats['uptime'] = 'N/A'
    return jsonify(stats)

@app.route('/api/history', methods=['GET'])
@login_required
@permission_required('view_dashboard')
def get_history():
    """Get alert history with acknowledgment status"""
    limit = request.args.get('limit', 100, type=int)
    alerts = db.get_recent_alerts(limit=limit)
    
    # Add acknowledgment info
    ack_ids = db.get_acknowledged_alert_ids()
    for alert in alerts:
        alert['is_acknowledged'] = alert.get('id') in ack_ids
    
    return jsonify(alerts)
# User Management API (Admin Only)
@app.route('/api/users', methods=['GET'])
@login_required
@role_required([ROLE_ADMIN])
def list_users():
    """List all users (admin only)"""
    users = db.list_users()
    return jsonify(users)

@app.route('/api/users', methods=['POST'])
@login_required
@role_required([ROLE_ADMIN])
def create_user():
    """Create new user (admin only)"""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    role = data.get('role', 'viewer')
    email = data.get('email')
    
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    
    user, error = db.create_user(username, password, role, email)
    if error:
        return jsonify({'error': error}), 400
    
    # Log the action
    db.log_audit(current_user.id, current_user.username, 'create_user', 
                 {'new_user': username, 'role': role}, get_client_ip())
    
    return jsonify({'success': True, 'user': user.to_dict()}), 201

@app.route('/api/users/<int:user_id>', methods=['PUT'])
@login_required
@role_required([ROLE_ADMIN])
def update_user(user_id):
    """Update user role (admin only)"""
    data = request.get_json()
    new_role = data.get('role')
    
    if not new_role:
        return jsonify({'error': 'Role required'}), 400
    
    # Don't allow changing own role
    if user_id == current_user.id:
        return jsonify({'error': 'Cannot change your own role'}), 400
    
    success, error = db.update_user_role(user_id, new_role)
    if error:
        return jsonify({'error': error}), 400
    
    # Log the action
    db.log_audit(current_user.id, current_user.username, 'update_user_role',
                 {'user_id': user_id, 'new_role': new_role}, get_client_ip())
    
    return jsonify({'success': True})

@app.route('/api/users/<int:user_id>/activate', methods=['POST'])
@login_required
@role_required([ROLE_ADMIN])
def activate_user(user_id):
    """Activate user (admin only)"""
    success, error = db.activate_user(user_id)
    if error:
        return jsonify({'error': error}), 400
    
    db.log_audit(current_user.id, current_user.username, 'activate_user',
                 {'user_id': user_id}, get_client_ip())
    
    return jsonify({'success': True})

@app.route('/api/users/<int:user_id>/deactivate', methods=['POST'])
@login_required
@role_required([ROLE_ADMIN])
def deactivate_user(user_id):
    """Deactivate user (admin only)"""
    # Don't allow deactivating yourself
    if user_id == current_user.id:
        return jsonify({'error': 'Cannot deactivate yourself'}), 400
    
    success, error = db.deactivate_user(user_id)
    if error:
        return jsonify({'error': error}), 400
    
    db.log_audit(current_user.id, current_user.username, 'deactivate_user',
                 {'user_id': user_id}, get_client_ip())
    
    return jsonify({'success': True})

# Alert Acknowledgment API
@app.route('/api/alerts/<int:alert_id>/acknowledge', methods=['POST'])
@login_required
@role_required([ROLE_ADMIN, ROLE_ANALYST])
def acknowledge_alert(alert_id):
    """Acknowledge an alert (admin/analyst only)"""
    data = request.get_json() or {}
    notes = data.get('notes')
    
    success, error = db.acknowledge_alert(alert_id, current_user.id, current_user.username, notes)
    if error:
        return jsonify({'error': error}), 400
    
    # Log the action
    db.log_audit(current_user.id, current_user.username, 'acknowledge_alert',
                 {'alert_id': alert_id}, get_client_ip())
    
    return jsonify({'success': True})

@app.route('/api/alerts/<int:alert_id>/acknowledgment', methods=['GET'])
@login_required
def get_acknowledgment(alert_id):
    """Get acknowledgment info for an alert"""
    ack = db.get_alert_acknowledgment(alert_id)
    return jsonify(ack if ack else {})

# Audit Logs API
@app.route('/api/audit-logs', methods=['GET'])
@login_required
@role_required([ROLE_ADMIN])
def get_audit_logs():
    """Get audit logs (admin only)"""
    limit = request.args.get('limit', 100, type=int)
    logs = db.get_audit_logs(limit=limit)
    return jsonify(logs)

# User Profile API
@app.route('/api/profile', methods=['GET'])
@login_required
def get_profile():
    """Get current user profile"""
    return jsonify(current_user.to_dict())

# Data Export (Admin/Analyst only)
@app.route('/api/export', methods=['POST'])
@login_required
@permission_required('export_data')
def log_export():
    """Log data export action"""
    data = request.get_json() or {}
    db.log_audit(current_user.id, current_user.username, 'export_data',
                 {'count': data.get('count', 0)}, get_client_ip())
    return jsonify({'success': True})


if __name__ == '__main__':
    host = config.get('dashboard.host', '0.0.0.0')
    port = config.get('dashboard.port', 5000)
    print(f"Starting IDS Dashboard on http://{host}:{port}")
    print(f"Default login: admin / admin123")
    socketio.run(app, host=host, port=port, debug=True)