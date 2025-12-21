from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from flask_socketio import SocketIO, emit
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
import json
import secrets
from ConfigManager import config
from database.db_manager import db
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
            if request.is_json:
                return jsonify({'success': True, 'message': 'Login successful'})
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
    logout_user()
    return redirect(url_for('login'))

# Protected Dashboard Routes
@app.route('/')
@login_required
def index():
    """Main dashboard page"""
    return render_template('index.html', username=current_user.username)

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
def get_stats():
    """Get alert statistics"""
    stats = db.get_stats()
    stats['status'] = 'Active'
    stats['uptime'] = 'N/A'
    return jsonify(stats)

@app.route('/api/history', methods=['GET'])
@login_required
def get_history():
    """Get alert history"""
    limit = request.args.get('limit', 100, type=int)
    return jsonify(db.get_recent_alerts(limit=limit))


if __name__ == '__main__':
    host = config.get('dashboard.host', '0.0.0.0')
    port = config.get('dashboard.port', 5000)
    print(f"Starting IDS Dashboard on http://{host}:{port}")
    print(f"Default login: admin / admin123")
    socketio.run(app, host=host, port=port, debug=True)