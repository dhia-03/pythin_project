from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit
import json
from ConfigManager import config
from database.db_manager import db
from GeolocateService import geo_service
import requests

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret_key_ids'
socketio = SocketIO(app, cors_allowed_origins="*")

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/alert', methods=['POST'])
def receive_alert():
    data = request.json
    print(f"Received Alert: {data['threat_type']}")
    
    # Push to all connected clients immediately
    # Note: We rely on the IDS to save to DB, but for the dashboard display we just broadcast
    socketio.emit('new_alert', data)
    return jsonify({"status": "success"}), 200

@app.route('/api/stats', methods=['GET'])
def get_stats():
    stats = db.get_stats()
    # Add system status
    stats['status'] = 'Active'
    stats['uptime'] = 'N/A' # Could be implemented
    return jsonify(stats)

@app.route('/api/geolocate/<ip>', methods=['GET'])
def get_location(ip):
    location = geo_service.get_location(ip)
    if location:
        return jsonify(location)
    return jsonify({'error': 'Location not found'}), 404

@app.route('/api/history', methods=['GET'])
def get_history():
    limit = request.args.get('limit', 100, type=int)
    return jsonify(db.get_recent_alerts(limit=limit))


if __name__ == '__main__':
    host = config.get('dashboard.host', '0.0.0.0')
    port = config.get('dashboard.port', 5000)
    print(f"Starting IDS Dashboard on http://{host}:{port}")
    socketio.run(app, host=host, port=port, debug=True)