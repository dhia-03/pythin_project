from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit
import json

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret_key_ids'
socketio = SocketIO(app, cors_allowed_origins="*")

# Store last 50 alerts for immediate display upon connection
alert_history = []

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/alert', methods=['POST'])
def receive_alert():
    data = request.json
    print(f"Received Alert: {data['threat_type']}")
    
    # Store locally
    alert_history.append(data)
    if len(alert_history) > 50:
        alert_history.pop(0)

    # Push to all connected clients immediately
    socketio.emit('new_alert', data)
    return jsonify({"status": "success"}), 200

if __name__ == '__main__':
    print("Starting IDS Dashboard on http://localhost:5000")
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)