# Network Intrusion Detection System (IDS)

A real-time network intrusion detection system with live web dashboard visualization, database persistence, and multi-channel notifications.

## 🚀 Features

- **Real-time Packet Capture**: High-performance sniffing using Scapy
- **Advanced Threat Detection**:
  - Port Scan Detection
  - SYN Flood Detection
  - DDoS Attack Detection
  - Configurable thresholds
- **Live Dashboard**:
  - Interactive world map (Leaflet.js)
  - Real-time alert feed
  - Threat distribution charts
  - IP Geolocation
- **Database Persistence**: SQLite storage for alert history and statistics
- **Notification System**:
  - Email alerts
  - Slack webhooks
  - Discord integration
- **Export**: Download alerts as CSV

## 📋 Requirements

- Python 3.8+
- Root/sudo privileges (required for packet capture)
- `libsodium` (sometimes required for networking libs)

## 🛠️ Installation

1. Clone the repository:
```bash
git clone git@github.com:dhia-03/pythin_project.git
cd pythin_project
```

2. Create and activate virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Configure the system:
```bash
cp config.example.yaml config.yaml
# Edit config.yaml with your settings
```

## 🎯 Usage

### 1. Start the Dashboard
```bash
python app.py
```
Access at `http://localhost:5000`

### 2. Run the IDS (in a new terminal)
Requires root privileges to capture packets:
```bash
sudo ./venv/bin/python Integration.py
# OR if using system python
sudo python Integration.py
```

### 3. Run Tests
```bash
python test_integration.py
```

## ⚙️ Configuration

The system is fully configurable via `config.yaml`:
- **Network**: Interface selection
- **Detection**: Customize packet rate thresholds
- **Notifications**: Enable/disable channels and set credentials
- **Database**: Path to SQLite file

## 🏗️ Architecture

- **Core**: `PacketCapture.py`, `Integration.py`
- **Analysis**: `TrafficAnalyzer.py`, `DetectionEngine.py`
- **Storage**: `database/` (SQLAlchemy models)
- **Web**: `app.py`, `templates/index.html`
- **Services**: `ConfigManager.py`, `GeolocateService.py`, `NotificationService.py`

## 🔒 Security Notes

⚠️ **Educational Use**: This system is designed for learning and testing. For production:
- Enable authentication (not included by default)
- Use a dedicated database (PostgreSQL)
- Run behind a reverse proxy (Nginx)

## 👤 Author

dhia-03
