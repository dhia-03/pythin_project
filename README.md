# Network Intrusion Detection System (IDS)

A professional-grade network intrusion detection system with real-time threat monitoring, threat intelligence integration, and a modern web-based dashboard.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.8%2B-blue)

## 🚀 Features

### Core Detection Capabilities
- **Port Scan Detection**: Identifies reconnaissance attempts across multiple ports
- **DDoS Attack Detection**: Detects distributed denial of service attacks
- **Real-time Packet Analysis**: High-performance packet capture using Scapy
- **Configurable Thresholds**: Customize detection sensitivity per attack type

### Threat Intelligence
- **AbuseIPDB Integration**: Real-time IP reputation scoring
- **Automatic Enrichment**: Every alert includes abuse confidence scores and threat categories
- **Known Threat Detection**: Identifies IPs with history of malicious activity
- **Smart Caching**: 24-hour cache minimizes API calls

### Professional Dashboard
- **Modern UI**: Clean, responsive interface with dark mode
- **Real-time Updates**: WebSocket-powered live threat feed
- **Threat Visualization**: Interactive charts showing attack distribution
- **IP Reputation Indicators**: Color-coded badges (red/yellow/green)
- **Data Export**: Download alerts as CSV for analysis

### Security & Access Control
- **Role-Based Access Control (RBAC)**:
  - **Admin**: User management, audit logs, full system control
  - **Analyst**: Read-only monitoring with export capabilities
- **Session Management**: Secure authentication with persistent sessions
- **Audit Logging**: Track all user actions and system events
- **Password Protection**: Hashed passwords using industry-standard methods

### Data Persistence
- **SQLite Database**: Efficient alert storage and history
- **Alert Archive**: Complete audit trail of detected threats
- **User Management**: Store user accounts and preferences
- **Audit Trail**: Comprehensive logging of system activities

### Notifications (Optional)
- **Email Alerts**: SMTP integration for critical threats
- **Slack Integration**: Webhook-based team notifications
- **Discord Integration**: Real-time alerts to Discord channels

## 📋 Requirements

- **Python**: 3.8 or higher
- **Operating System**: Linux (tested on Ubuntu/Debian)
- **Privileges**: Root/sudo access for packet capture
- **Network**: Active network interface for monitoring
- **Optional**: AbuseIPDB API key for threat intelligence (free tier available)

## 🛠️ Quick Installation

### 1. Clone Repository
```bash
git clone git@github.com:dhia-03/pythin_project.git
cd pythin_project
```

### 2. Set Up Environment
```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Configure System
```bash
# Copy example configuration
cp config.example.yaml config.yaml

# Edit config.yaml with your settings
nano config.yaml
```

**Minimum required configuration:**
```yaml
network:
  interface: "eth0"  # Change to your network interface

database:
  path: "ids_alerts.db"
```

### 4. Run Database Migration
```bash
# Apply threat intelligence schema
python3 migrate_threat_intel.py
```

## 🎯 Usage

### Starting the System

**Option 1: Quick Start (Recommended)**
```bash
# Terminal 1: Start dashboard
python3 app.py

# Terminal 2: Start IDS engine
sudo python3 Integration.py
```

**Option 2: Using Convenience Scripts**
```bash
# Terminal 1
./start_dashboard.sh

# Terminal 2
sudo ./start_ids.sh
```

### Accessing the Dashboard

1. Open browser to `http://localhost:5000`
2. Login with default credentials:
   - **Username**: `admin`
   - **Password**: `admin123`
3. **⚠️ Change default password immediately** in production environments

### Default User Accounts

| Username | Password | Role | Permissions |
|----------|----------|------|-------------|
| admin | admin123 | Admin | Full system control, user management, audit logs |
| analyst | analyst123 | Analyst | Read-only monitoring, data export |

## ⚙️ Configuration

### Network Interface
Find your interface:
```bash
ip addr show
# Common interfaces: eth0, wlan0, enp0s3
```

Update `config.yaml`:
```yaml
network:
  interface: "eth0"  # Your interface name
```

### Detection Thresholds
```yaml
detection:
  port_scan_threshold: 10      # Unique ports to trigger alert
  ddos_threshold: 100          # Requests/second
```

### Threat Intelligence (Optional)
```yaml
threat_intelligence:
  abuseipdb:
    enabled: true
    api_key: "YOUR_API_KEY_HERE"  # Get from abuseipdb.com
    cache_ttl: 86400
    confidence_threshold: 75
```

**Get API Key**: Sign up at [https://www.abuseipdb.com/](https://www.abuseipdb.com/) (free tier: 1,000 checks/day)

### Notifications (Optional)
```yaml
notifications:
  email:
    enabled: true
    smtp_server: "smtp.gmail.com"
    smtp_port: 587
    sender: "your-email@gmail.com"
    password: "your-app-password"
    recipients:
      - "admin@example.com"
```

## 🧪 Testing Detection

### Test Port Scan Detection
```bash
# Scan 20 ports (will trigger after 10)
nmap -p 1-20 localhost

# More aggressive scan
nmap -sS -p 1-100 <target-ip>
```

### Test DDoS Detection
```bash
# Use included simulation script
python3 simulate_ddos.py 127.0.0.1 80 200
```

### Verify Threat Intelligence
```bash
# Test API connectivity
python3 test_threat_intel.py
```

## 📊 Architecture

```
┌─────────────────────────────────────────────────┐
│  Web Dashboard (Flask + SocketIO)              │
│  ├─ app.py (Flask application)                 │
│  ├─ templates/index.html (UI)                  │
│  └─ Authentication & RBAC                      │
└─────────────────────────────────────────────────┘
                    ↕
┌─────────────────────────────────────────────────┐
│  Detection Engine                               │
│  ├─ Integration.py (Main orchestrator)         │
│  ├─ PacketCapture.py (Scapy interface)         │
│  ├─ DetectionEngine.py (Rule engine)           │
│  └─ ThreatIntelligence.py (AbuseIPDB)         │
└─────────────────────────────────────────────────┘
                    ↕
┌─────────────────────────────────────────────────┐
│  Data Layer                                     │
│  ├─ database/models.py (SQLAlchemy ORM)        │
│  ├─ database/db_manager.py (CRUD operations)   │
│  └─ ids_alerts.db (SQLite database)            │
└─────────────────────────────────────────────────┘
```

## 🔒 Security Best Practices

### For Production Deployment

1. **Change Default Credentials**
   ```bash
   # Log in as admin and create new admin user
   # Then deactivate the default admin account
   ```

2. **Configure Secret Key**
   ```yaml
   security:
     secret_key: "your-long-random-secret-key-here"
   ```
   Generate: `python -c "import secrets; print(secrets.token_hex(32))"`

3. **Use HTTPS**
   - Deploy behind reverse proxy (Nginx/Apache)
   - Enable SSL/TLS certificates

4. **Restrict Access**
   - Bind to specific IP: `dashboard.host: "127.0.0.1"`
   - Use firewall rules to limit access

5. **Regular Updates**
   - Keep dependencies updated: `pip install --upgrade -r requirements.txt`
   - Monitor security advisories

## 📁 Project Structure

```
python_project/
├── app.py                      # Flask web application
├── Integration.py              # Main IDS orchestrator
├── PacketCapture.py            # Packet sniffing
├── DetectionEngine.py          # Threat detection logic
├── ThreatIntelligence.py       # AbuseIPDB integration
├── AlertSystem.py              # Alert generation
├── NotificationService.py      # Multi-channel notifications
├── ConfigManager.py            # Configuration loader
├── permissions.py              # RBAC implementation
├── database/
│   ├── models.py              # SQLAlchemy models
│   └── db_manager.py          # Database operations
├── templates/
│   ├── index.html             # Main dashboard
│   ├── login.html             # Login page
│   └── user_management.html   # User admin
├── config.yaml                # Main configuration
├── requirements.txt           # Python dependencies
├── migrate_threat_intel.py    # Database migration
└── README.md                  # This file
```

## 🐛 Troubleshooting

### Dashboard Issues

**"Session expired" warnings**
- Ensure Flask app has been restarted after configuration changes
- Check that `.secret_key` file exists

**Login failures**  
- Verify default credentials: `admin` / `admin123`
- Check database exists: `ls ids_alerts.db`

### Detection Issues

**"Permission denied" errors**
- IDS requires root: Use `sudo python3 Integration.py`
- Or use: `sudo ./start_ids.sh`

**No alerts appearing**
- Verify correct network interface in `config.yaml`
- Check IDS console for errors
- Ensure dashboard is running
- Verify you're logged into the web interface

**"Interface not found" error**
- List interfaces: `ip addr show`
- Update `config.yaml` with correct interface name

### Network Interface Detection
```bash
# Find your active interface
ip addr show | grep -E '^[0-9]+:'

# Test if interface is up
ip link show eth0  # replace with your interface
```

## 📖 Documentation

- **[QUICKSTART.md](QUICKSTART.md)**: Step-by-step getting started guide
- **[THREAT_INTELLIGENCE.md](THREAT_INTELLIGENCE.md)**: AbuseIPDB setup and configuration
- **[DDOS_SIMULATION.md](DDOS_SIMULATION.md)**: Testing DDoS detection

## 🤝 Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs and feature requests.

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## ⚠️ Disclaimer

This IDS is designed for educational and testing purposes. For production cybersecurity infrastructure, consider enterprise-grade solutions like:
- Snort
- Suricata  
- Zeek (formerly Bro)
- Commercial SIEM platforms

## 👤 Author

**dhia-03**
- GitHub: [@dhia-03](https://github.com/dhia-03)

## 🙏 Acknowledgments

- **Scapy** for packet manipulation
- **Flask** for web framework
- **AbuseIPDB** for threat intelligence
- **SQLAlchemy** for ORM
- **Chart.js** for data visualization

---

**Built with ❤️ for network security education**
