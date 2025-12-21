# Network Intrusion Detection System (IDS)

A real-time network intrusion detection system with live web dashboard visualization.

## 🚀 Features

- **Real-time packet capture** using Scapy
- **Threat detection** with signature-based rules
- **Live web dashboard** with WebSocket updates
- **Port scan detection** with configurable thresholds
- **Alert logging** and visualization
- **Modern dark-themed UI** with real-time charts

## 📋 Requirements

- Python 3.8+
- Root/sudo privileges (required for packet capture)
- Linux environment recommended

## 🛠️ Installation

1. Clone the repository:
```bash
git clone git@github.com:dhia-03/pythin_project.git
cd pythin_project
```

2. Create and activate virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## 🎯 Usage

### Start the Dashboard
```bash
python app.py
```
The dashboard will be available at `http://localhost:5000`

### Run the IDS (requires root)
```bash
sudo python Integration.py
```

### Run Tests
```bash
python test_ids_mock.py
```

## 🏗️ Architecture

- **PacketCapture.py** - Network packet sniffing using Scapy
- **TrafficAnalyzer.py** - Packet feature extraction
- **DetectionEngine.py** - Threat detection logic
- **AlertSystem.py** - Alert generation and logging
- **Integration.py** - Main orchestrator
- **app.py** - Flask web dashboard with SocketIO

## ⚙️ Configuration

Edit the following in the source files:
- Network interface: `Integration.py` (default: `eth0`)
- Dashboard URL: `AlertSystem.py` and `Integration.py`
- Detection thresholds: `DetectionEngine.py`

## 📊 Current Detection Capabilities

- ✅ Port scan detection
- 🔄 SYN flood detection (in test phase)
- 🔜 Anomaly-based detection (planned)

## 🔒 Security Notes

⚠️ This is an educational/prototype project. For production use:
- Add authentication to the dashboard
- Implement HTTPS
- Use environment variables for configuration
- Increase detection thresholds
- Add rate limiting

## 📝 License

MIT License

## 👤 Author

dhia-03
