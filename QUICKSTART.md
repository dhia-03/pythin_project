# IDS Detection - Quick Start Guide

## ✅ Your IDS is Working!

The diagnostic tests confirm:
- ✅ Detection engine is functional
- ✅ Port scan detection threshold: **5 unique ports**
- ✅ Database connection verified
- ✅ Alert system ready

---

## 🚀 How to Use (3 Simple Steps)

### Step 1: Start the Dashboard
Open **Terminal 1**:
```bash
cd /home/dhia/python_project
./start_dashboard.sh
```

Then open your browser to: **http://localhost:5000**
- Login with: `admin` / `admin123`
- You'll see the professional dashboard with charts and alerts table

### Step 2: Start the IDS Engine
Open **Terminal 2**:
```bash
cd /home/dhia/python_project
sudo ./start_ids.sh
```

You should see:
```
[+] IDS running on eth0...
[*] Processed 0 packets...
```

### Step 3: Run an nmap Scan
Open **Terminal 3**:
```bash
# Scan 20 ports (will trigger after 5)
nmap -p 1-20 localhost

# Or scan with SYN:
nmap -sS -p 1-50 localhost

# Or scan your local network:
nmap -p 1-100 192.168.1.1
```

---

## 🎯 What You'll See

### In Terminal 2 (IDS Console):
```
[!!!] PORT_SCAN DETECTED from 127.0.0.1 [!!!]
[!] Alert Generated: port_scan
    [+] Alert saved to database.
    [+] Alert successfully sent to dashboard.
```

### In the Web Dashboard:
- 🔴 Real-time alert appears in the alerts table
- 📊 Charts update automatically
- 💾 Alert is saved to database
- 🎨 Color-coded by severity (Critical = red)

---

## 🔧 Current Detection Settings

- **Port Scan**: Triggers after scanning **5 unique ports**
- **SYN Flood**: 100 SYN packets per second
- **DDoS**: 100 requests per second

To change these, edit `config.yaml`:
```yaml
detection:
  port_scan_threshold: 5  # Change this number
```

---

## 🐛 Troubleshooting

### "No alerts appearing in dashboard"
1. Make sure dashboard is running (Terminal 1)
2. Make sure you're logged in to the web interface
3. Check IDS console (Terminal 2) for error messages

### "Permission denied" when starting IDS
- IDS needs root access for packet capture
- Use: `sudo ./start_ids.sh`

### "Interface not found" error
- Edit `config.yaml` and change `network.interface`
- Find your interface: `ip addr show`
- Common interfaces: `eth0`, `wlan0`, `enp0s3`, `lo`

### "Not detecting nmap scans"
- Make sure you scan **more than 5 ports**
- Try: `nmap -p 1-20 localhost`
- Check the IDS is monitoring the correct interface

---

## 📊 Test the Complete System

Run the diagnostic script:
```bash
cd /home/dhia/python_project
source venv/bin/activate
python test_ids_complete.py
```

This will test all components and show you detailed diagnostics.

---

## 🎉 You're All Set!

Your IDS is now ready to:
- ✅ Detect nmap port scans in real-time
- ✅ Display alerts in the web dashboard
- ✅ Save alerts to database
- ✅ Send notifications (if configured)

**Happy monitoring!** 🛡️
