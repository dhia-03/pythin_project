# IDS Quick Start Guide

Get your Intrusion Detection System up and running in 5 minutes.

## Prerequisites Check

Before starting, ensure you have:
- ✅ Python 3.8+ installed
- ✅ Root/sudo access (for packet capture)
- ✅ Active network connection

## 🚀 Quick Setup (3 Steps)

### Step 1: Install

```bash
# Clone repository
git clone git@github.com:dhia-03/pythin_project.git
cd pythin_project

# Set up Python environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Create configuration
cp config.example.yaml config.yaml

# Run database migration
python3 migrate_threat_intel.py
```

### Step 2: Configure Network Interface

Find your network interface:
```bash
ip addr show
```

Edit `config.yaml` and set your interface:
```yaml
network:
  interface: "eth0"  # Change to match your interface
```

Common interfaces:
- **eth0**: Wired Ethernet
- **wlan0**: Wireless
- **enp0s3**: VirtualBox/VMware
- **lo**: Localhost (for testing)

### Step 3: Start the System

**Terminal 1 - Web Dashboard:**
```bash
python3 app.py
```

**Terminal 2 - IDS Engine:**
```bash
sudo python3 Integration.py
```

## 🌐 Access Dashboard

1. Open browser to: **http://localhost:5000**
2. Login with default credentials:
   - **Username**: `admin`
   - **Password**: `admin123`

You'll see the professional dashboard with real-time threat monitoring.

## 🎯 Test Detection

### Test 1: Port Scan Detection

In a **new terminal (Terminal 3)**:
```bash
# Scan 20 ports (threshold is 10 ports)
nmap -p 1-20 localhost
```

**What happens:**
- IDS Console (Terminal 2):
  ```
  [!!!] PORT_SCAN DETECTED from 127.0.0.1 [!!!]
  [!] Alert Generated: port_scan
      [+] Alert saved to database.
      [+] Alert successfully sent to dashboard.
  ```

- Dashboard (Browser):
  - 🚨 Alert appears in real-time
  - 📊 Charts update automatically
  - 🎨 Color-coded by severity

### Test 2: DDoS Detection

```bash
# Use included simulation tool
python3 simulate_ddos.py 127.0.0.1 80 200
```

Expected: Alert appears within seconds showing DDoS attack detected.

## 📊 Understanding the Dashboard

### Main Components

**1. Statistics Cards**
- Total Alerts
- Critical Threats
- System Status
- Active Rules

**2. Threat Charts**
- Threat Distribution (pie chart)
- Severity Breakdown (bar chart)

**3. Live Threat Feed**
Real-time table showing:
- Timestamp of attack
- Severity level
- Attack type (Port Scan, DDoS)
- Source IP
- **IP Reputation** (new!) - Red/Yellow/Green indicators
- Target IP
- Confidence score

**4. Filters & Export**
- Filter by IP address
- Filter by attack type
- Export alerts to CSV

### IP Reputation Indicators

- 🚨 **THREAT** (Red): Known malicious IP (abuse score ≥ 75%)
- ⚠️ **Suspicious** (Yellow): Potentially malicious (score 50-74%)
- ✅ **Clean** (Green): No significant reports (score < 50%)

## 👥 User Roles

The system has two roles:

### Admin
**Full system control:**
- ✅ View dashboard and alerts
- ✅ Export data to CSV
- ✅ Manage user accounts
- ✅ View audit logs
- ✅ System configuration

### Analyst  
**Read-only monitoring:**
- ✅ View dashboard and alerts
- ✅ Export data to CSV
- ❌ Cannot manage users
- ❌ Cannot view audit logs

**Default Accounts:**
| Username | Password | Role |
|----------|----------|------|
| admin | admin123 | Admin |
| analyst | analyst123 | Analyst |

⚠️ **Change default passwords after first login!**

## ⚙️ Configuration

### Detection Thresholds

Edit `config.yaml`:

```yaml
detection:
  port_scan_threshold: 10      # Ports to scan before alert
  ddos_threshold: 100          # Requests per second
```

**Recommended Values:**
- **Strict**: port_scan_threshold: 5
- **Normal**: port_scan_threshold: 10 (default)
- **Relaxed**: port_scan_threshold: 20

### Enable Threat Intelligence (Optional)

1. Sign up at [https://www.abuseipdb.com/](https://www.abuseipdb.com/)
2. Get your free API key (1,000 checks/day)
3. Edit `config.yaml`:

```yaml
threat_intelligence:
  abuseipdb:
    enabled: true
    api_key: "YOUR_API_KEY_HERE"
```

4. Restart the system
5. **Test it:**
   ```bash
   python3 test_threat_intel.py
   ```

Now every alert will include IP reputation data!

## 🐛 Troubleshooting

### Dashboard Won't Start

**Error: "Address already in use"**
```bash
# Find and kill process on port 5000
lsof -ti:5000 | xargs kill -9

# Restart dashboard
python3 app.py
```

### IDS Won't Start

**Error: "Permission denied"**
- You need sudo for packet capture
- Use: `sudo python3 Integration.py`

**Error: "No such device eth0"**
- Wrong interface name in config.yaml
- Run `ip addr show` to find correct name
- Common: wlan0, enp0s3, ens33

### No Alerts Appearing

**Checklist:**
1. ✅ Is the dashboard running? (Terminal 1)
2. ✅ Are you logged in to web interface?
3. ✅ Is the IDS engine running? (Terminal 2)
4. ✅ Are you scanning with enough ports? (>10 ports)
5. ✅ Is the correct network interface configured?

**Debug Commands:**
```bash
# Check if IDS is running
ps aux | grep Integration.py

# Check if dashboard is running
ps aux | grep app.py

# Verify database exists
ls -lh ids_alerts.db

# Check recent alerts
sqlite3 ids_alerts.db "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 5;"
```

### "Session Expired" Errors

**Solution:**
1. Restart the Flask app:
   ```bash
   # Stop with Ctrl+C
   python3 app.py
   ```
2. Log in again
3. Session will now persist for 24 hours

## 🧪 Advanced Testing

### Run Comprehensive Tests

```bash
# Test all components
python3 test_ids_complete.py

# Test threat intelligence
python3 test_threat_intel.py

# Test DDoS detection specifically
python3 test_ddos_detection.py
```

### Simulate Various Attacks

**Heavy Port Scan:**
```bash
nmap -p 1-1000 <target-ip>
```

**SYN Scan:**
```bash
sudo nmap -sS -p 1-100 <target-ip>
```

**Aggressive Scan:**
```bash
nmap -A -T4 <target-ip>
```

**DDoS Simulation:**
```bash
# Light (150 packets/sec)
python3 simulate_ddos.py 127.0.0.1 80 150

# Heavy (500 packets/sec)
python3 simulate_ddos.py 127.0.0.1 80 500
```

## 📁 Important Files

```
python_project/
├── app.py                    # Dashboard application
├── Integration.py            # IDS main engine
├── config.yaml              # YOUR configuration
├── ids_alerts.db            # Alert database
├── .secret_key              # Session secret (auto-generated)
└── ids_alerts.log           # System logs
```

## 🔄 Stopping the System

**Stop IDS Engine:**
```bash
# In Terminal 2, press Ctrl+C
```

**Stop Dashboard:**
```bash
# In Terminal 1, press Ctrl+C
```

## 📈 Next Steps

Once you're comfortable with the basics:

1. **Configure Notifications**
   - Set up email alerts for critical threats
   - Integration with Slack/Discord
   - See `config.example.yaml` for examples

2. **Customize Detection Rules**
   - Adjust thresholds in `config.yaml`
   - Fine-tune for your network environment

3. **User Management**
   - Create analyst accounts for team members
   - Review audit logs in admin panel
   - Set up proper access control

4. **Production Deployment**
   - Change all default passwords
   - Configure SSL/TLS
   - Set up proper database backup
   - Enable threat intelligence

## 🆘 Getting Help

**Common Issues:**
- Check `ids_alerts.log` for error messages
- Verify all dependencies: `pip list`
- Ensure correct Python version: `python3 --version`

**Additional Documentation:**
- **[README.md](README.md)**: Complete system documentation
- **[THREAT_INTELLIGENCE.md](THREAT_INTELLIGENCE.md)**: AbuseIPDB setup guide
- **[DDOS_SIMULATION.md](DDOS_SIMULATION.md)**: DDoS testing guide

## 🎉 Success Checklist

Your IDS is working if you can:
- ✅ Log into dashboard at http://localhost:5000
- ✅ See "ACTIVE" status in dashboard
- ✅ Run nmap scan and see alert appear
- ✅ Export alerts to CSV
- ✅ View alerts in database

**Congratulations! Your IDS is operational.** 🛡️

---

**Quick Reference Commands:**
```bash
# Start Dashboard
python3 app.py

# Start IDS
sudo python3 Integration.py

# Test Detection
nmap -p 1-20 localhost

# View Logs
tail -f ids_alerts.log

# Check Database
sqlite3 ids_alerts.db "SELECT COUNT(*) FROM alerts;"
```
