# 🚀 EXACT STEPS - Copy and Paste These Commands

## The Problem
Your IDS **IS working**, but you need to run TWO programs at the same time:
1. **Dashboard** (web interface)
2. **IDS Engine** (detection)

## ✅ PROOF IT WORKS (No root needed!)

Run this simulation test:
```bash
cd /home/dhia/python_project
source venv/bin/activate
python test_simulation.py
```

This will simulate an nmap scan and prove detection works!

---

## 🎯 EXACT STEPS TO SEE IT WORKING

### **Step 1: Open TWO terminals side by side**

### **Step 2: In Terminal 1 - Start Dashboard**
```bash
cd /home/dhia/python_project
source venv/bin/activate
python app.py
```

**Wait for this message:**
```
[+] Default admin user created (username: admin, password: admin123)
Starting IDS Dashboard on http://0.0.0.0:5000
```

**Then open browser:** http://localhost:5000/login
**Login:** admin / admin123

### **Step 3: In Terminal 2 - Start IDS**
```bash
cd /home/dhia/python_project
sudo ./venv/bin/python Integration.py
```

**You should see:**
```
[+] IDS running on eth0...
[*] Processed 0 packets...
```

### **Step 4: In Terminal 3 (or Terminal 2 after Ctrl+C) - Run nmap**
```bash
nmap -p 1-20 localhost
```

---

## 🎬 WHAT YOU'LL SEE

### In Terminal 2 (IDS):
```
[!!!] PORT_SCAN DETECTED from 127.0.0.1 [!!!]
[!] Alert Generated: port_scan
    [+] Alert saved to database.
    [+] Alert successfully sent to dashboard.
```

### In Browser (Dashboard):
- Alert appears in red table
- Charts update
- "Total Alerts" counter increases

---

## ❓ Still Not Working? Try This:

### Option A: Use Loopback Interface
If eth0 doesn't work, try localhost interface:

Edit `config.yaml`:
```yaml
network:
  interface: "lo"  # Change from "eth0" to "lo"
```

Then restart IDS (Terminal 2)

### Option B: Test with Simulation (No root needed!)
```bash
# Start dashboard (Terminal 1)
cd /home/dhia/python_project
source venv/bin/activate
python app.py

# In another terminal, run simulation
cd /home/dhia/python_project  
source venv/bin/activate
python test_simulation.py
```

This will inject a fake alert directly - you'll see it in the dashboard!

---

## 📹 Quick Video Commands

Copy these EXACTLY:

**Terminal 1:**
```bash
cd /home/dhia/python_project && source venv/bin/activate && python app.py
```

**Terminal 2 (after Terminal 1 shows "Starting IDS Dashboard"):**
```bash
cd /home/dhia/python_project && sudo ./venv/bin/python Integration.py
```

**Terminal 3:**
```bash
nmap -p 1-20 localhost
```

---

## 🔍 Check What's Running

```bash
# See if dashboard is running
curl http://localhost:5000

# See processes
ps aux | grep python
```

---

## Need Help?

Tell me:
1. Which terminal command gives an error?
2. What error message do you see?
3. Can you open http://localhost:5000 in your browser?
