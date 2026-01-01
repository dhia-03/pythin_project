# DDoS Attack Simulation Guide

## Overview

This guide shows you how to simulate a DDoS attack to test your IDS detection capabilities.

## Prerequisites

1. **IDS must be running**: Make sure the IDS is capturing traffic
   ```bash
   sudo ./start_ids.sh
   ```

2. **Dashboard must be accessible** (optional, to view alerts)

## How to Run

### Basic Usage

From the **same machine** (may have limitations):
```bash
python3 simulate_ddos.py 172.27.252.208
```

### From Another Machine (Recommended)

For more realistic testing, copy the script to another machine and run:
```bash
# Copy your IP address from the IDS machine
python3 simulate_ddos.py <YOUR_IDS_IP_ADDRESS>
```

### Custom Parameters

```bash
python3 simulate_ddos.py <target_ip> [port] [num_requests]
```

**Examples:**
```bash
# Default: 150 requests to port 80
python3 simulate_ddos.py 172.27.252.208

# Custom port
python3 simulate_ddos.py 172.27.252.208 443

# Custom number of requests
python3 simulate_ddos.py 172.27.252.208 80 200
```

## What to Expect

### Script Output
```
============================================================
          DDoS Attack Simulation
============================================================

[*] Target: 172.27.252.208:80
[*] Requests: 150
[*] Duration: 1 second(s)
[*] Rate: 150 requests/sec

[!] Starting in 3 seconds...
[!] Make sure the IDS is running to capture this traffic!

[16:40:23] Starting DDoS simulation...
[*] Progress: 25/150 packets (156 pkt/s)
[*] Progress: 50/150 packets (148 pkt/s)
...
```

### IDS Detection

The IDS should detect the attack when:
- **Threshold**: More than 100 requests/second to the same IP
- **Alert Type**: `ddos`
- **Confidence**: 90%

### IDS Terminal Output
```
[!!!] DDOS DETECTED from <source_ip> [!!!]
[!] Alert Generated: ddos
    [+] Alert saved to database.
    [+] Alert successfully sent to dashboard.
```

### Dashboard
Check the dashboard at `http://<IDS_IP>:5000` to see:
- New DDoS alert in the alerts table
- Alert details including source IP, timestamp, confidence
- Alert status: Acknowledged/Pending

## Testing Scenarios

### Scenario 1: Basic DDoS Test
```bash
# Generate 150 requests (should trigger alert)
python3 simulate_ddos.py 172.27.252.208
```
**Expected**: DDoS alert generated

### Scenario 2: Below Threshold
```bash
# Generate only 80 requests (below 100 threshold)
python3 simulate_ddos.py 172.27.252.208 80 80
```
**Expected**: No alert (below threshold)

### Scenario 3: High Volume
```bash
# Generate 500 requests (well above threshold)
python3 simulate_ddos.py 172.27.252.208 80 500
```
**Expected**: Multiple DDoS alerts

## Important Notes

> [!WARNING]
> **Same Machine Limitation**: Just like port scans, running this simulation from the same machine as the IDS may have limitations due to kernel optimizations. For best results, run from a different machine on the network.

> [!CAUTION]
> **Only use for testing**: This script is for testing your own IDS. Never use it against systems you don't own or have permission to test.

## Troubleshooting

### No Alert Generated

1. **Check IDS is running**:
   ```bash
   ps aux | grep Integration.py
   ```

2. **Check threshold**: Default is 100 requests/sec
   - Make sure you're sending more than 100 requests
   - Check `config.yaml` for `ddos_threshold`

3. **Check network interface**: Ensure IDS is monitoring the correct interface

4. **Run from different machine**: Kernel may optimize local traffic

### Too Many Alerts

If you're getting alerts from normal traffic:
- Increase the threshold in `config.yaml`
- Adjust `ddos_threshold` to a higher value (e.g., 200)

## Verification

After running the simulation:

1. **Check IDS terminal** for alert messages
2. **Check dashboard** for new alerts
3. **Query database**:
   ```bash
   sqlite3 ids_alerts.db "SELECT * FROM alerts WHERE alert_type='ddos' ORDER BY timestamp DESC LIMIT 5;"
   ```

## Next Steps

After confirming DDoS detection works:
- Test SYN flood detection with `hping3` or similar tools
- Configure notification channels (email, Slack, Discord)
- Adjust thresholds based on your network baseline
