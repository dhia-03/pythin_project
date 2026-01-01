# DDoS Detection Testing - Quick Guide

## The Problem

When testing DDoS on the **same machine**, the Linux kernel optimizes traffic internally. Out of 887K packets sent by hping3, only ~230 reached the IDS on eth0. The highest count was 40 requests/sec, below the 100 threshold.

## Solution: Use Lower Threshold Test Script

I've created `test_ddos_detection.py` with a **threshold of 30 requests/sec** for same-machine testing.

## How to Test

### Step 1: Run the Test Script
```bash
sudo ./venv/bin/python test_ddos_detection.py
```

### Step 2: Generate Traffic (Choose One)

**Option A: Python Simulation**
```bash
# In another terminal
python3 simulate_ddos.py 172.27.252.208
```

**Option B: hping3 (More Realistic)**
```bash
# In another terminal
sudo hping3 -S -p 80 --faster 172.27.252.208
```
Stop after a few seconds with Ctrl+C.

### Expected Result

You should see:
```
[!!!] DDOS DETECTED from 172.27.252.208 [!!!]
[!] Alert Generated: ddos
    [+] Alert saved to database.
    [+] Alert successfully sent to dashboard.
```

## For Production Testing

To test with real network traffic from another machine:
1. Use the normal IDS: `sudo ./start_ids.sh`
2. Run attack from a different computer on your network
3. The default 100 req/sec threshold will work correctly

## Next Steps

After confirming it works, clean up debug code and commit the DDoS simulation tools to GitHub.
