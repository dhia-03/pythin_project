# Threat Intelligence Setup Guide

## Overview

Your IDS now includes professional threat intelligence integration with AbuseIPDB, providing real-time IP reputation scoring for detected threats.

## Features

✅ **Automatic IP Reputation Lookup** - Every alert checks source IP against AbuseIPDB  
✅ **Abuse Confidence Scores** - 0-100% rating based on reported malicious activity  
✅ **Threat Categories** - Identifies attack types (brute force, DDoS, port scan, etc.)  
✅ **Visual Indicators** - Color-coded badges in dashboard (red/yellow/green)  
✅ **Smart Caching** - 24-hour cache to respect API rate limits  
✅ **Private IP Filtering** - Automatically skips local/private IP addresses  

## Setup Instructions

### 1. Get AbuseIPDB API Key

1. Go to https://www.abuseipdb.com/
2. Create a free account
3. Navigate to "API" section
4. Copy your API key

**Free Tier Limits**: 1,000 checks per day

### 2. Configure IDS

Edit `config.yaml`:

```yaml
threat_intelligence:
  abuseipdb:
    enabled: true  # Enable the service
    api_key: "YOUR_API_KEY_HERE"  # Paste your API key
    cache_ttl: 86400  # 24 hours (in seconds)
    confidence_threshold: 75  # Mark as threat if score >= 75%
```

### 3. Run Database Migration

```bash
python3 migrate_threat_intel.py
```

This adds reputation columns to the alerts table.

### 4. Test Configuration

```bash
python3 test_threat_intel.py
```

This will verify your API key works and show sample reputation lookups.

### 5. Restart IDS

```bash
# Stop current IDS (Ctrl+C)
# Restart with new configuration
sudo python3 Integration.py
```

## Dashboard Display

The dashboard now shows IP reputation in a new "Reputation" column:

### Reputation Badges

- **🚨 THREAT** (Red) - Abuse score ≥ 75%, known malicious IP
- **⚠️ Suspicious** (Yellow) - Abuse score 50-74%, potentially malicious
- **✓ Clean** (Green) - Abuse score < 50%, no significant reports

### Additional Information

- **Abuse Score**: Percentage (0-100%) indicating confidence of malicious activity
- **Threat Categories**: Attack types reported (DDoS, brute force, port scan, etc.)

## Example Alert with Threat Intelligence

```
┌─────────────────────────────────────────────────────────┐
│ DDoS Attack Detected                                    │
├─────────────────────────────────────────────────────────┤
│ Source IP: 192.0.2.100                                  │
│ Reputation: 🚨 THREAT                                   │
│ Abuse Score: 92%                                        │
│ Categories: DDoS Attack, Port Scan, Brute-Force         │
│ Total Reports: 147                                      │
└─────────────────────────────────────────────────────────┘
```

## Troubleshooting

### "Threat intelligence is disabled"
- Check `enabled: true` in config.yaml
- Verify API key is set

### "Rate limit reached"
- Free tier: 1,000 checks/day
- Caching reduces API calls
- Consider upgrading for higher limits

### No reputation data shown
- Check API key is valid
- Ensure internet connectivity
- Private IPs (127.x.x.x, 192.168.x.x) are automatically skipped

## Privacy & Performance

- **Private IPs**: Local/private IPs are never sent to external APIs
- **Caching**: Results cached for 24 hours to minimize API calls
- **Non-Blocking**: Reputation checks don't slow down alert processing
- **Graceful Degradation**: IDS continues working if API unavailable

## Cost

- **Free Tier**: 1,000 checks/day (sufficient for most deployments)
- **Paid Plans**: Available at abuseipdb.com/pricing for higher volume

## Support

For issues:
1. Run `python3 test_threat_intel.py` to diagnose
2. Check logs for error messages
3. Verify API key is valid at abuseipdb.com
