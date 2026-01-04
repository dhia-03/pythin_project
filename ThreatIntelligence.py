"""
Threat Intelligence Service
Integrates with AbuseIPDB to check IP reputation
"""

import requests
import time
import logging
from datetime import datetime, timedelta
from ConfigManager import config

class ThreatIntelligence:
    def __init__(self):
        self.enabled = config.get('threat_intelligence.abuseipdb.enabled', False)
        self.api_key = config.get('threat_intelligence.abuseipdb.api_key', '')
        self.cache_ttl = config.get('threat_intelligence.abuseipdb.cache_ttl', 86400)  # 24 hours
        self.confidence_threshold = config.get('threat_intelligence.abuseipdb.confidence_threshold', 75)
        
        # Cache for IP reputation lookups
        self.cache = {}  # {ip: {'data': {...}, 'timestamp': ...}}
        
        # API endpoint
        self.api_url = 'https://api.abuseipdb.com/api/v2/check'
        
        # Rate limiting
        self.last_request_time = 0
        self.min_request_interval = 0.1  # 100ms between requests
        
        logging.info(f"ThreatIntelligence initialized (enabled: {self.enabled})")
    
    def check_ip(self, ip_address):
        """
        Check IP reputation using AbuseIPDB
        
        Args:
            ip_address: IP address to check
            
        Returns:
            dict: {
                'abuse_score': int (0-100),
                'is_known_threat': bool,
                'threat_categories': list,
                'last_reported': str (ISO date),
                'total_reports': int
            }
            Or None if service disabled/unavailable
        """
        # Return None if service is disabled
        if not self.enabled or not self.api_key:
            return None
        
        # Skip private/local IPs
        if self._is_private_ip(ip_address):
            return {
                'abuse_score': 0,
                'is_known_threat': False,
                'threat_categories': [],
                'last_reported': None,
                'total_reports': 0
            }
        
        # Check cache first
        cached = self._get_from_cache(ip_address)
        if cached:
            logging.debug(f"Using cached reputation for {ip_address}")
            return cached
        
        # Query API
        try:
            result = self._query_abuseipdb(ip_address)
            if result:
                # Cache the result
                self._add_to_cache(ip_address, result)
                return result
        except Exception as e:
            logging.error(f"Error checking IP reputation: {e}")
        
        return None
    
    def _query_abuseipdb(self, ip_address):
        """Query AbuseIPDB API"""
        # Rate limiting
        now = time.time()
        time_since_last = now - self.last_request_time
        if time_since_last < self.min_request_interval:
            time.sleep(self.min_request_interval - time_since_last)
        
        headers = {
            'Accept': 'application/json',
            'Key': self.api_key
        }
        
        params = {
            'ipAddress': ip_address,
            'maxAgeInDays': 90,  # Look back 90 days
            'verbose': ''
        }
        
        try:
            response = requests.get(
                self.api_url,
                headers=headers,
                params=params,
                timeout=5
            )
            self.last_request_time = time.time()
            
            if response.status_code == 200:
                data = response.json().get('data', {})
                
                # Extract relevant information
                abuse_score = data.get('abuseConfidenceScore', 0)
                total_reports = data.get('totalReports', 0)
                last_reported = data.get('lastReportedAt', None)
                
                # Parse categories
                categories = []
                for report in data.get('reports', [])[:5]:  # Last 5 reports
                    for cat_id in report.get('categories', []):
                        cat_name = self._get_category_name(cat_id)
                        if cat_name and cat_name not in categories:
                            categories.append(cat_name)
                
                return {
                    'abuse_score': abuse_score,
                    'is_known_threat': abuse_score >= self.confidence_threshold,
                    'threat_categories': categories,
                    'last_reported': last_reported,
                    'total_reports': total_reports
                }
            elif response.status_code == 429:
                logging.warning("AbuseIPDB rate limit reached")
            else:
                logging.error(f"AbuseIPDB API error: {response.status_code}")
        
        except requests.exceptions.Timeout:
            logging.error(f"Timeout querying AbuseIPDB for {ip_address}")
        except Exception as e:
            logging.error(f"Error querying AbuseIPDB: {e}")
        
        return None
    
    def _get_category_name(self, category_id):
        """Map AbuseIPDB category IDs to names"""
        categories = {
            3: 'Fraud',
            4: 'DDoS Attack',
            5: 'FTP Brute-Force',
            9: 'Website Spam',
            10: 'Email Spam',
            11: 'Blog Spam',
            14: 'Port Scan',
            15: 'Hacking',
            18: 'Brute-Force',
            19: 'Bad Web Bot',
            20: 'Exploited Host',
            21: 'Web App Attack',
            22: 'SSH Brute-Force',
            23: 'IoT Targeted'
        }
        return categories.get(category_id)
    
    def _is_private_ip(self, ip_address):
        """Check if IP is private/local"""
        parts = ip_address.split('.')
        if len(parts) != 4:
            return True
        
        try:
            first = int(parts[0])
            second = int(parts[1])
            
            # Private ranges
            if first == 10:
                return True
            if first == 172 and 16 <= second <= 31:
                return True
            if first == 192 and second == 168:
                return True
            if first == 127:  # Loopback
                return True
            
        except ValueError:
            return True
        
        return False
    
    def _get_from_cache(self, ip_address):
        """Get IP reputation from cache if not expired"""
        if ip_address in self.cache:
            cached = self.cache[ip_address]
            age = time.time() - cached['timestamp']
            
            if age < self.cache_ttl:
                return cached['data']
            else:
                # Expired, remove from cache
                del self.cache[ip_address]
        
        return None
    
    def _add_to_cache(self, ip_address, data):
        """Add IP reputation to cache"""
        self.cache[ip_address] = {
            'data': data,
            'timestamp': time.time()
        }
        
        # Clean up old entries (keep cache size reasonable)
        if len(self.cache) > 1000:
            self._cleanup_cache()
    
    def _cleanup_cache(self):
        """Remove expired entries from cache"""
        now = time.time()
        expired = [
            ip for ip, entry in self.cache.items()
            if now - entry['timestamp'] > self.cache_ttl
        ]
        
        for ip in expired:
            del self.cache[ip]
        
        logging.info(f"Cleaned up {len(expired)} expired cache entries")

# Global instance
threat_intel = ThreatIntelligence()
