import requests
import json
import os
from ConfigManager import config

class GeolocateService:
    def __init__(self):
        self.enabled = config.get('geolocation.enabled', True)
        self.cache_size = config.get('geolocation.cache_size', 1000)
        self.cache = {}
        # Simple file-based persistence for cache could be added here
    
    def get_location(self, ip_address):
        if not self.enabled or not ip_address:
            return None
            
        # Check cache first
        if ip_address in self.cache:
            return self.cache[ip_address]
            
        # Skip private IPs
        if ip_address.startswith(('192.168.', '10.', '127.', '172.16.', '172.17.', '172.18.', '172.19.', '172.2', '172.3')):
            return {
                'country': 'Local Network',
                'city': 'Internal',
                'lat': 0,
                'lon': 0,
                'isp': 'Private Network'
            }

        try:
            # Using ip-api.com (free for non-commercial use, 45 req/min)
            response = requests.get(f'http://ip-api.com/json/{ip_address}', timeout=2)
            if response.status_code == 200:
                data = response.json()
                if data['status'] == 'success':
                    location = {
                        'country': data.get('country'),
                        'city': data.get('city'),
                        'lat': data.get('lat'),
                        'lon': data.get('lon'),
                        'isp': data.get('isp')
                    }
                    self._add_to_cache(ip_address, location)
                    return location
        except Exception as e:
            print(f"[-] Geolocation error for {ip_address}: {e}")
            
        return None

    def _add_to_cache(self, ip, data):
        if len(self.cache) >= self.cache_size:
            # Remove oldest item (simple FIFO for this demo)
            # A real LRU cache would be better but requires more code
            self.cache.pop(next(iter(self.cache)))
        self.cache[ip] = data

geo_service = GeolocateService()
