import os
import yaml
import logging
from typing import Any, Dict

# Default configuration
DEFAULT_CONFIG = {
    'network': {
        'interface': 'eth0'
    },
    'dashboard': {
        'host': '0.0.0.0',
        'port': 5000,
        'url': 'http://localhost:5000/api/alert'
    },
    'database': {
        'path': 'ids_alerts.db'
    },
    'detection': {
        'port_scan_threshold': 10,
        'syn_flood_threshold': 100,
        'ddos_threshold': 100,
        'brute_force_threshold': 5
    },
    'notifications': {
        'email': {
            'enabled': False,
            'smtp_server': '',
            'smtp_port': 587,
            'sender': '',
            'password': '',
            'recipients': []
        },
        'slack': {
            'enabled': False,
            'webhook_url': ''
        },
        'discord': {
            'enabled': False,
            'webhook_url': ''
        }
    },
    'geolocation': {
        'enabled': True,
        'cache_size': 1000
    }
}

class ConfigManager:
    _instance = None
    _config: Dict[str, Any] = {}

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(ConfigManager, cls).__new__(cls)
            cls._instance._load_config()
        return cls._instance

    def _load_config(self):
        """Load configuration from config.yaml and environment variables"""
        self._config = DEFAULT_CONFIG.copy()
        
        # Load from file
        config_path = os.path.join(os.path.dirname(__file__), 'config.yaml')
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    file_config = yaml.safe_load(f)
                    if file_config:
                        self._deep_update(self._config, file_config)
            except Exception as e:
                print(f"[!] Error loading config.yaml: {e}")

        # Override with environment variables
        self._load_env_overrides()

    def _deep_update(self, base_dict, update_dict):
        """Recursively update dictionary"""
        for key, value in update_dict.items():
            if isinstance(value, dict) and key in base_dict and isinstance(base_dict[key], dict):
                self._deep_update(base_dict[key], value)
            else:
                base_dict[key] = value

    def _load_env_overrides(self):
        """Override specific settings with environment variables"""
        if os.getenv('IDS_INTERFACE'):
            self._config['network']['interface'] = os.getenv('IDS_INTERFACE')
        
        if os.getenv('DASHBOARD_URL'):
            self._config['dashboard']['url'] = os.getenv('DASHBOARD_URL')
            
        if os.getenv('DB_PATH'):
            self._config['database']['path'] = os.getenv('DB_PATH')

    def get(self, path: str, default=None):
        """Get config value using dot notation (e.g. 'network.interface')"""
        keys = path.split('.')
        value = self._config
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default
        return value

# Global instance
config = ConfigManager()
