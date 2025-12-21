import unittest
import os
import time
from database.db_manager import db
from database.models import Alert
from DetectionEngine import DetectionEngine
from ConfigManager import config

class TestIDSIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Use a test database
        config._config['database']['path'] = 'test_ids.db'
        db._init_db() # Re-init with test path
        
        # Adjust thresholds for testing
        config._config['detection']['port_scan_threshold'] = 2
        config._config['detection']['syn_flood_threshold'] = 5
        config._config['detection']['ddos_threshold'] = 5

    def setUp(self):
        # Clear database before each test
        session = db.get_session()
        session.query(Alert).delete()
        session.commit()
        session.close()
        
        self.engine = DetectionEngine()

    def test_database_persistence(self):
        """Verify alerts are saved to SQLite"""
        alert_data = {
            'type': 'test_threat',
            'rule': 'test_rule',
            'confidence': 0.95,
            'details': {}
        }
        packet_info = {'src_ip': '1.2.3.4', 'dst_ip': '5.6.7.8'}
        
        # Simulate what AlertSystem does (minus the network calls)
        from AlertSystem import AlertSystem
        alerter = AlertSystem()
        # Mock requests to avoid network calls
        import requests
        original_post = requests.post
        requests.post = lambda *args, **kwargs: type('obj', (object,), {'status_code': 200})
        
        alerter.generate_alert(alert_data, packet_info)
        
        # Check DB
        session = db.get_session()
        count = session.query(Alert).count()
        saved_alert = session.query(Alert).first()
        
        self.assertEqual(count, 1)
        self.assertEqual(saved_alert.source_ip, '1.2.3.4')
        self.assertEqual(saved_alert.severity, 'critical') # >0.8 confidence
        
        session.close()
        requests.post = original_post

    def test_syn_flood_detection(self):
        """Test SYN flood logic"""
        features = {
            'protocol': 'TCP',
            'tcp_flags': 'S',
            'dst_ip': '192.168.1.50'
        }
        
        # Send packets below threshold
        for _ in range(5):
            threats = self.engine.detect_threats(features)
            self.assertEqual(len(threats), 0)
            
        # Send trigger packet
        threats = self.engine.detect_threats(features)
        self.assertTrue(len(threats) > 0)
        self.assertEqual(threats[0]['rule'], 'syn_flood')

    @classmethod
    def tearDownClass(cls):
        # Clean up test DB
        if os.path.exists('test_ids.db'):
            os.remove('test_ids.db')

if __name__ == '__main__':
    unittest.main()
