import unittest
import json
from app import app

class TestApp(unittest.TestCase):
    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True

    def test_index(self):
        response = self.app.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, b'Network Intrusion Detection System Backend')

    def test_auth_valid(self):
        response = self.app.post('/auth', data=json.dumps({
            'username': 'admin',
            'password': 'admin'
        }), content_type='application/json')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data['message'], 'Authenticated')
        self.assertEqual(data['role'], 'admin')

    def test_auth_invalid(self):
        response = self.app.post('/auth', data=json.dumps({
            'username': 'invalid',
            'password': 'invalid'
        }), content_type='application/json')
        self.assertEqual(response.status_code, 401)
        data = json.loads(response.data)
        self.assertEqual(data['message'], 'Invalid credentials')

    def test_start_capture(self):
        response = self.app.post('/start_capture', data=json.dumps({
            'duration': 10
        }), content_type='application/json')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data['message'], 'Packet capturing started.')

    def test_stop_capture(self):
        response = self.app.post('/stop_capture')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data['message'], 'Packet capturing stopped.')

    def test_network_attacks(self):
        response = self.app.get('/network_attacks')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn('mitm_packets', data)
        self.assertIn('spoofing_packets', data)
        self.assertIn('total_packets', data)

    def test_logs(self):
        response = self.app.get('/logs')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn('logs', data)

    def test_fetch_threat_intelligence(self):
        response = self.app.get('/fetch_threat_intelligence')
        self.assertIn(response.status_code, [200, 500])  # API response may vary

if __name__ == '__main__':
    unittest.main()
