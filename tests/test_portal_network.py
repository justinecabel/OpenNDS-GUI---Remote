"""Mixed portal/auto-login regressions. All router operations are mocked."""
import base64
import ipaddress
import json
import unittest
from unittest.mock import Mock
import test_optimization as optimization

app, MAC, SECOND = optimization.app, optimization.MAC, optimization.SECOND


class PortalNetworkTests(unittest.TestCase):
    setUp = optimization.OptimizationTests.setUp
    patch = optimization.OptimizationTests.patch
    state = optimization.OptimizationTests.state
    control = optimization.OptimizationTests.control

    def networks(self):
        self.patch('PORTAL_SUBNETS', (ipaddress.IPv4Network('10.0.0.0/24'),))

    def test_auto_auth_only_authenticates_primary_lan(self):
        self.networks()
        lan = self.control('Preauthenticated')
        piso = dict(lan, mac=SECOND, ip='10.0.0.100')
        app._clients_cache_data['_live_clients'][SECOND] = piso
        auth = self.patch('_ndsctl_auth_with_limits', Mock(return_value=(0, 'authenticated')))
        app._control_once()
        self.assertEqual([call.args[0] for call in auth.call_args_list], [MAC])
        self.assertEqual(app._load_mode()['auto_authed'], [MAC])

    def test_auto_trust_never_trusts_portal_subnet(self):
        self.networks()
        lan = self.control('Preauthenticated', 'auto_trust')
        app._clients_cache_data['_live_clients'][SECOND] = dict(lan, mac=SECOND, ip='10.0.0.100')
        nds = self.patch('ndsctl', Mock(return_value=(0, 'trusted')))
        app._control_once()
        self.assertEqual([call.args[0] for call in nds.call_args_list], ['trust ' + MAC])

    def test_portal_fas_does_not_redirect_to_auto_auth(self):
        self.networks()
        self.state('MODE_FILE', {'mode': 'auto_auth'})
        self.patch('_read_hosted_index', lambda: '<body>{{CONNECTED}}{{CONTINUE_FORM}}</body>')
        for ip, expected in [('10.0.0.100', 200), ('192.168.1.100', 302)]:
            encoded = base64.b64encode(('hid=test-hid, clientip=' + ip +
                ', clientmac=' + MAC + ', gatewayaddress=192.168.1.1:2050').encode()).decode()
            response = self.client.get('/fas', query_string={'fas': encoded})
            self.assertEqual(response.status_code, expected)
            if expected == 200:
                self.assertIn(b'<body>0<form', response.data)

    def test_portal_continue_applies_limits_after_verification(self):
        self.networks()
        self.state('MODE_FILE', {'mode': 'auto_auth'})
        self.patch('_fas_key', lambda: 'test-key')
        self.patch('_refresh_punishment', Mock())
        self.patch('ndsctl', Mock(return_value=(0, json.dumps(
            {'mac': MAC, 'ip': '10.0.0.100', 'state': 'Preauthenticated'}).encode())))
        auth = self.patch('_ndsctl_auth_with_limits', Mock(return_value=(0, 'authenticated')))
        token = base64.b64encode(('hid=test-hid, clientip=10.0.0.100, clientmac=' + MAC +
             ', gatewayaddress=192.168.1.1:2050, originurl=http://example.com').encode()).decode()
        response = self.client.get('/fas/continue', query_string={'tok': token})
        self.assertEqual(response.status_code, 302)
        self.assertIn('/fas?landing=1', response.location)
        auth.assert_called_once()

    def test_spoofed_fas_ip_cannot_change_network_policy(self):
        self.networks()
        self.patch('_fas_key', lambda: 'test-key')
        self.patch('ndsctl', Mock(return_value=(0, json.dumps(
            {'mac': MAC, 'ip': '10.0.0.100', 'state': 'Preauthenticated'}).encode())))
        auth = self.patch('_ndsctl_auth_with_limits', Mock())
        token = base64.b64encode(('hid=test-hid, clientip=192.168.1.100, clientmac=' + MAC +
             ', gatewayaddress=192.168.1.1:2050').encode()).decode()
        self.assertEqual(self.client.get('/fas/continue', query_string={'tok': token}).status_code, 403)
        auth.assert_not_called()

    def test_portal_clients_do_not_get_primary_lan_queues(self):
        self.networks()
        policy = {'punished': [], 'download': 0, 'upload': 0, 'delay_ms': 100, 'loss_pct': '0'}
        limits = {'default': {'up': 800, 'down': 800}, 'devices': {}}
        client = {'mac': MAC, 'ip': '10.0.0.100', 'state': 'Authenticated'}
        self.assertEqual(app._managed_tc_clients([client], policy, limits, set(), set()), {})
        pending = app._session_pending(client, limits['default'], tc={'error': 'primary queue failure'})
        self.assertEqual(pending['tc_pending_message'], '')
        self.assertIn('interface unavailable', pending['tc_note'])

    def test_deauth_allowed_on_portal_subnet_with_primary_auto_auth(self):
        self.networks()
        self.state('MODE_FILE', {'mode': 'auto_auth'})
        self.patch('_cached_client', lambda mac: {'mac': mac, 'ip': '10.0.0.100'})
        nds = self.patch('ndsctl', Mock(return_value=(0, 'deauthenticated')))
        response = self.client.post('/api/action', headers=self.headers,
                                    json={'action': 'deauth', 'mac': MAC})
        self.assertEqual(response.status_code, 200)
        nds.assert_called_once_with('deauth ' + MAC)

    def test_primary_auto_trust_does_not_disable_portal_limit_updates(self):
        self.networks()
        self.control('Authenticated', 'auto_trust')['ip'] = '10.0.0.100'
        before = app._load_limits()
        after = json.loads(json.dumps(before))
        after['default']['timeout'] = 30
        self.assertEqual(app._queue_session_refresh(before, after), 1)


if __name__ == '__main__':
    unittest.main()
