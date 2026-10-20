"""Client-only Overview accounting, using real parsers and no router access."""
import copy
import time
import unittest
from unittest.mock import patch, Mock

import test_optimization as optimization

app = optimization.app
MAC, SECOND = optimization.MAC, optimization.SECOND
HOST_MAC = '02:00:00:00:00:97'


class ClientOverviewTests(unittest.TestCase):
    setUpBase = optimization.OptimizationTests.setUp
    patch = optimization.OptimizationTests.patch

    def setUp(self):
        self.setUpBase()
        self.t = int(time.time())
        self.patch('FAS_BASE_URL', 'http://192.168.1.198:8080')
        self.patch('_networks_data', {'initialized': True, 'primary_device': 'br-lan', 'networks': [
            {'name': 'lan', 'device': 'br-lan', 'role': 'LAN', 'subnets': ['192.168.1.0/24'],
             'addresses': [{'address': '192.168.1.1'}]},
            {'name': 'piso', 'device': 'eth2', 'role': 'LAN', 'subnets': ['10.0.0.0/24'],
             'addresses': [{'address': '10.0.0.1'}]},
            {'name': 'wan', 'device': 'eth0', 'role': 'WAN', 'subnets': ['192.168.122.0/24'],
             'addresses': [{'address': '192.168.122.127'}]},
        ]})
        self.inputs = {'192.168.1.99': MAC, '10.0.0.98': SECOND, '192.168.1.198': HOST_MAC}

    def flow(self, source, upload, download, destination='203.0.113.10', reply='192.168.122.127'):
        return (f'ipv4 2 tcp 6 30 ESTABLISHED src={source} dst={destination} '
                f'sport=12345 dport=443 packets=5 bytes={upload} '
                f'src={destination} dst={reply} sport=443 dport=12345 '
                f'packets=10 bytes={download} [ASSURED] mark=0 zone=0 use=2\n')

    def raw(self, at, records='', boot='12345678-abcd', rx=100000, tx=100000):
        return (f'@@SAMPLE_AT\n{at}\n@@BOOT_ID\n{boot}\n@@WAN_IPS\n192.168.122.127\n'
                f'@@WAN_COUNTERS\n{rx}\n{tx}\n@@CONNTRACK\n{records}').encode()

    def sample(self, at, records='', inputs=None, active=None, **kwargs):
        inputs = self.inputs if inputs is None else inputs
        active = set(inputs.values()) if active is None else active
        return app._wan_usage_snapshot(inputs, active, at, raw=self.raw(at, records, **kwargs))

    def overview(self, at, history=False):
        with patch.object(app.time, 'time', return_value=at):
            return app._traffic_overview(include_history=history)

    def test_client_deltas_exclude_host_router_local_and_unrelated_flows_on_both_lans(self):
        def records(step):
            return (self.flow('192.168.1.99', 1000+step*100, 1000+step*200) +
                    self.flow('10.0.0.98', 1000+step*300, 1000+step*400) +
                    self.flow('192.168.1.198', 1000+step*5000, 1000+step*6000) +
                    self.flow('192.168.122.127', 1000+step*7000, 1000+step*8000) +
                    self.flow('192.168.1.99', 1000+step*9000, 1000+step*9000,
                              destination='192.168.1.1', reply='192.168.1.99') +
                    self.flow('192.168.1.220', 1000+step*9000, 1000+step*9000))
        self.sample(self.t, records(0))
        usage = self.sample(self.t+1, records(1), rx=200000, tx=200000)
        overview = self.overview(self.t+1, history=True)
        self.assertEqual(overview['live'], {'download': 600, 'upload': 400})
        self.assertEqual(overview['today'], {'download': 600, 'upload': 400})
        self.assertEqual(overview['month'], overview['today'])
        self.assertEqual(overview['history'][-1]['download'], 600)
        # Existing device accounting is preserved, including display-hidden MACs.
        self.assertEqual(usage[HOST_MAC]['today_download'], 6000)
        self.assertEqual(usage[MAC]['download_rate']+usage[SECOND]['download_rate'], 600)
        self.assertEqual(self.commands, [])

    def test_zero_clients_stays_zero_while_wan_counters_and_router_flows_increase(self):
        self.sample(self.t, inputs={})
        self.sample(self.t+1, self.flow('192.168.122.127', 999999, 999999),
                    inputs={}, rx=999999, tx=999999)
        self.patch('_overview_clients', {'at': self.t+1, 'count': 0})
        with patch.object(app.time, 'time', return_value=self.t+1):
            response = self.client.get('/api/overview', headers=self.headers).get_json()
            history = self.client.get('/api/overview/history', headers=self.headers).get_json()
        self.assertEqual(response['connected'], 0)
        self.assertEqual(response['scope'], 'clients')
        self.assertFalse(response['stale'])
        self.assertEqual(response['live'], {'download': 0, 'upload': 0})
        self.assertEqual(response['today'], response['live'])
        self.assertTrue(all(p['download'] == p['upload'] == 0 for p in history['history']))
        self.assertEqual(self.commands, [])

    def test_only_infrastructure_or_inactive_clients_produce_zero_rates(self):
        self.sample(self.t, self.flow('192.168.1.198', 100, 100), active={HOST_MAC})
        self.sample(self.t+1, self.flow('192.168.1.198', 10000, 10000),
                    active={HOST_MAC}, rx=200000, tx=200000)
        self.assertEqual(self.overview(self.t+1)['live'], {'download': 0, 'upload': 0})
        self.sample(self.t+2, self.flow('192.168.1.99', 20000, 20000), active=set())
        self.assertEqual(self.overview(self.t+2)['today'], {'download': 0, 'upload': 0})

    def test_aggregate_uses_physically_capped_deltas(self):
        inputs = {'192.168.1.99': MAC}
        self.sample(self.t, self.flow('192.168.1.99', 100, 100), inputs=inputs, rx=100, tx=100)
        self.sample(self.t+1, self.flow('192.168.1.99', 1000, 1000), inputs=inputs, rx=150, tx=180)
        self.assertEqual(self.overview(self.t+1)['live'], {'download': 50, 'upload': 80})
        self.assertEqual(self.overview(self.t+1)['today'], {'download': 50, 'upload': 80})

    def test_failed_or_stale_collection_is_unavailable_and_recovery_rebaselines(self):
        inputs = {'192.168.1.99': MAC}
        self.sample(self.t, self.flow('192.168.1.99', 100, 100), inputs=inputs)
        self.sample(self.t+1, self.flow('192.168.1.99', 150, 150), inputs=inputs, rx=100100, tx=100100)
        for bad_inputs, raw in ((None, self.raw(self.t+2)), (inputs, b'invalid conntrack sample')):
            app._wan_usage_snapshot(bad_inputs, {MAC}, self.t+2, raw=raw)
            current = self.overview(self.t+2, history=True)
            self.assertTrue(current['stale'])
            self.assertIsNone(current['live']['download'])
            self.assertIsNone(current['history'][-1]['download'])
            self.assertEqual(current['today']['download'], 50)
        self.sample(self.t+3, self.flow('192.168.1.99', 5000, 5000), inputs=inputs, rx=200000, tx=200000)
        self.assertIsNone(self.overview(self.t+3)['live']['download'])
        self.sample(self.t+4, self.flow('192.168.1.99', 5050, 5050), inputs=inputs, rx=200100, tx=200100)
        self.assertEqual(self.overview(self.t+4)['today']['download'], 100)
        self.assertIsNone(self.overview(self.t+20)['live']['download'])

    def test_restart_keeps_client_overview_totals_and_requires_a_new_baseline(self):
        inputs = {'192.168.1.99': MAC}
        self.sample(self.t, self.flow('192.168.1.99', 100, 100), inputs=inputs)
        self.sample(self.t+1, self.flow('192.168.1.99', 150, 150), inputs=inputs, rx=100100, tx=100100)
        self.patch('WAN_USAGE_SAMPLER_ID', '1'*32)
        app._wan_usage_data = None
        self.assertIsNone(self.overview(self.t+2)['live']['download'])
        self.sample(self.t+2, self.flow('192.168.1.99', 1000, 1000), inputs=inputs, rx=200000, tx=200000)
        current = self.overview(self.t+2, history=True)
        self.assertEqual(current['tracking_since'], self.t)
        self.assertEqual(current['today']['download'], 50)
        self.assertIsNone(current['history'][-1]['download'])
        self.sample(self.t+3, self.flow('192.168.1.99', 1050, 1050), inputs=inputs, rx=200100, tx=200100)
        self.assertEqual(self.overview(self.t+3)['today']['download'], 100)

    def test_new_overview_never_imports_existing_wan_or_device_totals(self):
        raw_wan = app._wan_traffic_state()
        raw_wan['days'][app._traffic_time(self.t).strftime('%Y-%m-%d')] = {'download': 999999, 'upload': 999999}
        before = copy.deepcopy(raw_wan)
        app._save_json(app.WAN_USAGE_FILE, {'version': 2, 'devices': {
            MAC: {'today': {'download': 12345, 'upload': 12345},
                  'month': {'download': 12345, 'upload': 12345}}}})
        self.sample(self.t, inputs={})
        current = self.overview(self.t, history=True)
        self.assertEqual(current['today'], {'download': 0, 'upload': 0})
        self.assertEqual(current['tracking_since'], self.t)
        self.assertEqual(app._wan_traffic_state(), before)
        self.assertEqual(app._wan_usage_data['devices'][MAC]['today']['download'], 12345)

    def test_sampling_distinguishes_empty_snapshot_from_stale_and_collects_idle_samples(self):
        self.patch('_clients_cache_data', {'ok': True, 'sampled_at': self.t, '_live_clients': {}})
        with patch.object(app.time, 'time', return_value=self.t):
            self.assertEqual(app._wan_sampling_inputs(), ({}, set()))
        with patch.object(app.time, 'time', return_value=self.t+30):
            self.assertEqual(app._wan_sampling_inputs(), (None, set()))
        self.patch('_wan_sampling_inputs', Mock(return_value=({}, set())))
        read = self.patch('_read_traffic_counters', Mock(return_value={'at': self.t, 'flow_raw': self.raw(self.t)}))
        self.patch('_sample_traffic', Mock())
        with patch.object(app.time, 'sleep', side_effect=StopIteration):
            with self.assertRaises(StopIteration):
                app._traffic_loop()
        read.assert_called_once_with(include_flows=True, ip_to_mac={})
        self.assertEqual(self.overview(self.t)['live'], {'download': 0, 'upload': 0})

    def test_calendar_rollover_retains_previous_totals_without_charging_a_baseline(self):
        from datetime import datetime
        t = int(datetime(2026, 9, 30, 23, 59, 58, tzinfo=app.ZoneInfo('Asia/Manila')).timestamp())
        inputs = {'192.168.1.99': MAC}
        self.sample(t, self.flow('192.168.1.99', 100, 100), inputs=inputs)
        self.sample(t+1, self.flow('192.168.1.99', 150, 150), inputs=inputs, rx=100100, tx=100100)
        self.sample(t+2, self.flow('192.168.1.99', 1000, 1000), inputs=inputs, rx=200000, tx=200000)
        current = self.overview(t+2, history=True)
        self.assertEqual(current['today'], {'download': 0, 'upload': 0})
        self.assertEqual(current['month'], current['today'])
        self.assertIsNone(current['live']['download'])
        self.sample(t+3, self.flow('192.168.1.99', 1050, 1050), inputs=inputs, rx=200100, tx=200100)
        self.assertEqual(self.overview(t+3)['month']['download'], 50)
        self.assertEqual(app._wan_usage_data['overview']['months']['2026-09']['download'], 50)

    def test_history_retains_24_hours_and_supports_incremental_responses(self):
        inputs = {'192.168.1.99': MAC}
        self.sample(self.t, self.flow('192.168.1.99', 100, 100), inputs=inputs)
        self.sample(self.t+1, self.flow('192.168.1.99', 150, 150), inputs=inputs, rx=100100, tx=100100)
        with patch.object(app.time, 'time', return_value=self.t+1):
            first = self.client.get('/api/overview/history', headers=self.headers).get_json()
        self.sample(self.t+2, self.flow('192.168.1.99', 200, 200), inputs=inputs, rx=100200, tx=100200)
        with patch.object(app.time, 'time', return_value=self.t+2):
            delta = self.client.get('/api/overview/history', headers=self.headers,
                                    query_string={'since': first['cursor'], 'generation': first['generation']}).get_json()
        self.assertFalse(delta['reset'])
        self.assertEqual(delta['history'][-1]['download'], 50)
        self.sample(self.t+3602, inputs={})
        current = self.overview(self.t+3602, history=True)
        self.assertLess(current['history'][0]['at'], current['recent_start_at'])
        self.assertEqual(current['history'][-1]['download'], 0)
        self.sample(self.t+90000, inputs={})
        self.assertTrue(all(p['at'] > self.t for p in self.overview(self.t+90000, history=True)['history']))


if __name__ == '__main__':
    unittest.main()
