"""SQM snapshots remain fast, bounded and truthful while router commands wait."""
import threading
import time
import unittest
from unittest.mock import Mock
import test_optimization as optimization

app = optimization.app
READ_QUEUES = app._read_sqm_queues


class SqmCacheTests(unittest.TestCase):
    setUpBase = optimization.OptimizationTests.setUp
    patch = optimization.OptimizationTests.patch
    state = optimization.OptimizationTests.state

    def setUp(self):
        self.setUpBase()
        self.rows = [{'section': 'uplink', 'interface': 'eth0', 'enabled': '1',
                      'qdisc': 'cake', 'script': 'piece_of_cake.qos',
                      'download': '100000', 'upload': '15000'}]
        self.read = self.patch('_read_sqm_queues', Mock(side_effect=lambda: (self.rows, '')))
        self.links = self.patch('_router_interfaces', Mock(return_value=['lo', 'ifb4eth0', 'eth0', 'eth2']))
        self.patch('_networks_data', {'primary_device': 'br-lan', 'networks': []})

    def get(self, query=''):
        return self.client.get('/api/sqm' + query, headers=self.headers)

    def test_cold_cache_returns_pending_without_reading_or_default_settings(self):
        response = self.get()
        self.assertEqual(response.status_code, 202)
        data = response.get_json()
        self.assertTrue(data['pending'])
        self.assertNotIn('config', data)
        self.assertEqual(response.headers['Cache-Control'], 'no-store, max-age=0')
        self.read.assert_not_called()
        self.links.assert_not_called()

    def test_warm_get_is_detached_and_never_waits_for_router_or_settings_locks(self):
        app._refresh_sqm_cache()
        self.read.reset_mock(); self.links.reset_mock()
        ready, release = threading.Event(), threading.Event()
        def hold():
            with app._sqm_settings_lock, app._sqm_conditional_lock, app._ssh_lock:
                ready.set(); release.wait(2)
        thread = threading.Thread(target=hold)
        thread.start(); self.assertTrue(ready.wait(1))
        try:
            started = time.perf_counter()
            data = self.get().get_json()
            self.assertLess(time.perf_counter() - started, 1, "Cached GET waited for a router/settings lock")
            self.assertFalse(release.is_set())
            self.assertTrue(data['ok'])
            self.assertTrue(data['cached'])
            self.assertLess(data['age'], 1)
            self.assertEqual(data['config']['upload'], '1875')
            self.assertEqual(data['interfaces'], ['eth0', 'eth2'])
        finally:
            release.set(); thread.join(2)
        self.rows[0]['upload'] = '9000'
        self.assertEqual(self.get().get_json()['config']['upload'], '1875')
        self.read.assert_not_called(); self.links.assert_not_called()

    def test_expired_cache_hides_old_values_until_background_refresh(self):
        app._refresh_sqm_cache()
        app._sqm_cache_data['checked_at'] = time.time() - app.SQM_CACHE_MAX_AGE - 1
        self.read.reset_mock()
        response = self.get()
        self.assertEqual(response.status_code, 202)
        self.assertTrue(response.get_json()['stale'])
        self.assertNotIn('queues', response.get_json())
        self.read.assert_not_called()
        app._sqm_cache_attempted_at = 0
        app._refresh_sqm_cache()
        self.assertTrue(self.get().get_json()['ok'])

    def test_reload_forces_real_read_and_errors_never_claim_previous_values_fresh(self):
        app._refresh_sqm_cache()
        self.read.side_effect = lambda: ([], 'router disconnected')
        response = self.get('?refresh=1')
        self.assertEqual(response.status_code, 502)
        self.assertEqual(response.get_json()['output'], 'router disconnected')
        self.assertTrue(response.get_json()['stale'])
        self.assertNotIn('config', self.get().get_json())
        self.read.side_effect = lambda: (self.rows, '')
        self.assertTrue(self.get('?refresh=1').get_json()['ok'])

    def test_refresh_cadence_and_dirty_refresh_bypass_interval(self):
        app._refresh_sqm_cache(); app._refresh_sqm_cache()
        self.assertEqual(self.read.call_count, 1)
        app._invalidate_sqm_cache()
        self.assertEqual(self.get().status_code, 202)
        app._refresh_sqm_cache()
        self.assertEqual(self.read.call_count, 2)
        self.assertTrue(self.get().get_json()['ok'])

    def test_failed_refresh_is_throttled_and_timeout_is_reported(self):
        import subprocess
        self.read.side_effect = subprocess.TimeoutExpired('ssh', 15)
        app._refresh_sqm_cache(); app._refresh_sqm_cache()
        self.assertEqual(self.read.call_count, 1)
        self.assertIn('timed out', self.get().get_json()['output'])

    def test_invalidation_during_read_cannot_publish_old_generation(self):
        def raced_read():
            app._invalidate_sqm_cache()
            return self.rows, ''
        self.read.side_effect = raced_read
        app._refresh_sqm_cache()
        self.assertEqual(self.get().status_code, 202)
        self.read.side_effect = lambda: (self.rows, '')
        app._refresh_sqm_cache()
        self.assertTrue(self.get().get_json()['ok'])

    def test_daily_rates_and_baselines_are_captured_together(self):
        self.state('SQM_CONDITIONAL_FILE', {'version': 2, 'rules': {'eth0': {
            'enabled': True, 'active': True, 'placement': 'aggregate',
            'baseline': {'download': 200000, 'upload': 40000}}}})
        app._refresh_sqm_cache()
        self.state('SQM_CONDITIONAL_FILE', {'version': 2, 'rules': {}})
        data = self.get().get_json()
        self.assertEqual(data['config']['download'], '12500')
        self.assertEqual(data['baseline_config']['download'], '25000')

    def test_names_and_mode_overlay_cached_queues_without_router_reads(self):
        app._refresh_sqm_cache(); self.read.reset_mock()
        self.state('SQM_NAMES_FILE', {'eth0': 'Uplink'})
        self.state('SQM_MODE_FILE', {'mode': 'single', 'interface': 'eth0'})
        data = self.get().get_json()
        self.assertEqual(data['interface_names'], {'eth0': 'Uplink'})
        self.assertEqual(data['sqm_mode']['mode'], 'single')
        self.read.assert_not_called()

    def test_mode_save_invalidates_then_reload_reads_actual_queue_flags(self):
        app._refresh_sqm_cache()
        response = self.client.put('/api/sqm/mode', headers=self.headers, json={'mode': 'multiple'})
        self.assertTrue(response.get_json()['ok'])
        self.assertEqual(self.get().status_code, 202)
        self.rows[0]['enabled'] = '0'
        self.assertEqual(self.get('?refresh=1').get_json()['config']['enabled'], '0')

    def test_put_validates_current_router_instead_of_cached_queue(self):
        app._refresh_sqm_cache()
        self.read.side_effect = lambda: ([], 'live read failed')
        response = self.client.put('/api/sqm', headers=self.headers, json={
            'interface': 'eth0', 'enabled': False, 'download': 12500, 'upload': 1875})
        self.assertEqual(response.status_code, 502)
        self.assertEqual(response.get_json()['output'], 'live read failed')
        self.assertEqual(self.commands, [])
        self.assertEqual(self.get().status_code, 202)

    def test_existing_uci_read_populates_snapshot_without_another_queue_read(self):
        app.ssh.side_effect = None
        app.ssh.return_value = (0, b"sqm.uplink=queue\nsqm.uplink.interface='eth0'\nsqm.uplink.enabled='1'\nsqm.uplink.upload='8000'\n", '')
        queues, error = READ_QUEUES()
        self.assertFalse(error)
        app._refresh_sqm_cache()
        self.assertEqual(self.get().get_json()['config']['upload'], '1000')
        self.read.assert_not_called()
        app.ssh.assert_called_once_with('uci -q show sqm')

    def test_controller_observations_refresh_settings_without_extra_ssh(self):
        app._refresh_sqm_cache()
        self.read.reset_mock(); self.links.reset_mock()
        app._sqm_observed_data = {'queues': [{**self.rows[0], 'upload': '8000'}],
                                 'generation': app._sqm_cache_generation, 'checked_at': time.time(), 'error': ''}
        app._sqm_cache_attempted_at = 0
        app._refresh_sqm_cache()
        self.assertEqual(self.get().get_json()['config']['upload'], '1000')
        self.read.assert_not_called(); self.links.assert_not_called()

    def test_old_generation_observations_never_replace_post_save_router_read(self):
        app._sqm_observed_data = {'queues': self.rows, 'generation': 0, 'checked_at': time.time(), 'error': ''}
        app._invalidate_sqm_cache()
        self.rows = [{**self.rows[0], 'enabled': '0'}]
        app._refresh_sqm_cache()
        self.read.assert_called_once()
        self.assertEqual(self.get().get_json()['config']['enabled'], '0')

    def test_observed_read_failure_invalidates_healthy_settings_snapshot(self):
        app._refresh_sqm_cache()
        app._sqm_observed_data = {'generation': app._sqm_cache_generation, 'checked_at': time.time(),
                                 'error': 'controller router read failed'}
        app._sqm_cache_attempted_at = 0
        app._refresh_sqm_cache()
        response = self.get()
        self.assertEqual(response.status_code, 502)
        self.assertNotIn('config', response.get_json())

    def test_unauthenticated_reload_never_reads_router(self):
        self.assertEqual(self.client.get('/api/sqm?refresh=1').status_code, 401)
        self.read.assert_not_called()


if __name__ == '__main__':
    unittest.main()
