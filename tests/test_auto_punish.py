"""First-connection punishment, exclusions, persistence and explicit toggle saves."""
import json
import os
from pathlib import Path
import time
import threading
import unittest
from unittest.mock import Mock, patch

import test_optimization as optimization

app, MAC, SECOND = optimization.app, optimization.MAC, optimization.SECOND
THIRD = '02:00:00:00:00:97'


class AutoPunishTests(unittest.TestCase):
    setUpBase = optimization.OptimizationTests.setUp
    patch = optimization.OptimizationTests.patch
    state = optimization.OptimizationTests.state

    def setUp(self):
        self.setUpBase()
        self.patch('_client_tc_interface', Mock(side_effect=lambda c: c.get('interface', 'br-lan')))
        self.patch('_client_mode', Mock(side_effect=lambda c, *args: c.get('mode', 'auto_auth')))
        self.patch('_infrastructure_client_ips', Mock(return_value={'192.168.1.1', '192.168.1.198'}))
        self.clients = [self.client_record(MAC)]
        self.patch('_live_clients_for_control', Mock(side_effect=lambda: self.clients))
        self.refresh = self.patch('_refresh_punishment', Mock(return_value=(True, '')))
        self.patch('_trusted_macs', Mock(return_value=set()))

    def client_record(self, mac, **values):
        return {'mac': mac, 'ip': '192.168.1.99', 'state': 'Authenticated',
                'last_active': int(time.time()), **values}

    def toggle(self, enabled):
        return self.client.put('/api/punishment', headers=self.headers, json={'auto_punish_new': enabled})

    def control(self, clients=None, blocked=None, trusted=None):
        return app._auto_punish_connections(self.clients if clients is None else clients,
                                            blocked or set(), trusted or set())

    def test_default_off_and_read_only_get(self):
        response = self.client.get('/api/punishment', headers=self.headers).get_json()
        self.assertFalse(response['auto_punish_new'])
        self.assertFalse(Path(app.PUNISH_FILE).exists())
        self.assertEqual(self.commands, [])

    def test_enabling_seeds_current_users_without_applying_or_changing_policy(self):
        before = app._load_punishment_policy()
        response = self.toggle(True)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.get_json()['auto_punish_new'])
        saved = app._load_punishment_policy()
        self.assertEqual(saved['auto_seen'], [MAC])
        for key in ('delay_ms', 'loss_pct', 'download', 'upload', 'punished'):
            self.assertEqual(saved[key], before[key])
        self.refresh.assert_not_called()
        self.assertEqual(self.commands, [])

    def test_toggle_baseline_waits_for_inflight_connection_control(self):
        baseline_read, started = threading.Event(), threading.Event()
        self.patch('_live_clients_for_control', Mock(side_effect=lambda:
                   (baseline_read.set(), self.clients)[1]))
        result = []
        def toggle():
            started.set()
            result.append(self.toggle(True).status_code)
        with app._auth_control_lock:
            worker = threading.Thread(target=toggle)
            worker.start()
            self.assertTrue(started.wait(1))
            self.assertFalse(baseline_read.wait(.05))
        worker.join(2)
        self.assertFalse(worker.is_alive())
        self.assertEqual(result, [200])
        self.assertTrue(baseline_read.is_set())

    def test_new_connections_on_both_lans_are_punished_before_queue_reconcile(self):
        self.toggle(True)
        self.clients += [self.client_record(SECOND), self.client_record(THIRD, interface='eth2')]
        reconcile = self.patch('_reconcile_punishment', Mock(return_value=(True, '')))
        app._control_once()
        self.assertEqual(reconcile.call_args.args[0]['punished'], sorted([SECOND, THIRD]))
        self.assertNotIn(MAC, app._load_punishment_policy()['punished'])
        self.assertEqual(self.commands, [])

    def test_off_stops_future_additions_and_preserves_existing_punishments(self):
        self.toggle(True)
        self.clients.append(self.client_record(SECOND))
        self.control()
        self.toggle(False)
        self.clients.append(self.client_record(THIRD))
        self.assertEqual(self.control()['punished'], [SECOND])

    def test_previously_seen_offline_device_is_never_a_first_connection(self):
        self.state('SEEN_FILE', {SECOND: {'mac': SECOND, 'last_seen': 1}})
        self.toggle(True)
        self.clients.append(self.client_record(SECOND))
        self.assertEqual(self.control()['punished'], [])

    def test_devices_observed_while_off_stay_known_after_enabling_and_reconnect(self):
        self.control()
        self.clients.append(self.client_record(SECOND))
        self.control()
        self.clients = self.clients[:1]
        self.control()
        self.toggle(True)
        self.clients.append(self.client_record(SECOND))
        self.assertEqual(self.control()['punished'], [])

    def test_history_written_by_collector_does_not_hide_a_new_device(self):
        self.toggle(True)
        # Collection records history before the controller sees this sample.
        self.state('SEEN_FILE', {SECOND: {'mac': SECOND, 'last_seen': int(time.time())}})
        self.clients.append(self.client_record(SECOND))
        self.assertEqual(self.control()['punished'], [SECOND])

    def test_off_on_cycle_never_forgets_unpunished_device(self):
        self.toggle(True)
        self.clients.append(self.client_record(SECOND))
        self.control()
        self.client.post('/api/action', headers=self.headers, json={'action': 'unpunish', 'mac': SECOND})
        self.toggle(False)
        self.clients = self.clients[:1]
        self.control()
        self.toggle(True)
        self.clients.append(self.client_record(SECOND))
        self.assertEqual(self.control()['punished'], [])

    def test_legacy_online_and_deleted_history_seed_first_time_memory(self):
        self.state('PUNISH_FILE', {'auto_punish_new': True, 'auto_online': [SECOND]})
        self.state('DELETED_FILE', [THIRD])
        self.control()
        self.clients += [self.client_record(SECOND), self.client_record(THIRD)]
        policy = self.control()
        self.assertEqual(policy['punished'], [])
        self.assertEqual(policy['auto_seen'], sorted([MAC, SECOND, THIRD]))
        self.assertNotIn('auto_online', json.loads(Path(app.PUNISH_FILE).read_text()))

    def test_restart_with_offline_known_device_does_not_make_it_new(self):
        self.toggle(True)
        self.clients.append(self.client_record(SECOND))
        self.control()
        self.client.post('/api/action', headers=self.headers, json={'action': 'unpunish', 'mac': SECOND})
        self.control(self.clients[:1])
        self.assertIn(SECOND, app._load_punishment_policy()['auto_seen'])
        self.assertEqual(self.control()['punished'], [])

    def test_unpunish_is_permanent_across_disconnect_and_reconnect(self):
        self.toggle(True)
        self.clients.append(self.client_record(SECOND))
        self.control()
        result = self.client.post('/api/action', headers=self.headers, json={'action': 'unpunish', 'mac': SECOND})
        self.assertEqual(result.status_code, 200)
        self.assertNotIn(SECOND, self.control()['punished'])
        self.control(self.clients[:1])
        self.assertNotIn(SECOND, self.control()['punished'])

    def test_unpunish_before_first_control_is_not_undone(self):
        self.toggle(True)
        self.clients.append(self.client_record(SECOND))
        self.client.post('/api/action', headers=self.headers, json={'action': 'unpunish', 'mac': SECOND})
        self.assertNotIn(SECOND, self.control()['punished'])

    def test_repeat_enabling_does_not_reset_pending_connection_detection(self):
        self.toggle(True)
        self.clients.append(self.client_record(SECOND))
        self.toggle(True)
        self.assertIn(SECOND, self.control()['punished'])

    def test_saved_known_set_survives_restart_and_does_not_repunish_existing_user(self):
        self.toggle(True)
        self.assertEqual(app._load_punishment_policy()['auto_seen'], [MAC])
        self.assertEqual(self.control()['punished'], [])
        before = Path(app.PUNISH_FILE).read_bytes()
        self.control()
        self.assertEqual(Path(app.PUNISH_FILE).read_bytes(), before)

    def test_unavailable_initial_snapshot_seeds_first_fresh_sample(self):
        app._live_clients_for_control.side_effect = lambda: None
        self.toggle(True)
        self.assertIsNone(app._load_punishment_policy()['auto_seen'])
        self.assertEqual(self.control()['punished'], [])
        self.clients.append(self.client_record(SECOND))
        self.assertEqual(self.control()['punished'], [SECOND])

    def test_stale_snapshot_cannot_turn_existing_users_into_new_connections(self):
        self.toggle(True)
        before = app._load_punishment_policy()
        app._live_clients_for_control.side_effect = lambda: None
        app._control_once()
        self.assertEqual(app._load_punishment_policy(), before)

    def test_excludes_trusted_blocked_infrastructure_unmanaged_ipv6_and_offline(self):
        self.toggle(True)
        variants = [
            {'ip': '192.168.1.1'}, {'ip': '192.168.1.198'}, {'interface': ''},
            {'ip': '::1'}, {'ip': 'invalid'}, {'state': 'Offline'},
            {'last_active': int(time.time()) - app.ONLINE_SECS - 1}, {'mode': 'auto_trust'}]
        for values in variants:
            self.assertEqual(self.control([self.client_record(SECOND, **values)])['punished'], [])
        self.assertEqual(self.control([self.client_record(SECOND)], trusted={SECOND})['punished'], [])
        self.assertEqual(self.control([self.client_record(THIRD)], blocked={THIRD})['punished'], [])

    def test_preauthenticated_new_connection_uses_policy_without_forcing_login(self):
        self.toggle(True)
        self.clients.append(self.client_record(SECOND, state='Preauthenticated', mode='portal'))
        reconcile = self.patch('_reconcile_punishment', Mock(return_value=(True, '')))
        app._control_once()
        self.assertIn(SECOND, reconcile.call_args.args[0]['punished'])
        self.assertEqual(self.commands, [])

    def test_invalid_flags_cannot_change_policy(self):
        before = app._load_punishment_policy()
        for value in ('true', 1, None, [], {}):
            self.assertEqual(self.toggle(value).status_code, 400)
        self.assertEqual(app._load_punishment_policy(), before)

    def test_saving_rate_fields_retains_toggle_and_detection_baseline(self):
        self.toggle(True)
        result = self.client.put('/api/punishment', headers=self.headers, json={'delay_ms': 200})
        self.assertTrue(result.get_json()['ok'])
        policy = app._load_punishment_policy()
        self.assertTrue(policy['auto_punish_new'])
        self.assertEqual(policy['auto_seen'], [MAC])
        self.assertEqual(policy['delay_ms'], 200)

    def test_failed_manual_action_does_not_erase_concurrent_auto_punishment(self):
        self.toggle(True)
        def fail(*args):
            policy = app._load_punishment_policy()
            policy['punished'] = sorted(set(policy['punished']) | {THIRD})
            app._save_punishment_policy(policy)
            return False, 'Synthetic queue failure'
        self.refresh.side_effect = fail
        result = self.client.post('/api/action', headers=self.headers, json={'action': 'punish', 'mac': SECOND})
        self.assertEqual(result.status_code, 502)
        self.assertEqual(app._load_punishment_policy()['punished'], [THIRD])
        self.assertTrue(app._load_punishment_policy()['auto_punish_new'])

    def test_legacy_latency_policy_never_automatically_enables_new_feature(self):
        legacy = Path(self.tmp.name) / 'legacy.json'
        legacy.write_text(json.dumps({'auto_punish_new': True, 'threshold_ms': 200}))
        with patch.dict(os.environ, {'LATENCY_FILE': str(legacy)}):
            policy = app._load_punishment_policy()
        self.assertFalse(policy['auto_punish_new'])
        self.assertEqual(policy['delay_ms'], 200)
