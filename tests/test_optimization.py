"""Connection-safety and accounting regressions. No router or background threads."""
import base64
import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch, Mock

BOOT = tempfile.TemporaryDirectory()
os.environ.update(HOSTED_PORTAL_DIR=BOOT.name + '/portal',
                  PORTAL_TYPE_FILE=BOOT.name + '/portal-type.json', SESSION_SECRET='test-session-secret',
                  ADMIN_USER='test', ADMIN_PASS='test')
with patch('threading.Thread.start') as startup:
    spec = importlib.util.spec_from_file_location('manager', Path(__file__).parents[1] / 'app.py')
    app = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(app)

MAC = '02:00:00:00:00:99'
SECOND = '02:00:00:00:00:98'
INTERFACES = {'download': 'br-lan', 'upload': 'ifb4br-lan'}
PROFILE = {'ip': '192.168.1.99', 'download_cap': 40000, 'upload_cap': 40000,
           'delay_ms': 0, 'loss_pct': '0', 'session_active': True}


def layout(direction='dst', client=True, filtered=True, backlog=0, rate='100Mbit'):
    text = f'''qdisc htb 1: root refcnt 2 r2q 10 default 0x10
qdisc cake 10: parent 1:10 bandwidth {rate} besteffort triple-isolate nat nowash no-ack-filter split-gso rtt 100ms raw overhead 0
 Sent 100 bytes 1 pkt (dropped 0, overlimits 0 requeues 0)
 backlog 0b 0p requeues 0
class htb 1:1 root rate {rate} ceil {rate} burst 1600b
class htb 1:10 parent 1:1 leaf 10: rate {rate} ceil {rate} burst 1600b
'''
    if client:
        text += f'''qdisc cake 100: parent 1:100 bandwidth 40Mbit besteffort triple-isolate
 backlog {backlog}b {backlog}p requeues 0
class htb 1:100 parent 1:1 leaf 100: rate 40Mbit ceil 40Mbit burst 1600b
'''
    if filtered and client:
        text += f'''filter protocol ip pref 100 u32 chain 0 fh 800::800 order 2048 key ht 800 bkt 0 flowid 1:100 not_in_hw
  match c0a80163/ffffffff at {16 if direction == 'dst' else 12}
'''
    return app._parse_tc_layout(text)


class OptimizationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        for name in ('MODE_FILE', 'LIMITS_FILE', 'APPLIED_FILE', 'SESSION_REFRESH_FILE', 'BLOCK_FILE', 'PUNISH_FILE',
                     'PUNISH_TC_FILE', 'THROTTLE_FILE', 'WAN_USAGE_FILE', 'WAN_TRAFFIC_FILE', 'TRAFFIC_FILE',
                     'CLIENT_WAN_HISTORY_FILE', 'DOMAIN_RANK_FILE', 'FAS_KEY_FILE'):
            self.patch(name, str(Path(self.tmp.name) / (name + '.json')))
        for name, value in {'_wan_usage_data': None, '_wan_usage_live': {}, '_client_wan_history_data': None,
                            '_client_wan_live_history': {}, '_traffic_data': None, '_wan_traffic_data': None,
                            '_clients_cache_data': None, '_auth_attempts': {}, '_trusted_macs_cache': set(),
                            '_domain_refresh_at': 0.0}.items():
            self.patch(name, value)
        self.commands = []
        def fake_ssh(command, data=None, timeout=15):
            self.commands.append(command)
            return 0, b'', ''
        self.patch('ssh', Mock(side_effect=fake_ssh))
        self.client = app.app.test_client()
        self.headers = {'Authorization': 'Basic ' + base64.b64encode(b'test:test').decode()}

    def patch(self, name, value):
        p = patch.object(app, name, value)
        p.start()
        self.addCleanup(p.stop)
        return value

    def state(self, filename, value):
        app._save_json(getattr(app, filename), value)

    def control(self, state='Authenticated', mode='auto_auth', sampled=None):
        now = int(time.time())
        client = {'mac': MAC, 'ip': '192.168.1.99', 'state': state, 'last_active': now,
                  'session_start': now-100, 'session_end': now+100,
                  'upload_rate_limit_threshold': '100', 'download_rate_limit_threshold': '100'}
        self.state('MODE_FILE', {'mode': mode})
        self.state('LIMITS_FILE', {'default': {'up': 40000, 'down': 40000, 'timeout': 480}})
        app._clients_cache_data = {'ok': True, 'sampled_at': sampled or now,
                                   '_collection_started_at': time.monotonic()-1,
                                   '_live_clients': {MAC: client}}
        self.patch('_reconcile_punishment', Mock(return_value=(True, 'unchanged')))
        return client

    def tc(self, desired=None, filtered=True, backlog=0):
        self.state('PUNISH_TC_FILE', {'active': True, 'interfaces': INTERFACES, 'clients': [MAC],
                   'signature': json.dumps({'clients': {MAC: PROFILE}, 'interfaces': INTERFACES})})
        layouts = {'download': layout('dst', filtered=filtered, backlog=backlog),
                   'upload': layout('src', filtered=filtered, backlog=backlog, rate='30Mbit')}
        self.patch('_punishment_interfaces', Mock(return_value=(INTERFACES, '')))
        self.patch('_inspect_managed_queues', Mock(return_value=(layouts, '')))
        if not filtered:
            self.state('PUNISH_TC_FILE', {**app._punishment_tc_state(),
                       'bindings': {MAC: {'minor': '100', 'priority': 100}}})
        return layouts

    def assert_safe(self):
        joined = '\n'.join(self.commands)
        for forbidden in ('deauth ', 'qdisc replace', '/etc/init.d/', 'network restart', 'firewall restart'):
            self.assertNotIn(forbidden, joined)
        self.assertNotRegex(joined, r'tc qdisc delete .*\broot\b')

    def test_overuse_policy_skips_device_overrides_including_inherited_rates(self):
        limits = {'default': {'up': 8000, 'down': 16000,
                             'throttle': {'trigger_secs': 3, 'final_rate': 800, 'reset_secs': 30}},
                  'devices': {MAC: {'latency_ms': 10}}}
        clients = [{'mac': mac, 'ip': ip, 'state': 'Authenticated'}
                   for mac, ip in ((MAC, '192.168.1.99'), (SECOND, '192.168.1.98'))]
        self.patch('_live_wan_usage', Mock(return_value={
            mac: {'download_rate': 2000000, 'upload_rate': 1000000}
            for mac in (MAC, SECOND)}))
        with patch.object(app.time, 'time', return_value=100):
            self.assertEqual(app._throttle_rate_caps(clients, limits), {})
        with patch.object(app.time, 'time', return_value=104):
            caps = app._throttle_rate_caps(clients, limits)
        self.assertEqual(caps, {SECOND: {'download': 800, 'upload': 800}})
        self.assertNotIn(MAC, app._load_json(app.THROTTLE_FILE, {})['clients'])
        self.assertFalse(app._throttle_status(MAC, limits)['download'])
        self.assertTrue(app._throttle_status(SECOND, limits)['download'])
        policy = {'punished': [], 'download': 0, 'upload': 0, 'delay_ms': 100, 'loss_pct': '0'}
        desired = app._managed_tc_clients(clients, policy, limits, set(), set(), caps)
        self.assertEqual(desired[MAC]['download_cap'], 16000)
        self.assertEqual(desired[MAC]['upload_cap'], 8000)
        self.assertEqual(desired[SECOND]['download_cap'], 800)

    def test_saving_override_clears_active_overuse_and_clearing_restarts_trigger(self):
        limits = {'default': {'down': 8000,
                             'throttle': {'trigger_secs': 3, 'final_rate': 800, 'reset_secs': 30}},
                  'devices': {}}
        clients = [{'mac': MAC, 'state': 'Authenticated'}]
        self.patch('_live_wan_usage', Mock(return_value={MAC: {'download_rate': 1000000}}))
        with patch.object(app.time, 'time', return_value=100):
            app._throttle_rate_caps(clients, limits)
        with patch.object(app.time, 'time', return_value=104):
            self.assertEqual(app._throttle_rate_caps(clients, limits), {MAC: {'download': 800}})
        self.state('LIMITS_FILE', limits)
        response = self.client.put('/api/limits', headers=self.headers,
                                   json={'mac': MAC, 'limits': {'down': 2000}})
        self.assertEqual(response.status_code, 200)
        limits = app._load_limits()
        self.assertFalse(app._throttle_status(MAC, limits)['download'])
        with patch.object(app.time, 'time', return_value=108):
            self.assertEqual(app._throttle_rate_caps(clients, limits), {})
        self.assertNotIn(MAC, app._load_json(app.THROTTLE_FILE, {})['clients'])
        response = self.client.put('/api/limits', headers=self.headers,
                                   json={'mac': MAC, 'clear': True, 'limits': {}})
        self.assertEqual(response.status_code, 200)
        limits = app._load_limits()
        with patch.object(app.time, 'time', return_value=112):
            self.assertEqual(app._throttle_rate_caps(clients, limits), {})
        with patch.object(app.time, 'time', return_value=116):
            self.assertEqual(app._throttle_rate_caps(clients, limits), {MAC: {'download': 800}})
        self.assertEqual(self.commands, [])

    def test_existing_session_and_missing_applied_state_are_preserved(self):
        c = self.control()
        app._control_once()
        self.assert_safe()
        self.assertEqual(self.commands, [])
        self.assertTrue(app._session_pending(c, {'up': 40000, 'timeout': 480})['limits_pending'])

    def save_session_limits(self, mac=MAC, values=None):
        values = values if values is not None else {'timeout': 240, 'up': 6250, 'down': 12500}
        response = self.client.put('/api/limits', headers=self.headers,
                                   json={'mac': mac, 'limits': values})
        self.assertEqual(response.status_code, 200)
        return response.get_json()

    def fresh_control_sample(self):
        app._clients_cache_data['_collection_started_at'] = time.monotonic() + 1
        app._clients_cache_data['sampled_at'] += 1

    def test_saved_limits_logout_and_login_only_affected_client_once(self):
        c = self.control(mode='portal')
        app._clients_cache_data['_live_clients'][SECOND] = {**c, 'mac': SECOND}
        self.assertEqual(self.save_session_limits()['sessions_refreshing'], 1)
        self.assertEqual(app._load_session_refresh(), {MAC: {'stage': 'logout', 'session_start': str(app._clients_cache_data['_live_clients'][MAC]['session_start'])}})
        self.assertTrue(app._session_pending(c, app._effective(MAC, app._load_limits()))['limits_refreshing'])
        self.patch('ndsctl', Mock(side_effect=[(0, 'Deauthenticated.'), (0, 'Client authenticated.')]))
        app._control_once(); app._control_once()
        self.assertEqual(app.ndsctl.call_count, 2)
        self.assertEqual(app.ndsctl.call_args_list[0].args, ('deauth ' + MAC,))
        self.assertIn('auth ' + MAC + ' 240 50000 100000', app.ndsctl.call_args_list[1].args[0])
        self.assertEqual(app._load_session_refresh(), {})
        self.assertEqual(app._load_json(app.APPLIED_FILE, {})[MAC], '240|50000|100000||')
        self.assertEqual(app._load_mode()['auto_authed'], [])
        self.fresh_control_sample()
        app._control_once()
        self.assertEqual(app.ndsctl.call_count, 2)

    def test_failed_limits_login_retries_in_portal_mode_after_fresh_sample(self):
        c = self.control(mode='portal')
        self.save_session_limits()
        self.patch('ndsctl', Mock(side_effect=[(0, 'Deauthenticated.'), (1, 'busy'),
                                               (1, 'busy'), (0, 'Client authenticated.')]))
        app._control_once(); app._control_once()
        self.assertEqual(app.ndsctl.call_count, 2)
        self.assertEqual(app._load_session_refresh(), {MAC: {'stage': 'login', 'session_start': str(app._clients_cache_data['_live_clients'][MAC]['session_start'])}})
        c['state'] = 'Preauthenticated'
        self.fresh_control_sample()
        app._control_once(); app._control_once()
        self.assertEqual(app.ndsctl.call_count, 3)
        # Pending retry remains durable even if the manager process restarts.
        app._auth_attempts = {}
        self.fresh_control_sample()
        app._control_once()
        self.assertEqual(app.ndsctl.call_count, 4)
        self.assertEqual(sum(call.args[0].startswith('deauth ') for call in app.ndsctl.call_args_list), 1)
        self.assertEqual(app._load_session_refresh(), {})

    def test_failed_limits_logout_does_not_login_or_repeat_from_old_sample(self):
        self.control()
        self.save_session_limits()
        self.patch('ndsctl', Mock(side_effect=[(1, 'busy'), (0, 'Deauthenticated.'),
                                               (0, 'Client authenticated.')]))
        app._control_once(); app._control_once()
        self.assertEqual(app.ndsctl.call_count, 1)
        self.assertEqual(app._load_session_refresh(), {MAC: {'stage': 'logout', 'session_start': str(app._clients_cache_data['_live_clients'][MAC]['session_start'])}})
        self.fresh_control_sample()
        app._control_once()
        self.assertEqual(app.ndsctl.call_count, 3)
        self.assertEqual(app._load_session_refresh(), {})

    def test_default_save_skips_clients_whose_effective_profile_did_not_change(self):
        c = self.control()
        app._clients_cache_data['_live_clients'][SECOND] = {**c, 'mac': SECOND}
        limits = app._load_limits()
        limits['devices'][SECOND] = app._effective(SECOND, limits)
        self.state('LIMITS_FILE', limits)
        self.save_session_limits(mac='')
        self.assertEqual(app._load_session_refresh(), {MAC: {'stage': 'logout', 'session_start': str(app._clients_cache_data['_live_clients'][MAC]['session_start'])}})

    def test_noop_latency_and_overuse_only_saves_do_not_restart_sessions(self):
        self.control()
        values = {'timeout': 480, 'up': 5000, 'down': 5000}
        self.assertEqual(self.save_session_limits(mac='', values=values)['sessions_refreshing'], 0)
        values['latency_ms'] = 50
        self.assertEqual(self.save_session_limits(mac='', values=values)['sessions_refreshing'], 0)
        response = self.client.put('/api/limits', headers=self.headers,
                                   json={'limits': values, 'throttle': {'final_rate': 128}})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(app._load_session_refresh(), {})
        app._control_once()
        self.assertEqual(self.commands, [])

    def test_clearing_session_limits_reauthenticates_with_blank_global_values(self):
        self.control()
        self.save_session_limits(mac='', values={})
        self.patch('ndsctl', Mock(side_effect=[(0, 'Deauthenticated.'), (0, 'Client authenticated.')]))
        app._control_once()
        self.assertEqual(app.ndsctl.call_args_list[1].args[0], 'auth ' + MAC + " '' '' '' '' '' ''")
        self.assertEqual(app._load_json(app.APPLIED_FILE, {})[MAC], app.BLANK_SIG)

    def test_blocked_trusted_and_auto_trust_clients_are_not_refreshed(self):
        self.control()
        app._trusted_macs_cache = {MAC}
        self.save_session_limits()
        self.assertEqual(app._load_session_refresh(), {})
        app._trusted_macs_cache = set()
        self.state('BLOCK_FILE', [MAC])
        self.save_session_limits(values={'down': 3000})
        self.assertEqual(app._load_session_refresh(), {})
        self.state('BLOCK_FILE', [])
        self.state('MODE_FILE', {'mode': 'auto_trust'})
        self.save_session_limits(values={'down': 2000})
        self.assertEqual(app._load_session_refresh(), {})

    def test_interrupted_refresh_recognizes_completed_login_without_another_logout(self):
        c = self.control(mode='portal')
        self.save_session_limits()
        self.state('SESSION_REFRESH_FILE', {MAC: {'stage': 'login', 'session_start': str(app._clients_cache_data['_live_clients'][MAC]['session_start'])}})
        c['session_start'] += 10
        c.update(session_end=c['session_start'] + 240 * 60,
                 upload_rate_limit_threshold=50000, download_rate_limit_threshold=100000)
        app._control_once()
        self.assertEqual(self.commands, [])
        self.assertEqual(app._load_session_refresh(), {})
        self.assertEqual(app._load_json(app.APPLIED_FILE, {})[MAC], '240|50000|100000||')

    def test_retry_does_not_mistake_old_session_for_success_when_clearing_limits(self):
        self.control(mode='portal')
        self.save_session_limits(mac='', values={})
        refresh = app._load_session_refresh()
        refresh[MAC]['stage'] = 'login'
        self.state('SESSION_REFRESH_FILE', refresh)
        self.patch('ndsctl', Mock(side_effect=[(0, 'Deauthenticated.'), (0, 'Client authenticated.')]))
        app._control_once()
        self.assertEqual(app.ndsctl.call_count, 2)
        self.assertEqual(app._load_session_refresh(), {})

    def test_limits_saved_with_stale_snapshot_wait_for_fresh_collection(self):
        self.control(sampled=int(time.time()) - 60)
        self.save_session_limits()
        self.assertIn(MAC, app._load_session_refresh())
        app._control_once()
        self.assertEqual(self.commands, [])
        app._clients_cache_data['sampled_at'] = int(time.time())
        self.fresh_control_sample()
        self.patch('ndsctl', Mock(side_effect=[(0, 'Deauthenticated.'), (0, 'Client authenticated.')]))
        app._control_once()
        self.assertEqual(app.ndsctl.call_count, 2)

    def test_limits_login_exception_keeps_durable_retry_and_attempt_gate(self):
        c = self.control(mode='portal')
        self.save_session_limits()
        self.patch('ndsctl', Mock(side_effect=[(0, 'Deauthenticated.'), RuntimeError('SSH failed')]))
        with self.assertRaises(RuntimeError):
            app._control_once()
        self.assertEqual(app._load_session_refresh(), {MAC: {'stage': 'login', 'session_start': str(app._clients_cache_data['_live_clients'][MAC]['session_start'])}})
        app._control_once()
        self.assertEqual(app.ndsctl.call_count, 2)

    def test_stale_snapshot_never_controls_router(self):
        self.control(sampled=int(time.time())-60)
        app._control_once()
        self.assertEqual(self.commands, [])

    def test_new_auto_login_is_not_repeated_for_same_sample(self):
        self.control('Preauthenticated')
        self.patch('ndsctl', Mock(return_value=(0, 'Client authenticated.')))
        app._control_once(); app._control_once()
        self.assertEqual(app.ndsctl.call_count, 1)
        self.assertTrue(app.ndsctl.call_args[0][0].startswith('auth '))
        self.assertEqual(app._load_json(app.APPLIED_FILE, {})[MAC], '480|40000|40000||')

    def test_auth_retry_requires_a_new_post_attempt_collection(self):
        self.control('Preauthenticated')
        self.patch('ndsctl', Mock(return_value=(1, 'busy')))
        app._control_once(); app._control_once()
        self.assertEqual(app.ndsctl.call_count, 1)
        app._clients_cache_data['_collection_started_at'] = time.monotonic()+1
        app._clients_cache_data['sampled_at'] += 1
        app._control_once()
        self.assertEqual(app.ndsctl.call_count, 2)

    def test_successful_login_does_not_trigger_limit_refresh(self):
        c = self.control('Preauthenticated')
        self.patch('ndsctl', Mock(return_value=(0, 'Client authenticated.')))
        app._control_once()
        c['state'] = 'Authenticated'
        app._control_once()
        self.assertEqual(app.ndsctl.call_count, 1)

    def test_portal_background_never_bypasses_login(self):
        self.control('Preauthenticated', mode='portal')
        app._control_once()
        self.assertEqual(self.commands, [])

    def test_trusted_and_blocked_clients_are_not_authed(self):
        self.control('Preauthenticated')
        app._trusted_macs_cache = {MAC}
        app._control_once()
        app._trusted_macs_cache = set()
        self.state('BLOCK_FILE', [MAC])
        app._control_once()
        self.assertEqual(self.commands, [])

    def test_legacy_adoption_preserves_roots_handles_and_rates(self):
        self.tc()
        ok, _ = app._apply_punishment_qdisc({}, {MAC: PROFILE})
        self.assertTrue(ok)
        self.assertEqual(self.commands, [])
        self.assertEqual(app._punishment_tc_state()['bindings'][MAC], {'minor': '100', 'priority': 100})

    def test_client_join_allocates_without_renumbering_existing_client(self):
        self.tc()
        other = {**PROFILE, 'ip': '192.168.1.98'}
        self.assertTrue(app._apply_punishment_qdisc({}, {MAC: PROFILE, SECOND: other})[0])
        bindings = app._punishment_tc_state()['bindings']
        self.assertEqual(bindings[MAC]['minor'], '100')
        self.assertEqual(bindings[SECOND]['minor'], '101')
        joined = self.commands[-1]
        self.assertLess(joined.index('tc class add'), joined.index('tc qdisc add'))
        self.assertLess(joined.index('tc qdisc add'), joined.index('tc filter add'))
        self.assert_safe()

    def test_rate_change_only_changes_existing_objects(self):
        self.tc()
        self.assertTrue(app._apply_punishment_qdisc({}, {MAC: {**PROFILE, 'download_cap': 20000}})[0])
        self.assertIn('tc class change', self.commands[-1])
        self.assertIn('tc qdisc change', self.commands[-1])
        self.assertNotIn('tc filter', self.commands[-1])
        self.assert_safe()

    def test_active_queue_type_change_is_pending_without_mutation(self):
        self.tc()
        self.assertTrue(app._apply_punishment_qdisc({}, {MAC: {**PROFILE, 'delay_ms': 100}})[0])
        self.assertEqual(self.commands, [])
        self.assertIn(MAC, app._punishment_tc_state()['pending'])

    def test_inactive_type_change_detaches_then_waits_for_drain(self):
        self.tc()
        profile = {**PROFILE, 'delay_ms': 100, 'session_active': False}
        self.assertTrue(app._apply_punishment_qdisc({}, {MAC: profile})[0])
        self.assertIn('tc filter delete', self.commands[-1])
        self.assertNotIn('tc qdisc delete', self.commands[-1])
        self.assert_safe()

    def test_drained_inactive_type_change_preserves_class_and_root(self):
        layouts = self.tc(filtered=False)
        commands, message = app._tc_client_update('br-lan', layouts['download'],
            {'minor': '100', 'priority': 100}, {**PROFILE, 'delay_ms': 100, 'session_active': False}, 'dst')
        self.assertEqual(message, '')
        self.commands += commands
        self.assertIn('tc qdisc delete', commands[0])
        self.assertTrue(any('netem delay 100ms' in command for command in commands))
        self.assertFalse(any('class delete' in command for command in commands))
        self.assert_safe()

    def test_drained_detached_queue_can_change_after_next_session_starts(self):
        layouts = self.tc(filtered=False)
        commands, message = app._tc_client_update('br-lan', layouts['download'],
            {'minor': '100', 'priority': 100}, {**PROFILE, 'delay_ms': 100}, 'dst')
        self.assertEqual(message, '')
        self.commands += commands
        self.assertTrue(any('netem delay 100ms' in command for command in commands))
        self.assertLess(next(i for i, c in enumerate(commands) if 'tc qdisc add' in c),
                        next(i for i, c in enumerate(commands) if 'tc filter add' in c))
        self.assert_safe()

    def test_departure_detaches_filters_before_drain(self):
        self.tc(backlog=2)
        self.assertTrue(app._apply_punishment_qdisc({}, {})[0])
        self.assertIn('tc filter delete', self.commands[-1])
        self.assertNotIn('tc qdisc delete', self.commands[-1])
        self.assert_safe()

    def test_busy_retired_leaf_is_kept(self):
        self.tc(filtered=False, backlog=2)
        self.assertTrue(app._apply_punishment_qdisc({}, {})[0])
        self.assertEqual(self.commands, [])

    def test_drained_retired_leaf_is_removed_without_root_change(self):
        self.tc(filtered=False)
        self.assertTrue(app._apply_punishment_qdisc({}, {})[0])
        self.assertIn('tc qdisc delete', self.commands[-1])
        self.assertIn('tc class delete', self.commands[-1])
        self.assert_safe()

    def test_partial_failure_retains_ownership_and_never_restarts(self):
        self.tc()
        app.ssh.side_effect = lambda command, **kw: (self.commands.append(command) or (1, b'', 'failed'))
        ok, _ = app._apply_punishment_qdisc({}, {MAC: PROFILE, SECOND: {**PROFILE, 'ip': '192.168.1.98'}})
        self.assertFalse(ok)
        self.assertIn(SECOND, app._punishment_tc_state()['bindings'])
        self.assert_safe()

    def test_unknown_layout_is_left_unchanged(self):
        self.tc()
        app._inspect_managed_queues.return_value = (None, 'unsupported root')
        self.assertFalse(app._apply_punishment_qdisc({}, {MAC: PROFILE})[0])
        self.assertEqual(self.commands, [])

    def test_unknown_class_identity_is_left_unchanged(self):
        layouts = self.tc()
        layouts['download']['classes']['1:999'] = {'rate': 1, 'ceil': 1}
        self.assertFalse(app._apply_punishment_qdisc({}, {MAC: PROFILE})[0])
        self.assertEqual(self.commands, [])

    def test_sqm_daily_bandwidth_preserves_lan_direction_and_caps(self):
        self.tc()
        self.assertTrue(app._set_sqm_rates({'download': 20000, 'upload': 50000})[0])
        commands = self.commands[-1]
        self.assertIn('dev br-lan classid 1:1 htb rate 50000000bit', commands)
        self.assertIn('dev ifb4br-lan classid 1:1 htb rate 20000000bit', commands)
        self.assertNotIn('classid 1:100', commands)
        self.assertIn('uci commit sqm', commands)
        self.assert_safe()

    def test_daily_rule_restores_baseline_after_forced_day_ends(self):
        policy = {'enabled': True, 'threshold_gb': '20', 'download': 20000, 'upload': 20000,
                  'active': True, 'baseline': {'download': 30000, 'upload': 100000},
                  'forced_date': '2026-10-06', 'error': ''}
        self.patch('_load_sqm_conditional', Mock(return_value=policy))
        self.patch('_today_wan_traffic_total', Mock(return_value=('2026-10-07', 0)))
        self.patch('_get_sqm_rates', Mock(return_value=({'download': 20000, 'upload': 20000}, '')))
        rates = self.patch('_set_sqm_rates', Mock(return_value=(True, '')))
        saved = self.patch('_save_sqm_conditional', Mock())
        self.assertTrue(app._reconcile_sqm_conditional(force=True)[0])
        rates.assert_called_once_with({'download': 30000, 'upload': 100000})
        self.assertFalse(saved.call_args[0][0]['active'])

    def test_daily_rule_retries_prior_partial_failure_even_when_uci_matches(self):
        policy = {'enabled': True, 'threshold_gb': '20', 'download': 20000, 'upload': 20000,
                  'active': True, 'baseline': {'download': 30000, 'upload': 100000},
                  'forced_date': '2026-10-07', 'error': 'previous incomplete update'}
        self.patch('_load_sqm_conditional', Mock(return_value=policy))
        self.patch('_today_wan_traffic_total', Mock(return_value=('2026-10-07', 0)))
        self.patch('_get_sqm_rates', Mock(return_value=({'download': 20000, 'upload': 20000}, '')))
        rates = self.patch('_set_sqm_rates', Mock(return_value=(False, 'still incomplete')))
        saved = self.patch('_save_sqm_conditional', Mock())
        self.assertFalse(app._reconcile_sqm_conditional(force=True)[0])
        self.assertEqual(rates.call_count, 1)
        self.assertEqual(saved.call_args[0][0]['error'], 'still incomplete')

    def test_dns_refresh_is_coalesced_across_tabs(self):
        collector = self.patch('_collect_domain_ranking', Mock())
        app._refresh_domain_ranking(); app._refresh_domain_ranking()
        self.assertEqual(collector.call_count, 1)

    def test_missing_dns_configuration_never_reloads_dnsmasq(self):
        self.assertFalse(app._ensure_domain_logging()[0])
        self.assert_safe()
        self.assertNotIn('uci set', '\n'.join(self.commands))

    def test_atomic_write_failure_preserves_prior_file(self):
        self.state('WAN_USAGE_FILE', {'old': 1})
        with patch.object(app.os, 'replace', side_effect=OSError('disk failure')):
            with self.assertRaises(OSError):
                app._save_json(app.WAN_USAGE_FILE, {'new': 2})
        self.assertEqual(app._load_json(app.WAN_USAGE_FILE, {}), {'old': 1})
        self.assertEqual(list(Path(self.tmp.name).glob('.state-*')), [])

    def test_atomic_write_preserves_existing_permissions(self):
        self.state('WAN_USAGE_FILE', {'old': 1})
        os.chmod(app.WAN_USAGE_FILE, 0o640)
        app._save_json(app.WAN_USAGE_FILE, {'new': 2})
        self.assertEqual(os.stat(app.WAN_USAGE_FILE).st_mode & 0o777, 0o640)

    def history(self, since=None, generation=None):
        query = '' if since is None else '?since=' + str(since)
        if generation:
            query += '&generation=' + generation
        with app.app.test_request_context('/' + query):
            return app._history_response({'history': [{'at': x, 'download': x, 'upload': None}
                                                      for x in (60, 120, 180, 181, 182)],
                                          'updated_at': 182, 'recent_start_at': 180})

    def test_history_full_and_boundary_delta(self):
        self.assertTrue(self.history()['reset'])
        response = self.history(181)
        self.assertFalse(response['reset'])
        self.assertEqual([p['at'] for p in response['history']], [120, 181, 182])
        self.assertEqual(response['cursor'], 182)

    def test_history_resets_expired_future_and_previous_process_cursors(self):
        for since, generation in ((1, None), (999, None), (181, 'old-process')):
            self.assertTrue(self.history(since, generation)['reset'])

    def test_history_rejects_invalid_cursors(self):
        for since in (-1, 'not-a-number'):
            with self.assertRaises(Exception) as exc:
                self.history(since)
            self.assertEqual(exc.exception.code, 400)

    def sample(self, at, upload, download, boot='12345678-abcd', interface_upload=None, interface_download=None):
        return (at, boot, {'rx': download if interface_download is None else interface_download,
                           'tx': upload if interface_upload is None else interface_upload},
                {'flow': {'mac': MAC, 'upload': upload, 'download': download}})

    def usage(self, sample, active=True):
        app._read_wan_flows = Mock(return_value=sample)
        return app._wan_usage_snapshot({'192.168.1.99': MAC}, {MAC} if active else set(), sample[0])[MAC]

    def test_usage_state_is_loaded_once_and_physical_attribution_is_capped(self):
        self.patch('_read_wan_flows', Mock())
        loader = self.patch('_load_wan_usage', Mock(wraps=app._load_wan_usage))
        t = int(time.time())
        self.usage(self.sample(t, 100, 200))
        values = self.usage(self.sample(t+1, 300, 500, interface_upload=150, interface_download=280))
        self.assertEqual(values['today_upload'], 50)
        self.assertEqual(values['today_download'], 80)
        self.assertEqual(values['download_rate'], 80)
        self.assertEqual(loader.call_count, 1)
        self.assertEqual(app._load_json(app.WAN_USAGE_FILE, {})['sample_at'], t+1)

    def test_usage_boot_change_gap_and_inactive_client_do_not_accrue(self):
        self.patch('_read_wan_flows', Mock())
        t = int(time.time())
        self.usage(self.sample(t, 100, 100))
        values = self.usage(self.sample(t+1, 200, 200), active=False)
        self.assertEqual(values['today_download'], 0)
        values = self.usage(self.sample(t+2, 300, 300, boot='87654321-abcd'))
        self.assertIsNone(values['download_rate'])
        values = self.usage(self.sample(t+20, 500, 500, boot='87654321-abcd'))
        self.assertEqual(values['today_download'], 0)

    def test_usage_midnight_and_month_rollover_establish_fresh_baseline(self):
        self.patch('_read_wan_flows', Mock())
        from datetime import datetime
        t = int(datetime(2026, 9, 30, 23, 59, 58, tzinfo=app.ZoneInfo('Asia/Manila')).timestamp())
        self.usage(self.sample(t, 100, 100))
        self.assertEqual(self.usage(self.sample(t+1, 150, 150))['today_download'], 50)
        values = self.usage(self.sample(t+2, 200, 200))
        self.assertEqual(values['today_download'], 0)
        self.assertEqual(values['month_download'], 0)
        self.assertIsNone(values['download_rate'])

    def test_wan_interval_splits_calendar_boundary(self):
        from datetime import datetime
        t = int(datetime(2026, 9, 30, 23, 59, 59, tzinfo=app.ZoneInfo('Asia/Manila')).timestamp())
        state = {'days': {}, 'months': {}}
        app._add_wan_traffic_interval(state, t, t+2, 100, 50)
        self.assertEqual(state['months']['2026-09']['download'], 50)
        self.assertEqual(state['months']['2026-10']['download'], 50)

    def test_combined_sample_uses_one_read_and_shares_wan_counter_interval(self):
        raw = b'1800000000\n100\n200\n@@WAN\n300\n400\n@@WAN_COUNTER\ntotal_rx=300\ntotal_tx=400\n@@FLOW_SAMPLE\n@@SAMPLE_AT\n1800000000\n@@BOOT_ID\n12345678-abcd\n@@WAN_IPS\n10.0.0.1\n@@WAN_COUNTERS\n300\n400\n@@CONNTRACK\n'
        app.ssh.side_effect = None
        app.ssh.return_value = (0, raw, '')
        result = app._read_traffic_counters(include_flows=True)
        self.assertEqual(app.ssh.call_count, 1)
        self.assertEqual(result['wan_rx'], 300)
        parsed = app._read_wan_flows({'192.168.1.99': MAC}, result['flow_raw'])
        self.assertEqual(parsed[0], result['at'])
        self.assertEqual(parsed[2], {'rx': 300, 'tx': 400})

    def test_scheduler_has_one_read_for_simultaneously_due_samplers(self):
        self.patch('_wan_sampling_inputs', Mock(return_value=({'192.168.1.99': MAC}, {MAC})))
        read = self.patch('_read_traffic_counters', Mock(return_value={'at': 1800000000, 'flow_raw': b'flows'}))
        traffic = self.patch('_sample_traffic', Mock())
        usage = self.patch('_wan_usage_snapshot', Mock())
        self.patch('_reconcile_sqm_conditional', Mock())
        with patch.object(app.time, 'sleep', side_effect=StopIteration):
            with self.assertRaises(StopIteration):
                app._traffic_loop()
        self.assertEqual(read.call_count, 1)
        self.assertEqual(traffic.call_count, 1)
        self.assertEqual(usage.call_count, 1)

    def test_overview_snapshot_does_not_change_after_publication(self):
        data = app._wan_traffic_state()
        day = app._traffic_time(int(time.time())).strftime('%Y-%m-%d')
        data['days'][day] = {'download': 1, 'upload': 2}
        response = app._traffic_overview()
        data['days'][day]['download'] = 999
        self.assertEqual(response['today']['download'], 1)

    def test_disk_write_occurs_after_releasing_accounting_lock(self):
        self.patch('_read_wan_flows', Mock())
        original = app._write_json
        def check(path, encoded):
            self.assertFalse(app._wan_usage_lock.locked())
            return original(path, encoded)
        self.patch('_write_json', check)
        self.usage(self.sample(int(time.time()), 100, 100))

    def fas(self, client_state='Preauthenticated'):
        self.state('MODE_FILE', {'mode': 'portal'})
        self.state('LIMITS_FILE', {'default': {'timeout': 480, 'up': 40000, 'down': 40000}})
        self.patch('_fas_key', lambda: 'test-shared-key')
        self.patch('_refresh_punishment', Mock(return_value=(True, 'queues ready')))
        token = base64.b64encode(f'hid={"a"*64}, clientmac={MAC}, clientip=192.168.1.99, gatewayaddress=192.168.1.1:2050, authdir=/opennds_auth/, originurl=http://example.com/'.encode()).decode()
        self.patch('ndsctl', Mock(side_effect=[(0, json.dumps({'mac': MAC, 'state': client_state})),
                                               (0, 'Client authenticated.')]))
        return self.client.get('/fas/continue', query_string={'tok': token})

    def test_fas_continuation_applies_profile_only_at_new_login(self):
        self.state('SESSION_REFRESH_FILE', {MAC: {'stage': 'login', 'session_start': '1'}})
        response = self.fas()
        self.assertEqual(app._load_session_refresh(), {})
        self.assertEqual(response.status_code, 302)
        self.assertTrue(app.ndsctl.call_args_list[0][0][0].startswith('json '))
        self.assertIn(" 480 40000 40000 ", app.ndsctl.call_args_list[1][0][0])
        self.assertNotIn('deauth', str(app.ndsctl.call_args_list))

    def test_fas_continuation_preserves_existing_session(self):
        self.assertEqual(self.fas('Authenticated').status_code, 302)
        self.assertEqual(app.ndsctl.call_count, 1)

    def test_fas_continuation_rejects_mismatched_client(self):
        self.fas('Authenticated')
        app.ndsctl.side_effect = [(0, json.dumps({'mac': SECOND, 'state': 'Preauthenticated'}))]
        token = base64.b64encode(f'hid={"a"*64}, clientmac={MAC}, gatewayaddress=192.168.1.1:2050'.encode()).decode()
        response = self.client.get('/fas/continue', query_string={'tok': token})
        self.assertEqual(response.status_code, 403)
        self.assertEqual(app.ndsctl.call_count, 2)  # Two lookups, never auth.

    def test_fas_continuation_rejects_blocked_client(self):
        self.state('BLOCK_FILE', [MAC])
        response = self.fas()
        self.assertEqual(response.status_code, 403)
        self.assertEqual(app.ndsctl.call_count, 1)

    def test_cleared_session_fields_remain_pending(self):
        self.state('APPLIED_FILE', {MAC: '480|40000|40000||'})
        pending = app._session_pending({'mac': MAC, 'state': 'Authenticated'},
                                      {key: '' for key in app.LIMIT_KEYS})
        self.assertTrue(pending['limits_pending'])
        self.assertIn('timeout', pending['limits_pending_fields'])

    def test_invalid_fas_continuation_never_calls_router(self):
        self.assertEqual(self.client.get('/fas/continue?tok=invalid').status_code, 403)
        self.assertEqual(self.commands, [])


if __name__ == '__main__':
    unittest.main()
