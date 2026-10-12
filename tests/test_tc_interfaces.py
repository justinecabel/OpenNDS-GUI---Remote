"""Per-LAN traffic-control isolation. Router operations are mocked."""
import copy
import json
import subprocess
import unittest
from unittest.mock import Mock
import test_optimization as optimization

app, MAC, SECOND = optimization.app, optimization.MAC, optimization.SECOND
PRIMARY = optimization.INTERFACES
EXTRA = {'download': 'eth2', 'upload': 'ifb4eth2'}
POLICY = {'punished': [], 'download': 1024, 'upload': 512, 'delay_ms': 100, 'loss_pct': '1'}
LIMITS = {'default': {'up': 8000, 'down': 16000, 'latency_ms': 20}, 'devices': {}}


class TrafficInterfaceTests(unittest.TestCase):
    setUpBase = optimization.OptimizationTests.setUp
    patch = optimization.OptimizationTests.patch
    state = optimization.OptimizationTests.state

    def setUp(self):
        self.setUpBase()
        self.patch('_networks_data', {'initialized': True, 'primary_device': 'br-lan', 'networks': [
            {'name': 'lan', 'device': 'br-lan', 'primary': True, 'eligible': True,
             'role': 'LAN', 'mode': 'auto_auth', 'subnets': ['192.168.1.0/24']},
            {'name': 'piso', 'device': 'eth2', 'primary': False, 'eligible': True,
             'role': 'LAN', 'mode': 'portal', 'subnets': ['10.0.0.0/24']},
            {'name': 'wan', 'device': 'eth0', 'primary': False, 'eligible': False,
             'role': 'WAN', 'mode': 'unmanaged', 'subnets': ['192.168.122.0/24']}]})
        self.clients = [{'mac': MAC, 'ip': '192.168.1.99', 'state': 'Authenticated'},
                        {'mac': SECOND, 'ip': '10.0.0.100', 'state': 'Authenticated'}]

    def layouts(self):
        return {'download': optimization.layout('dst', client=False, rate='50Mbit'),
                'upload': optimization.layout('src', client=False, rate='25Mbit')}

    def mock_queues(self):
        self.patch('_punishment_interfaces', Mock(side_effect=lambda iface=None: (EXTRA if iface else PRIMARY, '')))
        self.patch('_inspect_managed_queues', Mock(side_effect=lambda *a, **kw: (self.layouts(), '')))

    def test_managed_profiles_include_each_lan_and_combine_caps_delay_and_loss(self):
        profiles = app._managed_tc_clients(self.clients, {**POLICY, 'punished': [SECOND]}, LIMITS, set(), set())
        self.assertEqual(profiles[MAC]['interface'], 'br-lan')
        self.assertEqual(profiles[SECOND]['interface'], 'eth2')
        self.assertEqual(profiles[SECOND]['download_cap'], 1024)
        self.assertEqual(profiles[SECOND]['upload_cap'], 512)
        self.assertEqual(profiles[SECOND]['delay_ms'], 120)
        self.assertEqual(profiles[SECOND]['loss_pct'], '1')
        self.assertEqual(app._managed_tc_clients(self.clients, POLICY, LIMITS, {MAC}, {SECOND}), {})

    def test_unknown_wan_unmanaged_and_ipv6_clients_are_excluded(self):
        rows = app._network_state()['networks']
        for ip in ['203.0.113.10', '192.168.122.15', '::1']:
            self.assertEqual(app._managed_tc_clients([{**self.clients[0], 'ip': ip}], POLICY, LIMITS, set(), set()), {})
        rows[1]['mode'] = 'unmanaged'
        self.assertIsNone(app._client_tc_interface(self.clients[1]))
        rows[1]['mode'] = 'portal';rows[1]['eligible'] = False
        self.assertIsNone(app._client_tc_interface(self.clients[1]))

    def test_reconcile_uses_independent_queue_pairs_and_keeps_existing_native_handles(self):
        legacy = {'active': True, 'version': 2, 'interfaces': PRIMARY,
                  'bindings': {MAC: {'minor': '150', 'priority': 150}}}
        self.state('PUNISH_TC_FILE', legacy)
        self.mock_queues()
        self.assertTrue(app._reconcile_punishment(POLICY, LIMITS, self.clients, set(), set())[0])
        native, extra = app._punishment_tc_state(), app._punishment_tc_state('eth2')
        self.assertEqual(native['bindings'][MAC]['minor'], '150')
        self.assertNotIn(SECOND, native['bindings'])
        self.assertEqual(extra['bindings'][SECOND]['minor'], '100')
        self.assertNotIn(MAC, extra['bindings'])
        self.assertEqual(native['interfaces'], PRIMARY)
        self.assertEqual(extra['interfaces'], EXTRA)
        self.assertIn('match ip dst 10.0.0.100/32', self.commands[-1])
        self.assertNotIn('br-lan', self.commands[-1])
        self.assertNotIn('10.0.0.100', self.commands[0])

    def test_one_queue_failure_and_timeout_do_not_block_other_lan(self):
        def apply(policy, desired, interface=None):
            if interface is None:
                raise subprocess.TimeoutExpired('ssh', 30)
            self.assertEqual(set(desired), {SECOND})
            return True, 'active'
        call = self.patch('_apply_punishment_qdisc', Mock(side_effect=apply))
        ok, message = app._reconcile_punishment(POLICY, LIMITS, self.clients, set(), set())
        self.assertFalse(ok)
        self.assertIn('br-lan: queue operation timed out', message)
        self.assertEqual(call.call_count, 2)
        self.assertEqual(app._session_pending(self.clients[1], LIMITS['default'])['tc_pending_message'], '')

    def test_session_pending_reports_only_own_lan_failure(self):
        state = {'error': 'native failed', 'networks': {'eth2': {'error': 'piso failed'}}}
        self.assertEqual(app._session_pending(self.clients[0], {}, tc=state)['tc_pending_message'], 'native failed')
        result = app._session_pending(self.clients[1], {}, tc=state)
        self.assertEqual(result['tc_pending_message'], 'piso failed')
        self.assertEqual(result['tc_note'], '')

    def test_client_move_cleans_old_group_and_applies_new_group(self):
        self.state('PUNISH_TC_FILE', {'active': True, 'clients': [MAC],
                                    'networks': {'eth2': {'active': True, 'clients': [SECOND]}}})
        call = self.patch('_apply_punishment_qdisc', Mock(return_value=(True, 'active')))
        moved = {**self.clients[0], 'ip': '10.0.0.110'}
        app._reconcile_punishment(POLICY, LIMITS, [moved], set(), set())
        self.assertEqual(call.call_args_list[0].args[1], {})
        self.assertEqual(set(call.call_args_list[1].args[1]), {MAC})
        self.assertEqual(call.call_args_list[1].args[2], 'eth2')

    def test_partial_failure_retains_only_target_ownership(self):
        self.mock_queues()
        native = {'active': True, 'bindings': {MAC: {'minor': '123', 'priority': 123}}}
        self.state('PUNISH_TC_FILE', native)
        app.ssh.return_value = (1, b'', 'queue failure');app.ssh.side_effect = None
        desired = app._managed_tc_clients(self.clients[1:], POLICY, LIMITS, set(), set())
        self.assertFalse(app._apply_punishment_qdisc(POLICY, desired, 'eth2')[0])
        self.assertEqual(app._punishment_tc_state()['bindings'], native['bindings'])
        self.assertIn(SECOND, app._punishment_tc_state('eth2')['bindings'])
        self.assertIn('queue failure', app._punishment_tc_state('eth2')['error'])

    def test_ifb_is_discovered_and_direction_is_lan_oriented(self):
        app.ssh.side_effect = None
        app.ssh.return_value = (0, b'eth2\n1\ncake\naction order 1: mirred (Egress Redirect to device ifb-custom) stolen\n', '')
        self.assertEqual(app._punishment_interfaces('eth2'), ({'download': 'eth2', 'upload': 'ifb-custom'}, ''))
        command = app.ssh.call_args.args[0]
        self.assertIn('tc filter show dev eth2 parent ffff:', command)
        self.assertNotIn('sqm_primary=${sqm_primary:-$sqm_wan}', command)
        for output in [b'eth2\n0\ncake\n', b'eth2\n1\nfq_codel\n', b'eth2\n1\ncake\n',
                       b'eth2\n1\ncake\nRedirect to device eth0)\n',
                       b'eth2\n1\ncake\nRedirect to device ifb1)\nRedirect to device ifb2)\n']:
            app.ssh.return_value = (0, output, '')
            self.assertIsNone(app._punishment_interfaces('eth2')[0])
        self.assertIsNone(app._punishment_interfaces('eth0')[0])

    def test_secondary_daily_rate_change_is_in_place_and_preserves_native_state(self):
        self.mock_queues()
        native = {'active': True, 'bindings': {MAC: {'minor': '100', 'priority': 100}}}
        self.state('PUNISH_TC_FILE', native)
        self.assertTrue(app._set_sqm_rates({'download': 12000, 'upload': 24000}, 'eth2')[0])
        command = self.commands[-1]
        self.assertIn('dev eth2 classid 1:1 htb rate 24000000bit', command)
        self.assertIn('dev ifb4eth2 classid 1:1 htb rate 12000000bit', command)
        self.assertNotIn('br-lan', command)
        self.assertNotIn('/usr/lib/sqm/run.sh', command)
        self.assertEqual(app._punishment_tc_state(), native)

    def test_secondary_recovery_is_scoped_and_preserves_primary_state(self):
        self.mock_queues()
        native = {'active': True, 'bindings': {MAC: {'minor': '100', 'priority': 100}}}
        self.state('PUNISH_TC_FILE', native)
        self.assertTrue(app._restart_sqm(interface='eth2')[0])
        self.assertEqual(app._punishment_tc_state()['bindings'], native['bindings'])
        self.assertTrue(app._punishment_tc_state()['active'])
        self.assertFalse(app._punishment_tc_state('eth2')['active'])
        self.assertIn('[ "$dev" = eth2 ]', self.commands[-1])
        self.assertNotIn('br-lan', self.commands[-1])

    def test_only_extra_active_keeps_controller_and_status_active(self):
        self.state('PUNISH_TC_FILE', {'active': False, 'networks': {'eth2': {'active': True}}})
        self.assertTrue(app._managed_tc_active(app._punishment_tc_state()))
        self.assertTrue(app._punishment_for_ui(POLICY)['tc_active'])
        call = self.patch('_apply_punishment_qdisc', Mock(return_value=(True, 'cleaned')))
        app._reconcile_punishment(POLICY, LIMITS, [], set(), set())
        self.assertEqual(call.call_args.args, (POLICY, {}, 'eth2'))

    def test_punish_api_accepts_secondary_and_refreshes_just_its_lan(self):
        self.patch('_cached_client', Mock(return_value=self.clients[1]))
        refresh = self.patch('_refresh_punishment', Mock(return_value=(True, 'active')))
        result = self.client.post('/api/action', headers=self.headers, json={'action': 'punish', 'mac': SECOND})
        self.assertEqual(result.status_code, 200)
        self.assertIn(SECOND, app._load_punishment_policy()['punished'])
        refresh.assert_called_once_with('eth2')

    def test_failed_secondary_punish_restores_policy(self):
        self.patch('_cached_client', Mock(return_value=self.clients[1]))
        previous = app._load_punishment_policy()
        self.patch('_refresh_punishment', Mock(return_value=(False, 'SQM disabled')))
        result = self.client.post('/api/action', headers=self.headers, json={'action': 'punish', 'mac': SECOND})
        self.assertEqual(result.status_code, 502)
        self.assertEqual(app._load_punishment_policy(), previous)

    def test_targeted_refresh_ignores_unrelated_lan_failure(self):
        call = self.patch('_apply_punishment_qdisc', Mock(return_value=(True, 'active')))
        app._reconcile_punishment(POLICY, LIMITS, self.clients, set(), set(), 'eth2')
        self.assertEqual(call.call_count, 1)
        self.assertEqual(set(call.call_args.args[1]), {SECOND})
        self.assertEqual(call.call_args.args[2], 'eth2')

    def test_secondary_overuse_throttle_is_per_client(self):
        limits = copy.deepcopy(LIMITS)
        limits['default']['throttle'] = {'trigger_secs': 3, 'final_rate': 800, 'reset_secs': 30}
        self.patch('_live_wan_usage', Mock(return_value={SECOND: {'download_rate': 2000000, 'upload_rate': 1000000}}))
        from unittest.mock import patch
        with patch.object(app.time, 'time', return_value=100):
            self.assertEqual(app._throttle_rate_caps(self.clients, limits), {})
        with patch.object(app.time, 'time', return_value=104):
            self.assertEqual(app._throttle_rate_caps(self.clients, limits), {SECOND: {'download': 800, 'upload': 800}})

    def test_secondary_bootstrap_preserves_own_rates_options_and_native_ownership(self):
        self.mock_queues()
        native = {'active': True, 'bindings': {MAC: {'minor': '150', 'priority': 150}}}
        self.state('PUNISH_TC_FILE', native)
        plain = {direction: app._parse_tc_layout(
            f'qdisc cake 800a: root refcnt 2 bandwidth {rate} besteffort triple-isolate nat wash rtt 100ms raw overhead 0\n backlog 0b 0p')
            for direction, rate in [('download', '50Mbit'), ('upload', '25Mbit')]}
        app._inspect_managed_queues.side_effect = [(plain, ''), (self.layouts(), ''), (self.layouts(), '')]
        desired = app._managed_tc_clients(self.clients[1:], POLICY, LIMITS, set(), set())
        self.assertTrue(app._apply_punishment_qdisc(POLICY, desired, 'eth2')[0])
        commands = self.commands[0]
        self.assertIn('dev eth2 parent 1: classid 1:1 htb rate 50000000bit', commands)
        self.assertIn('dev ifb4eth2 parent 1: classid 1:1 htb rate 25000000bit', commands)
        self.assertIn('cake bandwidth 50Mbit besteffort triple-isolate nat wash', commands)
        self.assertNotIn('br-lan', '\n'.join(self.commands))
        self.assertEqual(app._punishment_tc_state()['bindings'], native['bindings'])

    def test_secondary_bandwidth_updates_latency_only_classes_but_keeps_explicit_caps(self):
        layouts = {'download': optimization.layout('dst'), 'upload': optimization.layout('src')}
        self.patch('_punishment_interfaces', Mock(return_value=(EXTRA, '')))
        self.patch('_inspect_managed_queues', Mock(return_value=(layouts, '')))
        state = {'active': True, 'bindings': {SECOND: {'minor': '100', 'priority': 100}},
                 'signature': json.dumps({'clients': {SECOND: {'download_cap': 0, 'upload_cap': 8000}}})}
        app._save_punishment_tc_state(state, 'eth2')
        self.assertTrue(app._set_sqm_rates({'download': 12000, 'upload': 24000}, 'eth2')[0])
        self.assertIn('dev eth2 classid 1:100 htb rate 24000000bit', self.commands[-1])
        self.assertNotIn('dev ifb4eth2 classid 1:100', self.commands[-1])

    def test_extra_queue_resolver_rejects_duplicates_and_never_falls_back_to_wan(self):
        functions = '''config_load() { :; }
config_get() { for item in $sqm_test_rows; do case "$item" in "$2":*) eval "$1=${item#*:}";; esac; done; }
config_foreach() { for item in $sqm_test_rows; do "$1" "${item%%:*}"; done; }
'''
        for rows, expected in [('native:br-lan guest:eth2 wan:eth0', 'guest'),
                               ('native:br-lan wan:eth0', None),
                               ('guest:eth2 duplicate:eth2 wan:eth0', None)]:
            command = app._primary_sqm_command('printf "%s" "$sqm_primary"', 'eth2')
            command = command.replace('. /lib/functions.sh;', functions+'\nsqm_test_rows="'+rows+'";')
            result = subprocess.run(['sh', '-c', command], capture_output=True, text=True)
            if expected:
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, expected)
            else:
                self.assertNotEqual(result.returncode, 0)

    def test_discovery_supports_vlan_device_and_custom_ifb_without_hardcoded_eth2(self):
        row = app._network_state()['networks'][1]
        row['device'] = 'br-guests.37'
        self.assertEqual(app._client_tc_interface(self.clients[1]), 'br-guests.37')
        app.ssh.side_effect = None
        app.ssh.return_value = (0, b'br-guests.37\n1\ncake\nRedirect to device ifb-guests37)\n', '')
        self.assertEqual(app._punishment_interfaces('br-guests.37')[0],
                         {'download': 'br-guests.37', 'upload': 'ifb-guests37'})

    def test_successful_group_save_preserves_other_group_error_and_recovery_backoff(self):
        root = {'active': True, 'error': 'native failed', 'recovery_at': 100,
                'bindings': {MAC: {'minor': '150', 'priority': 150}}}
        self.state('PUNISH_TC_FILE', root)
        app._save_punishment_tc_state({'active': True, 'recovery_at': 200, 'error': ''}, 'eth2')
        root_after = app._punishment_tc_state()
        for key in root:
            self.assertEqual(root_after[key], root[key])
        self.assertEqual(app._punishment_tc_state('eth2')['recovery_at'], 200)
        status = app._punishment_for_ui(POLICY)
        self.assertIn('br-lan: native failed', status['tc_error'])

    def test_missing_secondary_ifb_recovers_only_that_interface_then_applies(self):
        self.mock_queues()
        app._punishment_interfaces.side_effect = [(None, 'missing IFB'), (EXTRA, '')]
        app.ssh.side_effect = lambda command, **kw: (self.commands.append(command) or
            (0, b'1\ncake\n50000\n25000\n' if 'uci -q get sqm."$sqm_primary".qdisc' in command else b'', ''))
        desired = app._managed_tc_clients(self.clients[1:], POLICY, LIMITS, set(), set())
        self.assertTrue(app._apply_punishment_qdisc(POLICY, desired, 'eth2')[0])
        self.assertEqual(sum('/usr/lib/sqm/run.sh stop' in c for c in self.commands), 1)
        self.assertNotIn('br-lan', '\n'.join(self.commands))
        self.assertIn(SECOND, app._punishment_tc_state('eth2')['bindings'])

    def test_missing_ifb_does_not_restart_disabled_non_cake_or_zero_rate_queue(self):
        self.patch('_punishment_interfaces', Mock(return_value=(None, 'missing IFB')))
        desired = app._managed_tc_clients(self.clients[1:], POLICY, LIMITS, set(), set())
        for metadata in [b'0\ncake\n50000\n50000\n', b'1\nfq_codel\n50000\n50000\n',
                         b'1\ncake\n0\n50000\n']:
            app.ssh.side_effect = lambda command, **kw: (self.commands.append(command) or (0, metadata, ''))
            self.assertFalse(app._apply_punishment_qdisc(POLICY, desired, 'eth2')[0])
        self.assertFalse(any('/usr/lib/sqm/run.sh' in c for c in self.commands))

    def test_failed_secondary_recovery_uses_own_backoff_and_keeps_primary_untouched(self):
        self.patch('_punishment_interfaces', Mock(return_value=(None, 'missing IFB')))
        native = {'active': True, 'recovery_at': 1, 'bindings': {MAC: {'minor': '150', 'priority': 150}}}
        self.state('PUNISH_TC_FILE', native)
        app.ssh.side_effect = lambda command, **kw: (self.commands.append(command) or
            ((0, b'1\ncake\n50000\n50000\n', '') if 'uci -q get sqm."$sqm_primary".qdisc' in command else (1, b'', 'failed')))
        desired = app._managed_tc_clients(self.clients[1:], POLICY, LIMITS, set(), set())
        self.assertFalse(app._apply_punishment_qdisc(POLICY, desired, 'eth2')[0])
        self.assertFalse(app._apply_punishment_qdisc(POLICY, desired, 'eth2')[0])
        self.assertEqual(sum('/usr/lib/sqm/run.sh stop' in c for c in self.commands), 1)
        self.assertEqual(app._punishment_tc_state()['recovery_at'], 1)
        self.assertEqual(app._punishment_tc_state()['bindings'], native['bindings'])
