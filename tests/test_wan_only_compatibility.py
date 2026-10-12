"""Automatic LAN/WAN placement and preserved native session behavior.

No router access: state is temporary, threads are suppressed by test_optimization,
and generated UCI reads run against local shell fixtures. Writes are captured.
WAN packet enforcement also has an explicit isolated real-packet lab.
"""
import copy
import ipaddress
import re
import shlex
import subprocess
import time
import unittest
from unittest.mock import Mock, patch

import test_optimization as optimization
import test_tc_interfaces as tc

app, MAC, SECOND = optimization.app, optimization.MAC, optimization.SECOND


class WanOnlyCompatibilityTests(unittest.TestCase):
    setUpBase = optimization.OptimizationTests.setUp
    patch = optimization.OptimizationTests.patch
    state = optimization.OptimizationTests.state
    control = optimization.OptimizationTests.control
    save_session_limits = optimization.OptimizationTests.save_session_limits

    def setUp(self):
        tc.TrafficInterfaceTests.setUp(self)
        self.patch('WAN_IFACE', 'eth0')
        self.configs = [
            {'section': 'native', 'interface': 'br-lan', 'enabled': '0'},
            {'section': 'guest', 'interface': 'eth2', 'enabled': '0'},
            {'section': 'uplink', 'interface': 'eth0', 'enabled': '1'},
        ]
        for config in self.configs:
            config.update(qdisc='cake', download='100000', upload='50000',
                          script='piece_of_cake.qos')
        self.patch('_read_sqm_queues', Mock(side_effect=lambda: (copy.deepcopy(self.configs), '')))
        self.patch('_router_interfaces', Mock(return_value=['br-lan', 'eth2', 'eth0']))
        self.patch('ssh', Mock(side_effect=self.fixture_ssh))

    def fixture_ssh(self, command, data=None, timeout=15):
        self.commands.append(command)
        # Never execute generated router mutations, even within the shell fixture.
        if re.search(r'\btc (?:class|qdisc)\b|\buci (?:set|commit|add)\b|run\.sh', command):
            return 0, b'', ''
        cases = '\n'.join(
            shlex.quote(config['section'] + ':' + key) + ') printf "%s\\n" ' + shlex.quote(value) + ';;'
            for config in self.configs for key, value in config.items())
        sections = ' '.join(shlex.quote(config['section']) for config in self.configs)
        functions = '''
fixture_get() { case "$1:$2" in
CASES
*) return 1;; esac; }
config_load() { :; }
config_foreach() { for fixture_section in SECTIONS; do "$1" "$fixture_section"; done; }
config_get() { eval "$1=\\\"$(fixture_get "$2" "$3")\\\""; }
uci() { [ "$1" != -q ] || shift; [ "$1" = get ] || return 1;
 fixture_key=${2##*.}; fixture_section=${2#sqm.}; fixture_section=${fixture_section%.*};
 fixture_get "$fixture_section" "$fixture_key"; }
tc() { case "$*" in 'filter show dev eth0 parent ffff:') printf 'Redirect to device ifb4eth0)\\n';; esac; }
'''.replace('CASES', cases).replace('SECTIONS', sections)
        if '. /lib/functions.sh;' not in command:
            raise AssertionError('Unexpected simulated SSH read')
        result = subprocess.run(['sh', '-c', command.replace('. /lib/functions.sh;', functions, 1)],
                                capture_output=True, timeout=5)
        return result.returncode, result.stdout, result.stderr.decode()

    def remove_lan_queues(self):
        self.configs[:] = [config for config in self.configs if config['interface'] == 'eth0']

    def force_daily_rules(self):
        day = app._traffic_time(time.time()).strftime('%Y-%m-%d')
        for interface in ('br-lan', 'eth2'):
            policy = app._clean_sqm_conditional({'enabled': True, 'threshold_gb': '1',
                'download': 8000, 'upload': 16000, 'forced_date': day})
            app._save_sqm_conditional(policy, interface)

    def test_disabled_native_queue_prevents_automatic_wan_fallback(self):
        command = app._primary_sqm_command('uci -q get sqm.@queue[0].interface; uci -q get sqm.@queue[0].enabled')
        rc, output, error = app.ssh(command)
        self.assertEqual(rc, 0, error)
        self.assertEqual(output.splitlines(), [b'br-lan', b'0'])
        ok, message = app._recover_managed_sqm(None, 'missing LAN roots')
        self.assertFalse(ok)
        self.assertIn('enabled CAKE SQM', message)

    def test_removing_native_queue_enables_legacy_wan_direction_fallback(self):
        self.remove_lan_queues()
        self.assertEqual(app._punishment_interfaces(),
                         ({'download': 'ifb4eth0', 'upload': 'eth0'}, ''))

    def test_secondary_disabled_queue_rejects_client_enforcement(self):
        interfaces, message = app._punishment_interfaces('eth2')
        self.assertIsNone(interfaces)
        self.assertIn('enabled CAKE SQM on eth2', message)

    def test_secondary_missing_queue_does_not_use_wan_fallback(self):
        self.remove_lan_queues()
        interfaces, message = app._punishment_interfaces('eth2')
        self.assertIsNone(interfaces)
        self.assertIn('No SQM queue for eth2', message)

    def test_wan_does_not_replace_lan_identity_for_managed_clients(self):
        self.remove_lan_queues()
        profiles = app._managed_tc_clients(self.clients, tc.POLICY, tc.LIMITS, set(), set())
        self.assertEqual(profiles[MAC]['interface'], 'br-lan')
        self.assertEqual(profiles[SECOND]['interface'], 'eth2')

    def test_secondary_punish_caps_delay_and_loss_dispatch_to_shared_wan(self):
        self.remove_lan_queues()
        policy = {**tc.POLICY, 'punished': [SECOND]}
        desired = app._managed_tc_clients(self.clients[1:], policy, tc.LIMITS, set(), set())
        self.assertEqual(desired[SECOND]['delay_ms'], 120)
        self.assertEqual(desired[SECOND]['download_cap'], 1024)
        self.assertEqual(desired[SECOND]['upload_cap'], 512)
        self.assertEqual(desired[SECOND]['loss_pct'], '1')
        apply = self.patch('_apply_wan_qos', Mock(return_value=(True, 'verified')))
        local = self.patch('_apply_punishment_qdisc', Mock())
        self.assertTrue(app._reconcile_punishment(policy, tc.LIMITS, self.clients[1:], set(), set())[0])
        self.assertEqual(apply.call_count, 1)
        self.assertEqual(apply.call_args.args[3], desired)
        self.assertEqual(set(apply.call_args.args[1]), {'br-lan', 'eth2'})
        local.assert_not_called()

    def test_wan_client_filters_do_not_match_translated_ipv4_headers(self):
        self.remove_lan_queues()
        interfaces, error = app._punishment_interfaces()
        self.assertFalse(error)
        profile = app._managed_tc_clients(self.clients[:1], tc.POLICY, tc.LIMITS, set(), set())[MAC]
        binding = {'minor': '100', 'priority': 100}
        # Explicit NAT header fixtures, not a real-packet throughput measurement.
        for direction, match in [('download', 'dst'), ('upload', 'src')]:
            with self.subTest(direction=direction):
                layout = optimization.layout(match, client=False)
                commands, message = app._tc_client_update(interfaces[direction], layout, binding, profile, match)
                self.assertFalse(message)
                classifier = next(command for command in commands if 'u32 match ip' in command)
                address = re.search(r'match ip ' + match + r' (\S+)', classifier)[1]
                network = ipaddress.ip_network(address)
                self.assertIn(ipaddress.ip_address('192.168.1.99'), network)
                self.assertNotIn(ipaddress.ip_address('203.0.113.2'), network)

    def simulate_wan_refresh(self):
        state = app._wan_qos_state()
        app._save_json(app.WAN_QOS_FILE, {**state, 'daily_rates': app._wan_daily_targets(['br-lan', 'eth2'])})
        return True, 'verified'

    def test_daily_rules_use_wan_classes_when_lan_queues_are_disabled(self):
        self.force_daily_rules()
        self.patch('_refresh_punishment', Mock(side_effect=self.simulate_wan_refresh))
        ok, message = app._reconcile_sqm_conditional(force=True)
        self.assertTrue(ok, message)
        for interface in ('br-lan', 'eth2'):
            self.assertTrue(app._load_sqm_conditional(interface)['active'])
            self.assertEqual(app._load_sqm_conditional(interface)['placement'], 'wan')
            self.assertEqual(app._load_sqm_conditional(interface)['baseline'], {'download': 0, 'upload': 0})
        self.assertEqual(self.commands, [])

    def test_daily_rules_follow_wan_after_removal_and_restore_at_midnight(self):
        self.remove_lan_queues()
        self.force_daily_rules()
        self.patch('_refresh_punishment', Mock(side_effect=self.simulate_wan_refresh))
        self.assertTrue(app._reconcile_sqm_conditional(force=True)[0])
        with patch.object(app, '_today_interface_wan_total', return_value=('2099-01-01', 0)):
            self.assertTrue(app._reconcile_sqm_conditional(force=True)[0])
        for interface in ('br-lan', 'eth2'):
            self.assertFalse(app._load_sqm_conditional(interface)['active'])
            self.assertEqual(app._wan_qos_state()['daily_rates'][interface], {'download': 0, 'upload': 0})
        self.assertEqual(self.commands, [])

    def test_daily_rule_api_rejects_wan_target(self):
        response = self.client.put('/api/sqm/conditional', headers=self.headers,
            json={'interface': 'eth0', 'enabled': True, 'threshold_gb': '1', 'download': 1000, 'upload': 500})
        self.assertEqual(response.status_code, 400)
        self.assertIn('LAN interface', response.get_json()['output'])
        self.assertEqual(self.commands, [])

    def test_wan_aggregate_rate_commands_keep_correct_download_upload_directions(self):
        self.remove_lan_queues()
        layouts = {direction: optimization.layout(match, client=False)
                   for direction, match in [('download', 'dst'), ('upload', 'src')]}
        self.patch('_inspect_managed_queues', Mock(return_value=(layouts, '')))
        ok, message = app._set_sqm_rates({'download': 24000, 'upload': 8000})
        self.assertTrue(ok, message)
        mutation = self.commands[-1]
        self.assertIn('dev ifb4eth0 classid 1:1 htb rate 24000000bit', mutation)
        self.assertIn('dev eth0 classid 1:1 htb rate 8000000bit', mutation)
        self.assertNotIn('dev br-lan', mutation)

    def check_session_refresh(self, mode):
        self.remove_lan_queues()
        self.control(mode=mode)
        # Simulate broken hard-queue enforcement while exercising real session refresh.
        app._reconcile_punishment.return_value = (False, 'LAN SQM unavailable')
        self.patch('ndsctl', Mock(side_effect=[(0, 'Deauthenticated.'), (0, 'Client authenticated.')]))
        self.save_session_limits(values={'timeout': 240, 'up': 6250, 'down': 12500,
                                         'upq': 1024, 'downq': 2048})
        app._control_once()
        app._control_once()
        self.assertEqual(app.ndsctl.call_args_list[0].args, ('deauth ' + MAC,))
        self.assertEqual(shlex.split(app.ndsctl.call_args_list[1].args[0]),
                         ['auth', MAC, '240', '50000', '100000', '1024', '2048', ''])
        self.assertEqual(app._load_session_refresh(), {})

    def test_portal_session_timeouts_quotas_and_native_rates_still_apply(self):
        self.check_session_refresh('portal')

    def test_auto_auth_session_timeouts_quotas_and_native_rates_still_apply(self):
        self.check_session_refresh('auto_auth')

    def test_overuse_throttle_dispatches_secondary_client_to_wan(self):
        self.remove_lan_queues()
        limits = copy.deepcopy(tc.LIMITS)
        limits['default']['throttle'] = {'trigger_secs': 3, 'final_rate': 800, 'reset_secs': 30}
        self.patch('_live_wan_usage', Mock(return_value={SECOND: {'download_rate': 2000000, 'upload_rate': 0}}))
        with patch.object(app.time, 'time', return_value=100):
            self.assertEqual(app._throttle_rate_caps(self.clients, limits), {})
        with patch.object(app.time, 'time', return_value=104):
            caps = app._throttle_rate_caps(self.clients, limits)
        self.assertEqual(caps, {SECOND: {'download': 800}})
        profiles = app._managed_tc_clients(self.clients[1:], tc.POLICY, limits, set(), set(), caps)
        self.assertEqual(profiles[SECOND]['download_cap'], 800)
        apply = self.patch('_apply_wan_qos', Mock(return_value=(True, 'verified')))
        self.patch('_throttle_rate_caps', Mock(return_value=caps))
        self.assertTrue(app._reconcile_punishment(tc.POLICY, limits, self.clients[1:], set(), set())[0])
        self.assertEqual(apply.call_args.args[3][SECOND]['download_cap'], 800)


class WanDailyTransitionTests(unittest.TestCase):
    setUp = WanOnlyCompatibilityTests.setUp
    setUpBase = WanOnlyCompatibilityTests.setUpBase
    patch = WanOnlyCompatibilityTests.patch
    state = WanOnlyCompatibilityTests.state
    fixture_ssh = WanOnlyCompatibilityTests.fixture_ssh
    force_daily_rules = WanOnlyCompatibilityTests.force_daily_rules

    def test_lan_wan_mixed_lan_transitions_preserve_independent_restore_points_after_failure(self):
        originals = {}
        for index, queue in enumerate(self.configs[:2]):
            queue.update(enabled='1', download=str(100000-index*50000), upload=str(80000-index*40000))
            originals[queue['interface']] = {key: int(queue[key]) for key in ('download', 'upload')}
        self.force_daily_rules()
        failed = False
        calls = []
        def apply(iface, rates):
            nonlocal failed
            calls.append((iface, dict(rates)))
            routes, _ = app._qos_placements()
            if routes[iface]['placement'] == 'wan':
                if failed:
                    return False, 'simulated partial WAN failure'
                store = app._wan_qos_state()
                app._save_json(app.WAN_QOS_FILE, {**store, 'daily_rates': app._wan_daily_targets(
                    [name for name, route in routes.items() if route['placement'] == 'wan'])})
            else:
                next(q for q in self.configs if q['interface'] == iface).update({key: str(value) for key,value in rates.items()})
            return True, ''
        self.patch('_daily_sqm_set_rates', Mock(side_effect=apply))
        self.assertTrue(app._reconcile_sqm_conditional(force=True)[0])
        for iface in originals:
            self.assertEqual(app._load_sqm_conditional(iface)['baseline'], originals[iface])
        for queue in self.configs[:2]:
            queue['enabled'] = '0'
        failed = True
        self.assertFalse(app._reconcile_sqm_conditional(force=True)[0])
        for iface in originals:
            rule = app._load_sqm_conditional(iface)
            self.assertEqual(rule['baselines']['lan'], originals[iface])
            self.assertEqual(rule['baseline'], {'download': 0, 'upload': 0})
            self.assertIn('partial WAN failure', rule['error'])
        failed = False
        self.assertTrue(app._reconcile_sqm_conditional(force=True)[0])
        updated = {'download': 120000, 'upload': 90000}
        app._set_sqm_conditional_baseline(updated, 'br-lan')
        self.configs[0].update(enabled='1', **{key:str(value) for key,value in updated.items()})
        self.assertTrue(app._reconcile_sqm_conditional(force=True)[0])
        self.assertEqual(app._load_sqm_conditional('br-lan')['baseline'], updated)
        self.assertEqual(app._load_sqm_conditional('eth2')['placement'], 'wan')
        guest = app._load_sqm_conditional('eth2')
        policy = app._load_sqm_conditional('br-lan')
        policy['enabled'] = False
        app._save_sqm_conditional(policy, 'br-lan')
        self.assertTrue(app._reconcile_sqm_conditional(force=True, interface='br-lan')[0])
        self.assertEqual(calls[-1], ('br-lan', updated))
        self.assertEqual(app._load_sqm_conditional('eth2'), guest)
        self.configs[1]['enabled'] = '1'
        with patch.object(app, '_today_interface_wan_total', return_value=('2099-01-01', 0)):
            self.assertTrue(app._reconcile_sqm_conditional(force=True)[0])
        self.assertEqual(calls[-1], ('eth2', originals['eth2']))
        for iface in originals:
            self.assertFalse(app._load_sqm_conditional(iface)['active'])
            self.assertEqual(app._load_sqm_conditional(iface)['baseline'], {})


if __name__ == '__main__':
    unittest.main()
