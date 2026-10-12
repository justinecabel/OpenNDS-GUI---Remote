"""Independent interface queues and scoped client control, without router writes."""
import subprocess
import unittest
from unittest.mock import Mock
import test_optimization as optimization

app = optimization.app


class SqmInterfaceTests(unittest.TestCase):
    setUp = optimization.OptimizationTests.setUp
    patch = optimization.OptimizationTests.patch
    state = optimization.OptimizationTests.state

    def queues(self, extra_first=False):
        native = {'section': 'office', 'interface': 'br-lan', 'enabled': '1',
                  'download': '100000', 'upload': '50000', 'qdisc': 'cake', 'script': 'piece_of_cake.qos'}
        extra = {**native, 'section': 'guest', 'interface': 'eth2', 'download': '8000', 'upload': '4000'}
        configs = [extra, native] if extra_first else [native, extra]
        self.patch('_read_sqm_queues', Mock(return_value=(configs, '')))
        self.patch('_router_interfaces', Mock(return_value=['br-lan', 'eth2', 'eth0', 'lo', 'ifb4br-lan']))
        self.patch('_networks_data', {'networks': [
            {'name': 'office', 'device': 'br-lan', 'role': 'LAN', 'subnets': ['192.168.1.0/24']},
            {'name': 'guests', 'device': 'eth2', 'role': 'LAN', 'subnets': ['10.0.0.0/24']}]})
        return configs

    def body(self, iface='eth2'):
        return {'interface': iface, 'enabled': True, 'download': 250, 'upload': 500,
                'qdisc': 'cake', 'script': 'piece_of_cake.qos'}

    def test_get_selects_primary_by_interface_even_when_extra_queue_is_first(self):
        self.queues(extra_first=True)
        data = self.client.get('/api/sqm', headers=self.headers).get_json()
        self.assertEqual(data['config']['interface'], 'br-lan')
        self.assertEqual(data['config']['download'], '12500')
        self.assertEqual(len(data['queues']), 2)
        self.assertEqual(data['interface_roles']['eth2'], 'guests · LAN')
        self.assertNotIn('lo', data['interfaces'])
        self.assertNotIn('ifb4br-lan', data['interfaces'])
        self.assertEqual(self.commands, [])

    def test_get_extra_loads_its_own_rates(self):
        self.queues()
        data = self.client.get('/api/sqm?interface=eth2', headers=self.headers).get_json()
        self.assertEqual(data['config']['download'], '1000')
        self.assertEqual(data['config']['upload'], '500')
        self.assertEqual(data['config']['section'], 'guest')

    def test_get_separates_baseline_from_active_daily_rates_without_writes(self):
        configs = self.queues()
        configs[0].update(download='20000', upload='16000')
        policy = {'version': 2, 'rules': {'br-lan': {
            'enabled': True, 'active': True, 'placement': 'lan',
            'download': 20000, 'upload': 16000,
            'baseline': {'download': 100000, 'upload': 50000}}}}
        self.state('SQM_CONDITIONAL_FILE', policy)
        data = self.client.get('/api/sqm', headers=self.headers).get_json()
        self.assertEqual(data['config']['download'], '2500')
        self.assertEqual(data['config']['upload'], '2000')
        self.assertEqual(data['baseline_config']['download'], '12500')
        self.assertEqual(data['baseline_config']['upload'], '6250')
        self.assertEqual(data['baseline_config']['section'], 'office')
        self.assertEqual(data['baseline_queues'][1], data['queues'][1])
        self.assertEqual(configs[0]['download'], '20000')
        self.assertEqual(app._load_json(app.SQM_CONDITIONAL_FILE, {}), policy)
        self.assertEqual(self.commands, [])

    def test_waiting_rules_leave_baseline_equal_to_configured_queue(self):
        self.queues()
        self.state('SQM_CONDITIONAL_FILE', {'version': 2, 'rules': {
            'br-lan': {'enabled': True, 'active': False, 'download': 20000, 'upload': 20000}}})
        data = self.client.get('/api/sqm', headers=self.headers).get_json()
        self.assertEqual(data['baseline_config'], data['config'])
        self.assertEqual(data['baseline_queues'], data['queues'])

    def test_pending_daily_restore_still_returns_original_baseline(self):
        self.queues()
        self.state('SQM_CONDITIONAL_FILE', {'version': 2, 'rules': {
            'eth2': {'enabled': False, 'active': False, 'placement': 'lan',
                     'baseline': {'download': 32000, 'upload': 0}, 'error': 'restore failed'}}})
        data = self.client.get('/api/sqm?interface=eth2', headers=self.headers).get_json()
        self.assertEqual(data['config']['download'], '1000')
        self.assertEqual(data['baseline_config']['download'], '4000')
        self.assertEqual(data['baseline_config']['upload'], '0')
        self.assertEqual(data['baseline_queues'][0], data['queues'][0])

    def test_wan_daily_parent_rates_do_not_replace_aggregate_wan_baseline(self):
        configs = self.queues()
        configs.append({**configs[0], 'interface': 'eth0', 'section': 'wan'})
        self.state('SQM_CONDITIONAL_FILE', {'version': 2, 'rules': {
            'br-lan': {'enabled': True, 'active': True, 'placement': 'wan',
                       'baseline': {'download': 0, 'upload': 0},
                       'baselines': {'lan': {'download': 80000, 'upload': 40000}}}}})
        data = self.client.get('/api/sqm?interface=eth0', headers=self.headers).get_json()
        self.assertEqual(data['baseline_config'], data['config'])
        self.assertEqual(data['baseline_queues'][0]['download'], '10000')
        self.assertEqual(data['baseline_queues'][0]['upload'], '5000')

    def test_extra_bandwidth_save_is_in_place_and_refreshes_only_own_clients(self):
        self.queues(extra_first=True)
        daily = self.patch('_set_sqm_conditional_baseline', Mock())
        refresh = self.patch('_refresh_punishment', Mock(return_value=(True, 'active')))
        rates = self.patch('_set_sqm_rates', Mock(return_value=(True, '')))
        data = self.client.put('/api/sqm', headers=self.headers, json=self.body()).get_json()
        self.assertTrue(data['ok'])
        rates.assert_called_once_with({'download': 2000, 'upload': 4000}, 'eth2')
        daily.assert_called_once_with({'download': 2000, 'upload': 4000}, 'eth2')
        refresh.assert_called_once_with('eth2')
        self.assertEqual(self.commands, [])

    def test_extra_structural_save_targets_own_section_and_restores_its_client_queues(self):
        self.queues(extra_first=True)
        self.patch('_refresh_punishment', Mock(return_value=(True, 'active')))
        data = self.client.put('/api/sqm', headers=self.headers,
                               json={**self.body(), 'script': 'layer_cake.qos'}).get_json()
        self.assertTrue(data['ok'])
        command = self.commands[-1]
        self.assertIn('section=guest', command)
        self.assertIn('download=2000', command)
        self.assertIn('upload=4000', command)
        self.assertIn('sqm_apply_iface=eth2', command)
        self.assertIn('/usr/lib/sqm/run.sh stop "$sqm_apply_iface"', command)
        self.assertIn('/usr/lib/sqm/run.sh start "$sqm_apply_iface"', command)
        self.assertNotIn('br-lan', command)
        self.assertNotIn('@queue[0]', command)

    def test_new_queue_appends_instead_of_repurposing_native_queue(self):
        self.patch('_refresh_punishment', Mock(return_value=(True, 'active')))
        configs = self.queues()
        app._read_sqm_queues.return_value = (configs[:1], '')
        data = self.client.get('/api/sqm?interface=eth2', headers=self.headers).get_json()
        self.assertFalse(data['configured'])
        self.assertTrue(self.client.put('/api/sqm', headers=self.headers, json=self.body()).get_json()['ok'])
        command = self.commands[-1]
        self.assertIn('section=$(uci add sqm queue)', command)
        self.assertIn('linklayer=none', command)
        self.assertNotIn('office', command)

    def test_duplicate_interface_queues_and_invalid_interfaces_are_rejected(self):
        configs = self.queues()
        app._read_sqm_queues.return_value = ([configs[0], configs[1], {**configs[1], 'section': 'another'}], '')
        self.assertEqual(self.client.put('/api/sqm', headers=self.headers, json=self.body()).status_code, 409)
        self.assertEqual(self.client.get('/api/sqm?interface=eth2', headers=self.headers).status_code, 409)
        for iface in ('eth2;reboot', 'missing', 'lo', 'ifb4br-lan'):
            self.assertEqual(self.client.put('/api/sqm', headers=self.headers, json=self.body(iface)).status_code, 400)
        self.assertEqual(self.commands, [])

    def test_failed_read_does_not_create_queue_and_failed_apply_is_reported(self):
        self.queues()
        app._read_sqm_queues.return_value = ([], 'read failed')
        self.assertEqual(self.client.get('/api/sqm', headers=self.headers).status_code, 502)
        self.assertEqual(self.client.put('/api/sqm', headers=self.headers, json=self.body()).status_code, 502)
        self.assertEqual(self.commands, [])
        self.queues()
        self.patch('_set_sqm_rates', Mock(return_value=(False, 'apply failed')))
        app.ssh.side_effect = None
        app.ssh.return_value = (1, b'', 'apply failed')
        response = self.client.put('/api/sqm', headers=self.headers, json=self.body())
        self.assertEqual(response.status_code, 502)
        self.assertIn('apply failed', response.get_json()['output'])

    def test_uci_parser_preserves_named_and_anonymous_queue_identity(self):
        app.ssh.side_effect = None
        app.ssh.return_value = (0, b"sqm.guest=queue\nsqm.guest.interface='eth2'\nsqm.guest.download='8000'\nsqm.@queue[1]=queue\nsqm.@queue[1].interface='br-lan'\n", '')
        rows, error = app._read_sqm_queues()
        self.assertFalse(error)
        self.assertEqual([q['section'] for q in rows], ['guest', '@queue[1]'])
        self.assertEqual(rows[0]['download'], '8000')

    def test_primary_resolver_ignores_queue_order_and_falls_back_to_wan_only(self):
        for mapping, expected in [('guest:eth2 native:br-lan uplink:eth0', 'native'),
                                  ('guest:eth2 uplink:eth0', 'uplink'), ('guest:eth2', None)]:
            command = app._primary_sqm_command('printf "%s" "$sqm_primary"')
            functions = '''config_load() { :; }
config_get() { for item in $sqm_test_rows; do case "$item" in "$2":*) eval "$1=${item#*:}";; esac; done; }
config_foreach() { for item in $sqm_test_rows; do "$1" "${item%%:*}"; done; }
'''
            command = command.replace('. /lib/functions.sh;', functions + '\nsqm_test_rows="' + mapping + '";')
            result = subprocess.run(['sh', '-c', command], capture_output=True, text=True)
            if expected:
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, expected)
            else:
                self.assertNotEqual(result.returncode, 0)

    def test_scoped_apply_checks_state_instead_of_misleading_exit_status(self):
        import tempfile
        from pathlib import Path
        for initial, behavior, enabled, success, calls in (
                (False, 'success_with_rc1', '1', True, ['start']),
                (True, 'success_with_rc1', '1', True, ['stop', 'start']),
                (False, 'fail_start', '1', False, ['start']),
                (True, 'fail_stop', '1', False, ['stop']),
                (False, 'success_with_rc1', '0', True, []),
                (True, 'success_with_rc1', '0', True, ['stop'])):
            with self.subTest(initial=initial, behavior=behavior, enabled=enabled):
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    state = root / 'eth2.state'
                    if initial:
                        state.touch()
                    runner = root / 'run.sh'
                    runner.write_text(f'''#!/bin/sh
printf '%s\\n' "$1" >> {root}/calls
if [ "$1" = stop ]; then
 [ "{behavior}" != fail_stop ] || exit 1
 rm -f {state}
else
 [ "{behavior}" != fail_start ] || exit 1
 touch {state}
fi
exit 1
''')
                    runner.chmod(0o700)
                    command = app._sqm_apply_script('eth2', enabled)
                    config = root / 'sqm.conf'
                    config.write_text(f'SQM_STATE_DIR={root}\ncommand -v missing_sqm_test_binary\n')
                    command = command.replace('/etc/sqm/sqm.conf', str(config))
                    command = command.replace('/usr/lib/sqm/run.sh', str(runner))
                    command = command.replace('logread |', 'printf "SQM: test diagnostic\\n" |')
                    result = subprocess.run(['sh', '-ec', command], capture_output=True, text=True)
                    self.assertEqual(result.returncode == 0, success, result.stderr)
                    actual = (root / 'calls').read_text().splitlines() if (root / 'calls').exists() else []
                    self.assertEqual(actual, calls)
                    if not success:
                        self.assertIn('SQM', result.stderr)
