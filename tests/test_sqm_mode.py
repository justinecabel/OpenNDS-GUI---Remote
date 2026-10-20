"""Exclusive SQM selection, API guards and executable rollback without a router."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import Mock

import test_sqm_daily_interfaces as daily

app = daily.app


class SqmModeTests(unittest.TestCase):
    patch = daily.DailyInterfaceTests.patch
    state = daily.DailyInterfaceTests.state
    setUpBase = daily.DailyInterfaceTests.setUpBase

    def setUp(self):
        daily.DailyInterfaceTests.setUp(self)
        self.queues.append({'section': 'uplink', 'interface': 'eth0', 'enabled': '0',
                            'download': '100000', 'upload': '50000'})
        for queue in self.queues:
            queue.update(qdisc='cake', script='piece_of_cake.qos')
        self.patch('_router_interfaces', Mock(return_value=['br-lan', 'eth2', 'eth0']))
        self.refresh = self.patch('_refresh_punishment', Mock(return_value=(True, '')))
        self.reconcile = self.patch('_reconcile_sqm_conditional', Mock(return_value=(True, '')))

    def put(self, **body):
        return self.client.put('/api/sqm/mode', headers=self.headers, json=body)

    def select(self, iface='eth0'):
        self.state('SQM_MODE_FILE', {'mode': 'single', 'interface': iface})

    def test_default_preserves_multiple_and_get_has_no_writes(self):
        data = self.client.get('/api/sqm?refresh=1', headers=self.headers).get_json()
        self.assertEqual(data['sqm_mode'], {'mode': 'multiple', 'interface': ''})
        self.assertEqual(len(data['queues']), 3)
        self.assertFalse(Path(app.SQM_MODE_FILE).exists())
        self.assertEqual(self.commands, [])

    def test_single_disables_others_and_daily_preserving_policy_settings(self):
        for iface in ('br-lan', 'eth2'):
            app._save_sqm_conditional(app._clean_sqm_conditional({
                'enabled': True, 'active': True, 'forced_date': self.day,
                'threshold_gb': 17, 'download': 8000, 'upload': 16000,
                'baseline': {'download': 100000, 'upload': 90000}}), iface)
        response = self.put(mode='single', interface='eth0')
        self.assertEqual(response.status_code, 200, response.get_json())
        self.assertEqual(app._load_sqm_mode(), {'mode': 'single', 'interface': 'eth0'})
        command = self.commands[0]
        self.assertIn('uci set sqm.uplink.enabled=1', command)
        self.assertIn('uci set sqm.native.enabled=0', command)
        self.assertIn("uci set sqm.'@queue[1]'.enabled=0", command)
        self.assertIn('uci set sqm.native.upload=90000', command)
        for iface in ('br-lan', 'eth2'):
            policy = app._load_sqm_conditional(iface)
            self.assertFalse(policy['enabled'])
            self.assertFalse(policy['active'])
            self.assertEqual(policy['forced_date'], '')
            self.assertEqual(policy['threshold_gb'], '17')
            self.assertEqual(policy['download'], 8000)
            self.assertEqual(policy['baseline'], {})
        self.refresh.assert_called_once_with()

    def test_selected_daily_and_already_active_roots_are_retained(self):
        self.queues[-1]['enabled'] = '1'
        saved = app._clean_sqm_conditional({'enabled': True, 'active': True,
            'forced_date': self.day, 'baseline': {'download': 90000, 'upload': 40000}})
        app._save_sqm_conditional(saved, 'eth0')
        self.assertEqual(self.put(mode='single', interface='eth0').status_code, 200)
        self.assertEqual(app._load_sqm_conditional('eth0'), saved)
        # The already-running WAN is never stopped/restarted by the success path.
        main = self.commands[0].split('trap sqm_mode_finish EXIT;', 1)[1]
        self.assertNotIn('sqm_apply_iface=eth0', main)

    def test_mode_and_selected_interface_persist_across_get(self):
        self.select('eth2')
        response = self.client.get('/api/sqm?refresh=1', headers=self.headers).get_json()
        self.assertEqual(response['selected_interface'], 'eth2')
        self.assertEqual(response['sqm_mode']['mode'], 'single')
        self.assertEqual(len(response['queues']), 3)

    def test_multiple_changes_only_mode_without_reenabling_queues(self):
        self.select()
        before = copy.deepcopy(self.queues)
        self.assertEqual(self.put(mode='multiple').status_code, 200)
        self.assertEqual(app._load_sqm_mode()['mode'], 'multiple')
        self.assertEqual(self.queues, before)
        self.assertEqual(self.commands, [])
        self.refresh.assert_not_called()

    def test_single_api_rejects_enabling_other_interfaces(self):
        self.select()
        response = self.client.put('/api/sqm', headers=self.headers, json={
            'interface': 'br-lan', 'enabled': True, 'download': 10000, 'upload': 5000})
        self.assertEqual(response.status_code, 409)
        self.assertEqual(self.commands, [])

    def test_selected_queue_can_still_be_turned_off(self):
        self.select('eth2')
        self.patch('_save_extra_sqm', Mock(return_value=(True, '')))
        response = self.client.put('/api/sqm', headers=self.headers, json={
            'interface': 'eth2', 'enabled': False, 'download': 10000, 'upload': 5000})
        self.assertEqual(response.status_code, 200, response.get_json())
        self.assertEqual(app._load_sqm_mode()['interface'], 'eth2')

    def test_failure_retains_mode_and_daily(self):
        self.select('br-lan')
        before = app._load_sqm_conditional('br-lan')
        app.ssh.side_effect = lambda *args, **kw: (1, b'', 'SQM start failed')
        self.assertEqual(self.put(mode='single', interface='eth0').status_code, 502)
        self.assertEqual(app._load_sqm_mode()['interface'], 'br-lan')
        self.assertEqual(app._load_sqm_conditional('br-lan'), before)
        self.refresh.assert_not_called()

    def test_pending_client_policy_does_not_report_mode_apply_as_failed(self):
        self.refresh.return_value = (False, 'classification pending')
        response = self.put(mode='single', interface='eth0')
        self.assertEqual(response.status_code, 200)
        self.assertIn('classification pending', response.get_json()['tc_error'])

    def test_invalid_unconfigured_duplicate_and_unauthenticated_writes(self):
        for body in ({'mode': 'bad'}, {'mode': 'single', 'interface': 'eth0;false'},
                     {'mode': 'single', 'interface': 'ifb4eth0'}, {'mode': 'single'}):
            self.assertEqual(self.put(**body).status_code, 400)
        self.assertEqual(self.put(mode='single', interface='eth3').status_code, 409)
        self.queues.append(dict(self.queues[0], section='duplicate'))
        self.assertEqual(self.put(mode='single', interface='eth0').status_code, 502)
        self.assertEqual(self.client.put('/api/sqm/mode', json={'mode': 'multiple'}).status_code, 401)
        self.assertEqual(self.commands, [])

    def run_shell(self, fail_start=False, fail_stop=False):
        self.assertTrue(app._apply_single_sqm(self.queues, 'eth0')[0])
        command = self.commands[-1]
        root = Path(self.tmp.name)
        config, conf, run, state, trace = [root / name for name in ('sqm', 'sqm.conf', 'run.sh', 'state', 'trace')]
        state.mkdir()
        original = {q['section']: {k: str(v) for k, v in q.items()} for q in self.queues}
        config.write_text(json.dumps(original))
        conf.write_text('SQM_STATE_DIR=' + str(state) + '\n')
        for q in self.queues:
            if q['enabled'] == '1':
                (state / (q['interface'] + '.state')).touch()
        run.write_text('''#!/bin/sh
printf '%s %s\\n' "$1" "$2" >> "$TRACE"
if [ "$1" = stop ]; then
  [ "$FAIL_STOP" != "$2" ] || exit 1
  rm -f "$STATE/$2.state"
else
  [ "$FAIL_START" != "$2" ] || exit 1
  touch "$STATE/$2.state"
fi
exit 1
''')
        run.chmod(0o700)
        uci = root / 'uci'
        uci.write_text('#!' + sys.executable + '\n' + '''import json, os, sys
from pathlib import Path
p=Path(os.environ['CONFIG']); args=[a for a in sys.argv[1:] if a != '-q']; data=json.loads(p.read_text())
if args[0] == 'set':
    key,value=args[1].split('=',1); _,section,option=key.split('.',2); data[section][option]=value; p.write_text(json.dumps(data))
elif args[0] == 'get':
    _,section,option=args[1].split('.',2); print(data[section][option])
''')
        uci.chmod(0o700)
        command = command.replace('/etc/config/sqm', str(config)).replace('/etc/sqm/sqm.conf', str(conf)).replace('/usr/lib/sqm/run.sh', str(run))
        env = {**os.environ, 'PATH': str(root) + ':' + os.environ['PATH'], 'STATE': str(state),
               'CONFIG': str(config), 'TRACE': str(trace),
               'FAIL_START': 'eth0' if fail_start else '', 'FAIL_STOP': 'eth2' if fail_stop else ''}
        result = subprocess.run(['sh', '-c', command], env=env, capture_output=True, text=True, timeout=15)
        return result, json.loads(config.read_text()), {p.stem for p in state.glob('*.state')}, original, trace.read_text()

    def test_executable_shell_enables_one_queue_and_stops_others_before_start(self):
        result, config, running, _, trace = self.run_shell()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(running, {'eth0'})
        self.assertEqual({q['interface'] for q in config.values() if q['enabled'] == '1'}, {'eth0'})
        self.assertLess(trace.index('stop eth2'), trace.index('start eth0'))

    def test_executable_shell_start_failure_rolls_back_config_and_runtime(self):
        result, config, running, original, _ = self.run_shell(fail_start=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(config, original)
        self.assertEqual(running, {'br-lan', 'eth2'})

    def test_executable_shell_stop_failure_rolls_back_without_starting_target(self):
        result, config, running, original, trace = self.run_shell(fail_stop=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(config, original)
        self.assertEqual(running, {'br-lan', 'eth2'})
        self.assertNotIn('start eth0', trace)
