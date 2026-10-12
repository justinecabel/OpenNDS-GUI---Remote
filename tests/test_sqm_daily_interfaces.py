"""Independent daily rules and WAN byte attribution; no router mutations."""
import copy
import subprocess
import time
import unittest
from unittest.mock import Mock, patch
import test_optimization as optimization

app = optimization.app
MAC, SECOND = optimization.MAC, optimization.SECOND
GB = 1024 ** 3


class DailyInterfaceTests(unittest.TestCase):
    setUpBase = optimization.OptimizationTests.setUp
    patch = optimization.OptimizationTests.patch
    state = optimization.OptimizationTests.state

    def setUp(self):
        self.setUpBase()
        self.patch('_networks_data', {'initialized': True, 'primary_device': 'br-lan', 'networks': [
            {'name': 'lan', 'device': 'br-lan', 'role': 'LAN', 'subnets': ['192.168.1.0/24']},
            {'name': 'piso', 'device': 'eth2', 'role': 'LAN', 'subnets': ['10.0.0.0/24']},
            {'name': 'wan', 'device': 'eth0', 'role': 'WAN', 'subnets': ['192.168.122.0/24']} ]})
        self.queues = [{'section': 'native', 'interface': 'br-lan', 'enabled': '1',
                        'download': '100000', 'upload': '100000'},
                       {'section': '@queue[1]', 'interface': 'eth2', 'enabled': '1',
                        'download': '50000', 'upload': '50000'}]
        self.patch('_read_sqm_queues', Mock(side_effect=lambda: (self.queues, '')))
        self.day = app._traffic_time(time.time()).strftime('%Y-%m-%d')
        self.state('SQM_CONDITIONAL_FILE', {'version': 2, 'rules': {}})
        self.calls = []
        def change(iface, rates):
            self.calls.append((iface, dict(rates)))
            queue = next(q for q in self.queues if q['interface'] == iface)
            queue.update({k: str(v) for k,v in rates.items()})
            return True, ''
        self.patch('_daily_sqm_set_rates', Mock(side_effect=change))
        self.patch('_wan_usage_data', {'day': self.day, 'interface_days': {}, 'interface_tracking_since': 123})

    def policy(self, iface, **values):
        policy = app._clean_sqm_conditional({'enabled': True, 'threshold_gb': '1',
                                            'download': 8000, 'upload': 16000, **values})
        app._save_sqm_conditional(policy, iface)
        return policy

    def usage(self, **totals):
        app._wan_usage_data['interface_days'] = {iface: {'download': total, 'upload': 0}
                                               for iface,total in totals.items()}

    def test_migration_keeps_original_policy_only_on_primary_and_get_never_writes(self):
        original = self.policy('br-lan', active=True, forced_date=self.day,
                               baseline={'download': 100000, 'upload': 100000})
        self.state('SQM_CONDITIONAL_FILE', original)
        self.usage(**{'br-lan': 42, 'eth2': 99})
        data = self.client.get('/api/sqm/conditional', headers=self.headers).get_json()
        rules = {r['interface']: r for r in data['rules']}
        self.assertTrue(rules['br-lan']['enabled'])
        self.assertTrue(rules['br-lan']['forced_today'])
        self.assertFalse(rules['eth2']['enabled'])
        self.assertFalse(rules['eth2']['forced_today'])
        self.assertEqual(rules['eth2']['today_bytes'], 99)
        self.assertNotIn('eth0', rules)
        self.assertEqual(app._load_json(app.SQM_CONDITIONAL_FILE, {}), original)
        self.assertEqual(self.commands, [])
        app._reconcile_sqm_conditional(force=True)
        self.assertEqual(app._load_json(app.SQM_CONDITIONAL_FILE, {})['version'], 2)

    def test_only_interface_over_its_threshold_activates(self):
        self.policy('br-lan')
        self.policy('eth2', download=4000, upload=6000)
        self.usage(**{'br-lan': GB-1, 'eth2': GB})
        self.assertTrue(app._reconcile_sqm_conditional(force=True)[0])
        self.assertEqual(self.calls, [('eth2', {'download': 4000, 'upload': 6000})])
        self.assertFalse(app._load_sqm_conditional('br-lan')['active'])
        self.assertEqual(app._load_sqm_conditional('eth2')['baseline'], {'download': 50000, 'upload': 50000})

    def test_one_error_does_not_block_other_interface(self):
        self.policy('br-lan'); self.policy('eth2')
        self.queues[0]['enabled'] = '0'
        self.usage(**{'br-lan': GB, 'eth2': GB})
        ok, message = app._reconcile_sqm_conditional(force=True)
        self.assertFalse(ok)
        self.assertIn('br-lan', message)
        self.assertEqual([iface for iface,_ in self.calls], ['eth2'])
        self.assertTrue(app._load_sqm_conditional('eth2')['active'])

    def test_timeout_on_one_interface_keeps_restore_point_and_does_not_block_other(self):
        for iface in ('br-lan', 'eth2'):
            self.policy(iface, forced_date=self.day)
        change = app._daily_sqm_set_rates.side_effect
        def timeout_first(iface, rates):
            if iface == 'br-lan':
                raise subprocess.TimeoutExpired('ssh', 30)
            return change(iface, rates)
        app._daily_sqm_set_rates.side_effect = timeout_first
        ok, message = app._reconcile_sqm_conditional(force=True)
        self.assertFalse(ok)
        self.assertIn('timed out', message)
        self.assertEqual(app._load_sqm_conditional('br-lan')['baseline'], {'download': 100000, 'upload': 100000})
        self.assertTrue(app._load_sqm_conditional('eth2')['active'])

    def test_force_today_targets_selected_queue_and_midnight_restores_its_baseline(self):
        self.policy('br-lan')
        before = app._load_sqm_conditional('br-lan')
        response = self.client.put('/api/sqm/conditional', headers=self.headers,
            json={'interface': 'eth2', 'force_today': True, 'download': 500, 'upload': 750})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.calls, [('eth2', {'download': 4000, 'upload': 6000})])
        self.assertEqual(app._load_sqm_conditional('br-lan'), before)
        with patch.object(app, '_today_interface_wan_total', return_value=('2099-01-01', 0)):
            self.assertTrue(app._reconcile_sqm_conditional(force=True)[0])
        self.assertEqual(self.calls[-1], ('eth2', {'download': 50000, 'upload': 50000}))
        self.assertFalse(app._load_sqm_conditional('eth2')['active'])
        self.assertEqual(app._load_sqm_conditional('eth2')['forced_date'], '')

    def test_disabling_one_rule_does_not_restore_other_active_rule(self):
        for iface in ('br-lan','eth2'):
            self.policy(iface, forced_date=self.day)
        app._reconcile_sqm_conditional(force=True)
        self.calls.clear()
        response = self.client.put('/api/sqm/conditional', headers=self.headers,
                                   json={'interface': 'eth2', 'enabled': False})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.calls, [('eth2', {'download': 50000, 'upload': 50000})])
        self.assertTrue(app._load_sqm_conditional('br-lan')['active'])

    def test_base_edits_change_only_selected_restore_point(self):
        for iface in ('br-lan', 'eth2'):
            self.policy(iface, active=True, baseline={'download': 10000, 'upload': 20000})
        before = app._load_sqm_conditional('br-lan')
        app._set_sqm_conditional_baseline({'download': 30000, 'upload': 40000}, 'eth2')
        self.assertEqual(app._load_sqm_conditional('br-lan'), before)
        self.assertEqual(app._load_sqm_conditional('eth2')['baseline'], {'download': 30000, 'upload': 40000})

    def test_baseline_save_reapplies_daily_then_midnight_restores_new_baseline(self):
        for queue in self.queues:
            queue.update(qdisc='cake', script='piece_of_cake.qos')
        self.patch('_router_interfaces', Mock(return_value=['br-lan', 'eth2']))
        self.patch('_refresh_punishment', Mock(return_value=(True, 'active')))
        self.policy('br-lan', forced_date=self.day)
        self.assertTrue(app._reconcile_sqm_conditional(force=True)[0])
        self.assertEqual(self.queues[0]['download'], '8000')
        change = app._daily_sqm_set_rates.side_effect
        self.patch('_set_sqm_rates', Mock(side_effect=lambda rates, interface=None:
                                        change(interface or 'br-lan', rates)))
        response = self.client.put('/api/sqm', headers=self.headers, json={
            'interface': 'br-lan', 'enabled': True, 'download': 20000, 'upload': 30000,
            'qdisc': 'cake', 'script': 'piece_of_cake.qos'})
        self.assertEqual(response.status_code, 200, response.get_json())
        self.assertEqual(self.queues[0]['download'], '8000')
        self.assertEqual(self.queues[0]['upload'], '16000')
        self.assertEqual(app._load_sqm_conditional('br-lan')['baseline'],
                         {'download': 160000, 'upload': 240000})
        data = self.client.get('/api/sqm', headers=self.headers).get_json()
        self.assertEqual(data['baseline_config']['download'], '20000')
        self.assertEqual(data['baseline_config']['upload'], '30000')
        self.assertEqual(data['config']['download'], '1000')
        self.assertEqual(data['config']['upload'], '2000')
        with patch.object(app, '_today_interface_wan_total', return_value=('2099-01-01', 0)):
            self.assertTrue(app._reconcile_sqm_conditional(force=True)[0])
        self.assertEqual(self.queues[0]['download'], '160000')
        self.assertEqual(self.queues[0]['upload'], '240000')
        data = self.client.get('/api/sqm', headers=self.headers).get_json()
        self.assertEqual(data['baseline_config'], data['config'])

    def test_partial_failure_persists_original_baseline_and_disable_recovers_it(self):
        self.policy('eth2', forced_date=self.day)
        def partial(iface, rates):
            self.queues[1].update({key: str(value) for key,value in rates.items()})
            return False, 'start failed'
        app._daily_sqm_set_rates.side_effect = partial
        self.assertFalse(app._reconcile_sqm_conditional(force=True)[0])
        policy = app._load_sqm_conditional('eth2')
        self.assertFalse(policy['active'])
        self.assertEqual(policy['baseline'], {'download': 50000, 'upload': 50000})
        app._daily_sqm_set_rates.side_effect = None
        app._daily_sqm_set_rates.return_value = (True, '')
        policy.update(enabled=False, forced_date='')
        app._save_sqm_conditional(policy, 'eth2')
        self.assertTrue(app._reconcile_sqm_conditional(force=True)[0])
        app._daily_sqm_set_rates.assert_called_with('eth2', {'download': 50000, 'upload': 50000})

    def test_extra_rate_dispatch_preserves_section_and_never_touches_primary(self):
        with patch.object(app, '_daily_sqm_set_rates', self._real_set):
            self.assertTrue(app._daily_sqm_set_rates('eth2', {'download': 8000, 'upload': 16000})[0])
        command = self.commands[-1]
        self.assertIn("section='@queue[1]'", command)
        self.assertIn('sqm_apply_iface=eth2', command)
        self.assertNotIn('br-lan', command)
        self.assertNotIn('qdisc=', command)

    _real_set = staticmethod(app._daily_sqm_set_rates)

    def test_invalid_missing_disabled_or_duplicate_target_cannot_enable_rule(self):
        for iface in ([], 'eth2;reboot', 'missing', 'eth0'):
            response = self.client.put('/api/sqm/conditional', headers=self.headers,
                                       json={'interface': iface, 'enabled': True})
            self.assertEqual(response.status_code, 400)
        for queues in (self.queues[:1], [self.queues[0], {**self.queues[1], 'enabled': '0'}],
                       [*self.queues, {**self.queues[1], 'section': 'duplicate'}]):
            app._read_sqm_queues.side_effect = None
            app._read_sqm_queues.return_value = (queues, '')
            response = self.client.put('/api/sqm/conditional', headers=self.headers,
                                       json={'interface': 'eth2', 'enabled': True})
            self.assertEqual(response.status_code, 409)
        self.assertEqual(self.calls, [])
        self.assertEqual(self.commands, [])

    def test_old_day_is_zero_even_before_next_sampler_tick(self):
        self.usage(**{'br-lan': 2*GB, 'eth2': 3*GB})
        app._wan_usage_data['day'] = '2000-01-01'
        data = self.client.get('/api/sqm/conditional?interface=eth2', headers=self.headers).get_json()
        self.assertEqual(data['today_bytes'], 0)
        self.assertEqual(data['interface'], 'eth2')


class InterfaceAccountingTests(unittest.TestCase):
    setUp = DailyInterfaceTests.setUp
    setUpBase = DailyInterfaceTests.setUpBase
    patch = DailyInterfaceTests.patch
    state = DailyInterfaceTests.state

    def sample(self, at, first, second, ip='192.168.1.99', active=True, boot='12345678-abcd', cap=None):
        self.patch('_read_wan_flows', Mock(return_value=(at, boot, {'rx': cap if cap is not None else first+second, 'tx': 0},
            {'a': {'mac': MAC, 'download': first, 'upload': 0},
             'b': {'mac': SECOND, 'download': second, 'upload': 0}})))
        return app._wan_usage_snapshot({ip: MAC, '10.0.0.98': SECOND}, {MAC,SECOND} if active else set(), at)

    def start(self):
        app._wan_usage_data = None
        self.t = int(time.time())
        self.sample(self.t, 100, 200)

    def test_counts_deltas_per_interface_and_moving_mac_does_not_move_old_bytes(self):
        self.start(); self.sample(self.t+1, 130, 250)
        self.assertEqual(app._wan_usage_data['interface_days'], {
            'br-lan': {'download': 30, 'upload': 0}, 'eth2': {'download': 50, 'upload': 0}})
        self.sample(self.t+2, 150, 260, ip='10.0.0.99')
        self.assertEqual(app._wan_usage_data['interface_days']['br-lan']['download'], 30)
        self.assertEqual(app._wan_usage_data['interface_days']['eth2']['download'], 80)
        app._wan_usage_data['devices'].clear()
        self.assertEqual(app._today_interface_wan_total('br-lan')[1], 30)

    def test_interface_totals_use_physically_capped_deltas_and_exclude_unknown_addresses(self):
        self.start(); self.sample(self.t+1, 300, 400, cap=400)
        self.assertEqual(sum(v['download'] for v in app._wan_usage_data['interface_days'].values()), 100)
        before = copy.deepcopy(app._wan_usage_data['interface_days'])
        self.sample(self.t+2, 500, 400, ip='203.0.113.99', cap=900)
        self.assertEqual(app._wan_usage_data['interface_days'], before)

    def test_persistence_restart_baseline_and_offline_clients_do_not_duplicate_counts(self):
        self.start(); self.sample(self.t+1, 130, 250)
        before = copy.deepcopy(app._wan_usage_data['interface_days'])
        app._wan_usage_data = None
        with patch.object(app, 'WAN_USAGE_SAMPLER_ID', 'a'*32):
            self.sample(self.t+2, 500, 600)
            self.assertEqual(app._wan_usage_data['interface_days'], before)
            self.sample(self.t+3, 600, 700, active=False)
            self.assertEqual(app._wan_usage_data['interface_days'], before)

    def test_midnight_clears_all_interface_totals_and_establishes_baseline(self):
        self.start(); self.sample(self.t+1, 130, 250)
        app._wan_usage_data['day'] = '2000-01-01'
        self.sample(self.t+2, 300, 400)
        self.assertEqual(app._wan_usage_data['interface_days'], {})
        self.sample(self.t+3, 310, 420)
        self.assertEqual(app._wan_usage_data['interface_days']['br-lan']['download'], 10)
        self.assertEqual(app._wan_usage_data['interface_days']['eth2']['download'], 20)


if __name__ == '__main__':
    unittest.main()
