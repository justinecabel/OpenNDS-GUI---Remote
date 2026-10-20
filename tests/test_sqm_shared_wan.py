"""Shared WAN Daily lifecycle, isolation and display names; no router access."""
import copy
import time
import unittest
from unittest.mock import Mock, patch

import test_sqm_daily_interfaces as daily
import test_wan_policy as wan

GB, app = daily.GB, daily.app


class SharedWanTests(unittest.TestCase):
    patch = daily.DailyInterfaceTests.patch
    state = daily.DailyInterfaceTests.state
    setUpBase = daily.DailyInterfaceTests.setUpBase
    policy = daily.DailyInterfaceTests.policy
    usage = daily.DailyInterfaceTests.usage

    def setUp(self):
        daily.DailyInterfaceTests.setUp(self)
        self.queues.append({'section': 'uplink', 'interface': 'eth0', 'enabled': '1',
                            'download': '200000', 'upload': '80000',
                            'qdisc': 'cake', 'script': 'piece_of_cake.qos'})
        self.patch('_today_wan_traffic_total', Mock(return_value=(self.day, 2 * GB)))

    def test_shared_rule_reads_all_wan_counter_and_get_is_read_only(self):
        self.usage(**{'br-lan': 17, 'eth2': 23})
        before = app._load_json(app.SQM_CONDITIONAL_FILE, {})
        data = self.client.get('/api/sqm/conditional?interface=eth0', headers=self.headers).get_json()
        self.assertEqual(data['usage_scope'], 'all_wan')
        self.assertEqual(data['today_bytes'], 2 * GB)
        self.assertTrue(data['available'])
        self.assertFalse(data['enabled'])
        self.assertEqual({r['interface']: r['today_bytes'] for r in data['rules']},
                         {'br-lan': 17, 'eth2': 23, 'eth0': 2 * GB})
        self.assertEqual(app._load_json(app.SQM_CONDITIONAL_FILE, {}), before)
        self.assertEqual(self.commands, [])

    def test_shared_threshold_changes_only_wan_aggregate(self):
        for iface in ('br-lan', 'eth2', 'eth0'):
            self.policy(iface)
        self.assertTrue(app._reconcile_sqm_conditional(force=True)[0])
        self.assertEqual(self.calls, [('eth0', {'download': 8000, 'upload': 16000})])
        saved = app._load_sqm_conditional('eth0')
        self.assertEqual(saved['placement'], 'aggregate')
        self.assertEqual(saved['baseline'], {'download': 200000, 'upload': 80000})
        self.assertTrue(saved['active'])
        self.assertFalse(app._load_sqm_conditional('br-lan')['active'])

    def test_disable_shared_restores_aggregate_without_changing_lan_daily(self):
        self.policy('br-lan', forced_date=self.day)
        self.policy('eth0')
        app._reconcile_sqm_conditional(force=True)
        lan = app._load_sqm_conditional('br-lan')
        self.calls.clear()
        response = self.client.put('/api/sqm/conditional', headers=self.headers,
                                   json={'interface': 'eth0', 'enabled': False})
        self.assertEqual(response.status_code, 200, response.get_json())
        self.assertEqual(self.calls, [('eth0', {'download': 200000, 'upload': 80000})])
        self.assertEqual(app._load_sqm_conditional('br-lan'), lan)
        self.assertFalse(app._load_sqm_conditional('eth0')['active'])

    def test_force_today_and_midnight_restore_only_shared_baseline(self):
        app._today_wan_traffic_total.return_value = (self.day, 0)
        self.policy('br-lan', forced_date=self.day)
        self.policy('eth0', threshold_gb='99')
        response = self.client.put('/api/sqm/conditional', headers=self.headers,
            json={'interface': 'eth0', 'force_today': True, 'download': 2500, 'upload': 1000})
        self.assertEqual(response.status_code, 200, response.get_json())
        self.assertEqual(self.calls, [('eth0', {'download': 20000, 'upload': 8000})])
        app._today_wan_traffic_total.return_value = ('2099-01-01', 0)
        self.assertTrue(app._reconcile_sqm_conditional(force=True, interface='eth0')[0])
        self.assertEqual(self.calls[-1], ('eth0', {'download': 200000, 'upload': 80000}))
        self.assertEqual(app._load_sqm_conditional('eth0')['forced_date'], '')
        self.assertEqual(app._load_sqm_conditional('br-lan')['forced_date'], self.day)

    def test_shared_baseline_edit_is_retained_and_daily_reapplied(self):
        self.policy('eth0')
        app._reconcile_sqm_conditional(force=True)
        change = app._daily_sqm_set_rates.side_effect
        self.patch('_router_interfaces', Mock(return_value=['br-lan', 'eth2', 'eth0']))
        self.patch('_refresh_punishment', Mock(return_value=(True, 'verified')))
        self.patch('_set_sqm_rates', Mock(side_effect=lambda rates, interface=None: change(interface, rates)))
        response = self.client.put('/api/sqm', headers=self.headers, json={
            'interface': 'eth0', 'enabled': True, 'download': 30000, 'upload': 15000,
            'qdisc': 'cake', 'script': 'piece_of_cake.qos'})
        self.assertEqual(response.status_code, 200, response.get_json())
        self.assertEqual(app._load_sqm_conditional('eth0')['baseline'],
                         {'download': 240000, 'upload': 120000})
        data = self.client.get('/api/sqm?refresh=1&interface=eth0', headers=self.headers).get_json()
        self.assertEqual(data['config']['download'], '1000')
        self.assertEqual(data['baseline_config']['download'], '30000')
        app._today_wan_traffic_total.return_value = ('2099-01-01', 0)
        app._reconcile_sqm_conditional(force=True, interface='eth0')
        self.assertEqual(self.calls[-1], ('eth0', {'download': 240000, 'upload': 120000}))

    def test_partial_apply_keeps_restore_point_for_retry_after_restart(self):
        self.policy('eth0')
        def partial(iface, rates):
            self.queues[-1].update({k: str(v) for k, v in rates.items()})
            return False, 'verification failed'
        app._daily_sqm_set_rates.side_effect = partial
        self.assertFalse(app._reconcile_sqm_conditional(force=True)[0])
        self.assertEqual(app._load_sqm_conditional('eth0')['baseline'],
                         {'download': 200000, 'upload': 80000})
        app._daily_sqm_set_rates.side_effect = None
        app._daily_sqm_set_rates.return_value = (True, '')
        self.assertEqual(self.client.put('/api/sqm/conditional', headers=self.headers,
            json={'interface': 'eth0', 'enabled': False}).status_code, 200)
        app._daily_sqm_set_rates.assert_called_with('eth0', {'download': 200000, 'upload': 80000})

    def test_missing_disabled_non_cake_duplicate_wan_never_falls_back_to_lan(self):
        original = copy.deepcopy(self.queues)
        for queues in (original[:-1], [*original[:-1], {**original[-1], 'enabled': '0'}],
                       [*original[:-1], {**original[-1], 'qdisc': 'fq_codel'}],
                       [*original, {**original[-1], 'section': 'duplicate'}]):
            app._read_sqm_queues.side_effect = None
            app._read_sqm_queues.return_value = (queues, '')
            response = self.client.put('/api/sqm/conditional', headers=self.headers,
                json={'interface': 'eth0', 'enabled': True})
            self.assertEqual(response.status_code, 409, response.get_json())
        self.assertEqual(self.calls, [])
        self.assertEqual(app._load_sqm_conditional_store()['rules'], {})

    def test_shared_rates_must_preserve_positive_wan_aggregate(self):
        for key in ('download', 'upload'):
            response = self.client.put('/api/sqm/conditional', headers=self.headers,
                json={'interface': 'eth0', 'force_today': True, key: 0})
            self.assertEqual(response.status_code, 400)
        self.assertEqual(self.calls, [])

    def test_shared_dispatch_updates_root_then_refreshes_managed_wan_owner(self):
        rates = {'download': 20000, 'upload': 8000}
        setter = self.patch('_set_sqm_rates', Mock(return_value=(True, '')))
        refresh = self.patch('_refresh_punishment', Mock(return_value=(True, 'verified')))
        with patch.object(app, '_daily_sqm_set_rates', daily.DailyInterfaceTests._real_set):
            self.assertEqual(app._daily_sqm_set_rates('eth0', rates), (True, 'verified'))
            setter.assert_called_once_with(rates, 'eth0')
            refresh.assert_called_once_with()
            setter.return_value = (False, 'write failed')
            refresh.reset_mock()
            self.assertEqual(app._daily_sqm_set_rates('eth0', rates), (False, 'write failed'))
            refresh.assert_not_called()

    def test_all_wan_midnight_uses_current_date_even_with_old_sample(self):
        stamp = int(time.time())
        self.patch('_wan_traffic_data', {'started_at': stamp - 100, 'updated_at': stamp - 86400,
            'days': {self.day: {'download': 7, 'upload': 11}, '2000-01-01': {'download': GB}},
            'months': {}, 'history': [], 'minute_history': []})
        with patch.object(app, '_today_wan_traffic_total', SharedWanTests._real_usage):
            self.assertEqual(app._today_wan_traffic_total(), (self.day, 18))
            app._wan_traffic_data['days'].pop(self.day)
            self.assertEqual(app._today_wan_traffic_total(), (self.day, 0))

    def test_shared_ceiling_retains_lan_and_device_caps_with_stable_identities(self):
        qos = wan.qos
        identity = qos.identities({}, wan.NETWORKS, wan.CLIENTS)
        profiles = {wan.MAC: {'download_cap': 40000, 'upload_cap': 10000},
                    wan.SECOND: {'download_cap': 8000, 'upload_cap': 4000}}
        daily_rates = {'br-lan': {'download': 16000, 'upload': 30000}}
        normal = qos.nodes(wan.NETWORKS, wan.CLIENTS, profiles, daily_rates, identity, wan.TOTALS)
        limited = qos.nodes(wan.NETWORKS, wan.CLIENTS, profiles, daily_rates, identity,
                            {'download': 20000000, 'upload': 10000000})
        first, second = (format(identity['client_ids'][mac], 'x') for mac in (wan.MAC, wan.SECOND))
        self.assertEqual(normal['download'][first]['ceil'], 30000000)
        self.assertEqual(limited['download'][first]['ceil'], 20000000)
        self.assertEqual(limited['download'][second]['ceil'], 8000000)
        commands = qos.plan({'download': 'ifb4eth0', 'upload': 'eth0'}, wan.realized(normal), limited)
        self.assertTrue(commands)
        self.assertFalse(any(' root ' in command or 'filter' in command for command in commands))
        self.assertEqual(set(normal['download']), set(limited['download']))
        self.assertEqual(qos.nodes(wan.NETWORKS, wan.CLIENTS, profiles, daily_rates, identity, wan.TOTALS), normal)

    _real_usage = staticmethod(app._today_wan_traffic_total)


class SqmNameTests(unittest.TestCase):
    setUp = daily.DailyInterfaceTests.setUpBase
    patch = daily.DailyInterfaceTests.patch

    def test_names_persist_independently_without_router_reads_or_writes(self):
        for iface, name in [('eth0', ' Internet '), ('br-lan', 'Home')]:
            response = self.client.put('/api/sqm/name', headers=self.headers,
                                       json={'interface': iface, 'name': name})
            self.assertEqual(response.status_code, 200)
        self.assertEqual(app._load_sqm_names(), {'eth0': 'Internet', 'br-lan': 'Home'})
        self.client.put('/api/sqm/name', headers=self.headers, json={'interface': 'eth0', 'name': ''})
        self.assertEqual(app._load_sqm_names(), {'br-lan': 'Home'})
        self.assertEqual(self.commands, [])

    def test_invalid_names_and_interfaces_do_not_overwrite_saved_values(self):
        app._save_json(app.SQM_NAMES_FILE, {'eth0': 'Internet'})
        for body in ([], {'interface': 'eth0', 'name': 'x'*65}, {'interface': 'eth0', 'name': 7},
                     {'interface': 'eth0', 'name': 'bad\nname'}, {'interface': 'eth0;reboot', 'name': 'WAN'},
                     {'interface': 'lo', 'name': 'Loopback'}, {'interface': 'ifb4eth0', 'name': 'IFB'}):
            self.assertEqual(self.client.put('/api/sqm/name', headers=self.headers, json=body).status_code, 400)
        self.assertEqual(app._load_sqm_names(), {'eth0': 'Internet'})
        self.assertEqual(self.commands, [])


class SqmOffTests(unittest.TestCase):
    setUpBase = daily.DailyInterfaceTests.setUpBase
    patch = daily.DailyInterfaceTests.patch
    state = daily.DailyInterfaceTests.state
    policy = daily.DailyInterfaceTests.policy

    def setUp(self):
        daily.DailyInterfaceTests.setUp(self)
        for queue in self.queues:
            queue.update(qdisc='cake', script='piece_of_cake.qos')
        self.patch('_router_interfaces', Mock(return_value=['br-lan', 'eth2', 'eth0']))
        self.refresh = self.patch('_refresh_punishment', Mock(return_value=(True, 'verified')))
        def save(queue, settings):
            queue.update({key: str(value) for key, value in settings.items()})
            return True, ''
        self.save = self.patch('_save_extra_sqm', Mock(side_effect=save))
        self.patch('_set_sqm_rates', Mock(side_effect=lambda rates, iface=None: save(
            next(q for q in self.queues if q['interface'] == (iface or 'br-lan')), rates)))

    def body(self, enabled=False):
        return {'interface': 'eth2', 'enabled': enabled, 'download': 6250, 'upload': 6250,
                'qdisc': 'cake', 'script': 'piece_of_cake.qos'}

    def test_queue_off_disables_active_daily_without_restoring_stopped_queue(self):
        self.policy('br-lan')
        other = app._load_sqm_conditional('br-lan')
        original = self.policy('eth2', active=True, placement='lan', forced_date=self.day,
                               baseline={'download': 50000, 'upload': 50000})
        response = self.client.put('/api/sqm', headers=self.headers, json=self.body())
        self.assertEqual(response.status_code, 200, response.get_json())
        rule = app._load_sqm_conditional('eth2')
        for flag in ('enabled', 'active'):
            self.assertFalse(rule[flag])
        for key in ('threshold_gb', 'download', 'upload'):
            self.assertEqual(rule[key], original[key])
        self.assertEqual(rule['forced_date'], '')
        self.assertEqual(rule['baseline'], {})
        self.assertEqual(rule['error'], '')
        self.assertEqual(app._load_sqm_conditional('br-lan'), other)
        self.assertEqual(self.queues[1]['enabled'], '0')
        app._daily_sqm_set_rates.assert_not_called()

    def test_failed_stop_keeps_daily_policy_and_returns_real_error(self):
        before = self.policy('eth2', forced_date=self.day)
        self.save.side_effect = None
        self.save.return_value = (False, 'stop failed')
        response = self.client.put('/api/sqm', headers=self.headers, json=self.body())
        self.assertEqual(response.status_code, 502)
        self.assertEqual(app._load_sqm_conditional('eth2'), before)
        self.refresh.assert_not_called()

    def test_reenable_baseline_keeps_daily_off(self):
        self.policy('eth2', forced_date=self.day)
        self.assertTrue(self.client.put('/api/sqm', headers=self.headers, json=self.body()).get_json()['ok'])
        self.assertTrue(self.client.put('/api/sqm', headers=self.headers, json=self.body(True)).get_json()['ok'])
        self.assertFalse(app._load_sqm_conditional('eth2')['enabled'])
        self.assertFalse(app._load_sqm_conditional('eth2')['active'])
        app._daily_sqm_set_rates.assert_not_called()

    def test_daily_cannot_enable_with_own_baseline_off_even_if_wan_available(self):
        self.queues[1]['enabled'] = '0'
        self.queues.append({'interface': 'eth0', 'enabled': '1', 'qdisc': 'cake',
                            'download': '100000', 'upload': '100000'})
        response = self.client.put('/api/sqm/conditional', headers=self.headers,
                                   json={'interface': 'eth2', 'enabled': True})
        self.assertEqual(response.status_code, 409)
        self.assertIn('Baseline', response.get_json()['output'])

    def test_successful_stop_with_other_queue_failure_returns_saved_and_diagnostic(self):
        self.refresh.return_value = (False, 'Other queue verification failed')
        response = self.client.put('/api/sqm', headers=self.headers, json=self.body())
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.get_json()['ok'])
        self.assertIn('verification', response.get_json()['tc_error'])
        self.assertEqual(self.queues[1]['enabled'], '0')

    def test_intentionally_off_lan_does_not_attempt_recovery_and_retains_client_note(self):
        self.queues[1]['enabled'] = '0'
        mac = daily.SECOND
        self.patch('_managed_tc_clients', Mock(return_value={mac: {'interface': 'eth2'}}))
        self.patch('_publish_qos_status', Mock())
        apply = self.patch('_apply_punishment_qdisc', Mock())
        app._save_punishment_tc_state({'active': True, 'error': 'old queue failed',
                                     'bindings': {mac: {'minor': '100', 'priority': 100}}}, 'eth2')
        ok, message = app._reconcile_punishment({'punished': []}, {'default': {}, 'devices': {}}, [], set(), set())
        self.assertTrue(ok, message)
        apply.assert_not_called()
        state = app._punishment_tc_state('eth2')
        self.assertFalse(state['active'])
        self.assertEqual(state['error'], '')
        self.assertIn('SQM off', state['pending'][mac])
        self.assertEqual(state['bindings'][mac]['minor'], '100')

    def test_off_status_is_explicit_and_does_not_claim_active_caps(self):
        self.queues[1]['enabled'] = '0'
        routes, error = app._qos_placements(self.queues)
        self.patch('_punishment_interfaces', Mock(return_value=(None, 'not inspected')))
        app._publish_qos_status(self.queues, routes, {daily.SECOND: {'interface': 'eth2'}})
        row = next(row for row in app._qos_status_data['networks'] if row['interface'] == 'eth2')
        self.assertEqual(row['state'], 'off')
        self.assertIn('inactive', row['message'])
        self.assertEqual(row['clients'], 1)


class SqmQueueStatusTests(unittest.TestCase):
    setUp = daily.DailyInterfaceTests.setUp
    setUpBase = daily.DailyInterfaceTests.setUpBase
    patch = daily.DailyInterfaceTests.patch
    state = daily.DailyInterfaceTests.state

    def publish(self, active=False, error=''):
        for queue in self.queues:
            queue.update(enabled='0', qdisc='cake')
        self.queues.append({'interface': 'eth0', 'enabled': '1', 'qdisc': 'cake',
                            'download': '100000', 'upload': '50000'})
        self.state('SQM_NAMES_FILE', {'eth0': 'Internet'})
        self.state('WAN_QOS_FILE', {'installed': True, 'active': active, 'error': error,
                                  'verified_at': time.time() if active else 0})
        routes, _ = app._qos_placements(self.queues)
        app._publish_qos_status(self.queues, routes, {})
        return app._qos_status_data

    def test_queue_rows_match_actual_interfaces_and_assign_wan_error_to_wan_only(self):
        data = self.publish(error='classifier failed')
        rows = {row['interface']: row for row in data['queues']}
        self.assertEqual(set(rows), {'br-lan', 'eth2', 'eth0'})
        self.assertEqual(rows['br-lan']['state'], 'off')
        self.assertEqual(rows['eth2']['state'], 'off')
        self.assertEqual(rows['br-lan']['message'], '')
        self.assertEqual(rows['eth0']['state'], 'error')
        self.assertEqual(rows['eth0']['message'], 'classifier failed')
        self.assertEqual(rows['eth0']['name'], 'Internet')
        self.assertEqual(rows['eth0']['download'], '12500')
        self.assertEqual(rows['eth0']['upload'], '6250')
        self.assertTrue(all(row['placement'] == 'wan' for row in data['networks']))

    def test_verified_wan_is_active_and_cached_api_never_reads_router(self):
        data = self.publish(active=True)
        self.assertEqual(data['queues'][-1]['state'], 'active')
        app.ssh.reset_mock()
        response = self.client.get('/api/qos/status', headers=self.headers).get_json()
        self.assertEqual(response['queues'][-1]['state'], 'active')
        app.ssh.assert_not_called()

    def test_stale_queue_checks_cannot_claim_active(self):
        self.publish(active=True)
        app._qos_status_data['checked_at'] = time.time() - 100
        response = self.client.get('/api/qos/status', headers=self.headers).get_json()
        self.assertTrue(response['stale'])
        self.assertEqual(response['queues'][-1]['state'], 'unknown')


if __name__ == '__main__':
    unittest.main()
