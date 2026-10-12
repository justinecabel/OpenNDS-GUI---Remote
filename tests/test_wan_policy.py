"""WAN ownership, policy isolation, verification and failure recovery; offline."""
import copy
import time
import unittest
from unittest.mock import Mock, patch

import test_optimization as optimization
import test_tc_interfaces as tc
import wan_shaping as qos

app, MAC, SECOND = optimization.app, optimization.MAC, optimization.SECOND
QUEUE = {'interface': 'eth0', 'enabled': '1', 'qdisc': 'cake', 'download': '100000', 'upload': '50000'}
NETWORKS = {'br-lan': {'subnets': ['192.168.1.0/24']}, 'eth2': {'subnets': ['10.0.0.0/24']}}
CLIENTS = {MAC: {'interface': 'br-lan', 'ip': '192.168.1.99'}, SECOND: {'interface': 'eth2', 'ip': '10.0.0.100'}}
TOTALS = {'download': 100000000, 'upload': 50000000}


def realized(specs):
    """Kernel-style read fixture, separate from proposed shell commands."""
    layouts = {}
    for direction, nodes in specs.items():
        classes, qdiscs, filters = {}, {'root': {'kind': 'htb', 'handle': qos.MAJOR, 'options': 'root default 0x10'}}, {}
        for minor, node in nodes.items():
            cid = qos.MAJOR + ':' + minor
            classes[cid] = {key: node[key] for key in ('parent', 'rate', 'ceil')}
            if 'kind' in node:
                parameters = f'bandwidth {node["ceil"]}bit besteffort nat' if node['kind'] == 'cake' else f'delay {node["delay_ms"]}ms loss {node["loss_pct"]}%'
                qdiscs[cid] = {'kind': node['kind'], 'handle': minor, 'options': f'parent {cid} {parameters}'}
                if minor != '10':
                    value = int(minor, 16)
                    filters[cid] = {'priority': value, 'mark': value << 20, 'mask': qos.MASK}
        layouts[direction] = {'classes': classes, 'qdiscs': qdiscs, 'filters': filters}
    return layouts


class WanPlannerTests(unittest.TestCase):
    def setUp(self):
        self.state = qos.identities({}, NETWORKS, CLIENTS)

    def test_disabled_lan_sections_do_not_block_wan(self):
        queues = [{**QUEUE, 'interface': 'br-lan', 'enabled': '0'}, QUEUE]
        routes = qos.placements(queues, NETWORKS, 'eth0')
        self.assertEqual({r['placement'] for r in routes.values()}, {'wan'})

    def test_enabled_lan_precedes_wan_and_other_lan_uses_wan(self):
        routes = qos.placements([{**QUEUE, 'interface': 'br-lan'}, QUEUE], NETWORKS, 'eth0')
        self.assertEqual(routes['br-lan']['placement'], 'lan')
        self.assertEqual(routes['eth2']['placement'], 'wan')

    def test_ambiguous_non_cake_disabled_or_zero_rate_queue_is_not_ready(self):
        for queues in [[QUEUE, QUEUE], [{**QUEUE, 'qdisc': 'fq_codel'}],
                       [{**QUEUE, 'enabled': '0'}], [{**QUEUE, 'download': '0'}]]:
            with self.subTest(queues=queues):
                self.assertEqual(qos.placements(queues, NETWORKS, 'eth0')['eth2']['placement'], 'unavailable')

    def test_enabled_non_cake_lan_does_not_silently_move_to_wan(self):
        routes = qos.placements([{**QUEUE, 'interface': 'br-lan', 'qdisc': 'fq_codel'}, QUEUE], NETWORKS, 'eth0')
        self.assertEqual(routes['br-lan']['placement'], 'unavailable')

    def test_ids_survive_departure_restart_and_client_move(self):
        saved = copy.deepcopy(self.state)
        moved = {MAC: {'interface': 'eth2', 'ip': '10.0.0.101'}}
        self.assertEqual(qos.identities(saved, NETWORKS, moved), saved)
        other = qos.identities(saved, NETWORKS, {**moved, '02:00:00:00:00:97': {}})
        self.assertEqual(other['client_ids'][MAC], saved['client_ids'][MAC])
        self.assertEqual(len(set(other['client_ids'].values())), 3)

    def test_corrupt_identity_state_is_rejected_before_writes(self):
        self.state['client_ids'][MAC] = self.state['client_ids'][SECOND]
        with self.assertRaises(ValueError):
            qos.identities(self.state, NETWORKS, CLIENTS)

    def test_daily_parent_rates_are_independent_and_direction_is_correct(self):
        nodes = qos.nodes(NETWORKS, CLIENTS, {}, {'eth2': {'download': 8000, 'upload': 16000}}, self.state, TOTALS)
        parent = format(self.state['lan_ids']['eth2'], 'x')
        primary = format(self.state['lan_ids']['br-lan'], 'x')
        self.assertEqual(nodes['download'][parent]['ceil'], 16000000)
        self.assertEqual(nodes['upload'][parent]['ceil'], 8000000)
        self.assertEqual(nodes['download'][primary]['ceil'], TOTALS['download'])

    def test_client_caps_are_bounded_by_lan_and_global_parents(self):
        nodes = qos.nodes(NETWORKS, CLIENTS, {SECOND: {'download_cap': 40000}},
                          {'eth2': {'download': 8000, 'upload': 16000}}, self.state, TOTALS)
        leaf = format(self.state['client_ids'][SECOND], 'x')
        self.assertEqual(nodes['download'][leaf]['ceil'], 16000000)

    def test_nft_identity_is_scoped_to_wan_and_preserves_low_mark_bits(self):
        rules, digest = qos.nft_rules('eth0', NETWORKS, CLIENTS, self.state)
        self.assertIn('iifname "eth2" oifname "eth0" ip saddr 10.0.0.100', rules)
        self.assertIn('iifname "eth0" oifname "eth2" ip daddr 10.0.0.100', rules)
        self.assertNotIn('iifname "eth2" oifname "br-lan"', rules)
        self.assertIn('ct mark & 0xfffff', rules)
        self.assertIn('manager-' + digest, rules)

    def test_wan_filters_use_connmarks_instead_of_private_ip_headers(self):
        nodes = qos.nodes(NETWORKS, CLIENTS, {}, {}, self.state, TOTALS)
        plain = {direction: qos.parse(f'qdisc cake 800a: root bandwidth {rate}bit besteffort nat') for direction, rate in TOTALS.items()}
        commands = qos.plan({'download': 'ifb-test', 'upload': 'eth0'}, plain, nodes)
        text = ';'.join(commands)
        self.assertIn(' fw classid ', text)
        self.assertIn('/0xfff00000', text)
        self.assertNotIn('match ip', text)
        self.assertEqual(qos.plan({'download': 'ifb-test', 'upload': 'eth0'}, realized(nodes), nodes), [])

    def test_cake_to_netem_deletes_leaf_before_reusing_handle(self):
        initial = qos.nodes(NETWORKS, CLIENTS, {}, {}, self.state, TOTALS)
        changed = qos.nodes(NETWORKS, CLIENTS, {MAC: {'delay_ms': 100, 'loss_pct': '1'}}, {}, self.state, TOTALS)
        commands = qos.plan({'download': 'ifb-test', 'upload': 'eth0'}, realized(initial), changed)
        self.assertIn('qdisc delete', commands[0])
        self.assertIn('qdisc add', commands[1])
        self.assertIn('netem delay 100ms loss 1%', commands[1])
        self.assertFalse(any(' root ' in c for c in commands))

    def test_both_directions_preflight_before_any_root_changes(self):
        nodes = qos.nodes(NETWORKS, CLIENTS, {}, {}, self.state, TOTALS)
        plain = {direction: qos.parse('qdisc cake 800a: root bandwidth 100Mbit besteffort') for direction in TOTALS}
        plain['upload'] = qos.parse('qdisc fq_codel 0: root')
        with self.assertRaises(ValueError):
            qos.plan({'download': 'ifb-test', 'upload': 'eth0'}, plain, nodes)

    def test_foreign_ingress_priority_is_not_overwritten(self):
        with self.assertRaises(ValueError):
            qos.ingress_status('filter protocol ip pref 1 u32 fh 800::1\n action mirred')
        owned = 'filter protocol ip pref 1 u32 fh 800::1\n action ctinfo cpmark 0xfff00000 continue\n'
        with self.assertRaises(ValueError):
            qos.ingress_status(owned + 'filter protocol all pref 1 matchall\n action mirred')
        with self.assertRaises(ValueError):
            qos.ingress_status(owned + 'filter protocol ip pref 1 u32 fh 800::2\n action mirred')

    def test_kernel_text_parser_recognizes_masked_fw_filters_and_rates(self):
        text = '''qdisc htb 7ea0: root default 0x10
class htb 7ea0:1 root rate 100Mbit ceil 100Mbit
class htb 7ea0:201 parent 7ea0:20 leaf 201: rate 1Kbit ceil 4Mbit
filter parent 7ea0: protocol ip pref 513 fw chain 0 handle 0x20100000/0xfff00000 classid 7ea0:201'''
        parsed = qos.parse(text)
        self.assertEqual(parsed['classes']['7ea0:201'], {'parent': '7ea0:20', 'rate': 1000, 'ceil': 4000000})
        self.assertEqual(parsed['filters']['7ea0:201']['mask'], qos.MASK)


class WanRuntimeTests(unittest.TestCase):
    setUpBase = optimization.OptimizationTests.setUp
    patch = optimization.OptimizationTests.patch
    state = optimization.OptimizationTests.state

    def setUp(self):
        tc.TrafficInterfaceTests.setUp(self)
        self.patch('WAN_IFACE', 'eth0')
        self.patch('_read_sqm_queues', Mock(return_value=([QUEUE], '')))
        self.desired = app._managed_tc_clients(self.clients, tc.POLICY, tc.LIMITS, set(), set())
        self.bound = app._wan_qos_clients(self.clients, NETWORKS)
        self.identity = qos.identities({}, NETWORKS, self.bound)
        self.specs = qos.nodes(NETWORKS, self.bound, self.desired, {}, self.identity, TOTALS)
        self.rules, self.digest = qos.nft_rules('eth0', NETWORKS, self.bound, self.identity)
        self.ingress = 'filter pref 10 matchall\n Egress Redirect to device ifb4eth0)\n'
        self.owned = self.ingress + 'filter pref 1 u32 fh 800::1\n action ctinfo cpmark 0xfff00000 continue\n'
        def fake_ssh(command, data=None, timeout=15):
            self.commands.append(command)
            if '@@OFFLOAD' in command:
                return 0, (self.ingress + '@@OFFLOAD\n0\n0\n@@CTINFO\nloaded\n@@NFT\ncomment "manager-' + self.digest+'"').encode(), ''
            if '@@NFT' in command:
                return 0, (self.owned + '@@NFT\nmanager-' + self.digest).encode(), ''
            return 0, b'', ''
        self.patch('ssh', Mock(side_effect=fake_ssh))
        p = patch.object(qos, 'inspect', Mock(return_value=realized(self.specs)))
        self.inspect = p.start();self.addCleanup(p.stop)

    def test_active_requires_verified_classes_and_ingress_connmarks(self):
        self.assertTrue(app._apply_wan_qos(QUEUE, NETWORKS, self.clients, self.desired)[0])
        state = app._wan_qos_state()
        self.assertTrue(state['active'])
        self.assertGreater(state['verified_at'], 0)
        self.assertEqual(state['interfaces'], {'download': 'ifb4eth0', 'upload': 'eth0'})

    def test_missing_ingress_verification_never_claims_active(self):
        original = app.ssh.side_effect
        app.ssh.side_effect = lambda command, **kw: (0, (self.ingress+'@@NFT\nmanager-'+self.digest).encode(), '') if '@@NFT' in command and '@@OFFLOAD' not in command else original(command, **kw)
        self.assertFalse(app._apply_wan_qos(QUEUE, NETWORKS, self.clients, self.desired)[0])
        self.assertFalse(app._wan_qos_state()['active'])
        self.assertEqual(app._wan_qos_state()['verified_at'], 0)

    def test_unapplied_classes_remain_pending_despite_successful_command_exit(self):
        plain = {direction: qos.parse(f'qdisc cake 800a: root bandwidth {rate}bit besteffort nat') for direction, rate in TOTALS.items()}
        self.inspect.return_value = plain
        ok, message = app._apply_wan_qos(QUEUE, NETWORKS, self.clients, self.desired)
        self.assertFalse(ok)
        self.assertIn('verification pending', message)

    def test_flow_offloading_reports_error_without_mutating_queues(self):
        original = app.ssh.side_effect
        app.ssh.side_effect = lambda command, **kw: (0, (self.ingress+'@@OFFLOAD\n1\n@@CTINFO\nloaded\n@@NFT\n').encode(), '') if '@@OFFLOAD' in command else original(command, **kw)
        self.assertFalse(app._apply_wan_qos(QUEUE, NETWORKS, self.clients, self.desired)[0])
        self.assertFalse(any('tc class add' in c or 'nft -f' in c for c in self.commands))

    def test_foreign_wan_table_is_rejected_before_router_mutations(self):
        app.ssh.side_effect = lambda command, **kw: (0, (self.ingress+'@@OFFLOAD\n0\n0\n@@CTINFO\nloaded\n@@NFT\ntable inet nds_mgr_wan_qos { }').encode(), '')
        self.assertFalse(app._apply_wan_qos(QUEUE, NETWORKS, self.clients, self.desired)[0])
        self.assertEqual(app.ssh.call_count, 1)

    def test_filter_ownership_conflict_cannot_trigger_disruptive_recovery(self):
        broken = realized(self.specs)
        cid = '7ea0:' + format(self.identity['client_ids'][MAC], 'x')
        broken['upload']['filters'][cid]['mark'] = 123
        self.inspect.return_value = broken
        restart = self.patch('_restart_sqm', Mock())
        ok, message = app._apply_wan_qos(QUEUE, NETWORKS, self.clients, self.desired)
        self.assertFalse(ok)
        self.assertIn('ownership conflict', message)
        restart.assert_not_called()

    def test_status_get_has_no_router_reads_and_stale_active_becomes_unknown(self):
        app._qos_status_data = {'checked_at': time.time()-60, 'queues': [], 'networks': [
            {'interface': 'eth2', 'placement': 'wan', 'state': 'active', 'verified_at': time.time()-60}]}
        response = self.client.get('/api/qos/status', headers=self.headers)
        self.assertTrue(response.get_json()['stale'])
        self.assertEqual(response.get_json()['networks'][0]['state'], 'unknown')
        self.assertEqual(self.commands, [])

    def test_wan_pending_message_is_reported_on_secondary_client(self):
        self.state('WAN_QOS_FILE', {'error': 'ctinfo unavailable'})
        app._qos_status_data['networks'] = [{'interface': 'eth2', 'placement': 'wan'}]
        self.assertEqual(app._session_pending(self.clients[1], {})['tc_pending_message'], 'ctinfo unavailable')

    def test_daily_rule_no_longer_throttles_after_disable_even_with_saved_wan_rates(self):
        self.state('WAN_QOS_FILE', {'daily_rates': {'eth2': {'download': 1000, 'upload': 1000}}})
        self.assertEqual(app._wan_daily_targets(NETWORKS)['eth2'], {'download': 0, 'upload': 0})

    def test_missing_discovered_subnets_cannot_silently_claim_wan_placement(self):
        self.patch('_sqm_daily_interfaces', Mock(return_value={'br-lan': 'lan', 'eth2': 'piso'}))
        self.patch('_network_state', Mock(return_value={'networks': []}))
        apply = self.patch('_apply_wan_qos', Mock())
        ok, message = app._reconcile_punishment(tc.POLICY, tc.LIMITS, self.clients, set(), set())
        self.assertFalse(ok)
        self.assertIn('discovered LAN subnets', message)
        apply.assert_not_called()
        self.assertEqual({r['state'] for r in app._qos_status_data['networks']}, {'error'})

    def test_wan_bandwidth_only_save_preserves_shared_roots_until_immediate_reconcile(self):
        interfaces = {'download': 'ifb4eth0', 'upload': 'eth0'}
        self.state('WAN_QOS_FILE', {'installed': True, 'interfaces': interfaces})
        self.patch('_punishment_interfaces', Mock(return_value=(interfaces, '')))
        restart = self.patch('_restart_sqm', Mock())
        self.assertTrue(app._set_sqm_rates({'download': 24000, 'upload': 8000}, 'eth0')[0])
        self.assertIn('uci set sqm."$sqm_primary".download=24000', self.commands[-1])
        self.assertNotIn('tc qdisc', self.commands[-1])
        restart.assert_not_called()

    def test_cleanup_removes_only_owned_classification_and_verifies_removal(self):
        self.state('WAN_QOS_FILE', {'installed': True, 'wan': 'eth0'})
        app.ssh.side_effect = [(0, (self.owned+'@@NFT\ncomment "manager-'+self.digest+'"').encode(), ''),
                               (0, b'', ''), (0, (self.ingress+'@@NFT\n').encode(), '')]
        restart = self.patch('_restart_sqm', Mock(return_value=(True, '')))
        self.assertTrue(app._wan_qos_cleanup()[0])
        delete = app.ssh.call_args_list[1].args[0]
        self.assertTrue(delete.startswith('set -e; nft delete'))
        self.assertNotIn('|| :', delete)
        self.assertNotIn('firewall restart', delete)
        restart.assert_called_once_with(interface='eth0')
        self.assertFalse(app._wan_qos_state()['installed'])

    def test_cleanup_failure_keeps_retry_ownership_and_cannot_claim_success(self):
        self.state('WAN_QOS_FILE', {'installed': True, 'wan': 'eth0'})
        app.ssh.side_effect = [(0, (self.owned+'@@NFT\ncomment "manager-'+self.digest+'"').encode(), ''),
                               (1, b'', 'nft delete failed')]
        self.assertFalse(app._wan_qos_cleanup()[0])
        self.assertTrue(app._wan_qos_state()['installed'])
        self.assertEqual(app._wan_qos_state()['error'], 'nft delete failed')

    def test_cleanup_foreign_table_is_not_deleted(self):
        self.state('WAN_QOS_FILE', {'installed': True, 'wan': 'eth0'})
        app.ssh.side_effect = [(0, (self.ingress+'@@NFT\ntable inet nds_mgr_wan_qos { }').encode(), '')]
        self.assertFalse(app._wan_qos_cleanup()[0])
        self.assertEqual(app.ssh.call_count, 1)


if __name__ == '__main__':
    unittest.main()
