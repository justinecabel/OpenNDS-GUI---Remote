"""Dynamic LAN discovery, generated rules and scoped behavior changes."""
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import Mock
import network_policy
import test_optimization as optimization

app, MAC, SECOND = optimization.app, optimization.MAC, optimization.SECOND


def topology():
    dump = {"interface": [
        {"interface": name, "l3_device": dev, "proto": proto, "up": True,
         "ipv4-address": [{"address": addr, "mask": 24}],
         "route": [{"mask": 0, "nexthop": "198.51.100.1"}] if proto == "dhcp" else []}
        for name, dev, proto, addr in [
            ("office", "br-office", "static", "172.16.5.1"),
            ("visitors", "br-guest.37", "static", "172.20.7.1"),
            ("uplink", "eth9", "dhcp", "198.51.100.2")]]}
    firewall = {name: {".type": "zone", "name": zone, "network": [name], "masq": masq}
                for name, zone, masq in [("office", "inside", "0"), ("visitors", "guests", "0"), ("uplink", "internet", "1")]}
    dhcp = {name: {".type": "dhcp", ".name": "pool_" + name, "interface": name, "ignore": "0"}
            for name in ("office", "visitors")}
    meta = {"gatewayaddress": "172.16.5.1", "gatewayfqdn": "login.office.test", "version": "10.3.1",
            "fasremoteip": "172.16.5.200", "fasport": "8090", "faspath": "/fas", "gatewayport": "2051"}
    return dump, firewall, dhcp, meta


def discovery(modes=None):
    data = network_policy.discover(*topology())
    modes = modes or {"office": "auto_auth", "visitors": "portal"}
    data.update(modes=modes, initialized=True)
    for row in data["networks"]:
        row["mode"] = modes.get(row["name"], "unmanaged")
    return data


class NetworkDiscoveryTests(unittest.TestCase):
    def test_discovers_arbitrary_lan_names_vlan_devices_and_upstream(self):
        data = discovery()
        office, guests, upstream = data["networks"]
        self.assertEqual(data["primary_device"], "br-office")
        self.assertTrue(office["eligible"])
        self.assertTrue(guests["eligible"])
        self.assertEqual(guests["subnets"], ["172.20.7.0/24"])
        self.assertFalse(upstream["eligible"])
        self.assertEqual(upstream["reason"], "Upstream / WAN")

    def test_disabled_dhcp_and_unknown_zone_are_not_eligible(self):
        dump, firewall, dhcp, meta = topology()
        dhcp['visitors']['ignore'] = '1'
        self.assertIn('DHCP', network_policy.discover(dump, firewall, dhcp, meta)['networks'][1]['reason'])
        dhcp['visitors']['ignore'] = '0'
        del firewall['visitors']
        self.assertIn('firewall zone', network_policy.discover(dump, firewall, dhcp, meta)['networks'][1]['reason'])

    def test_overlapping_subnets_disable_both_networks(self):
        dump, firewall, dhcp, meta = topology()
        dump['interface'][1]['ipv4-address'][0]['address'] = '172.16.5.2'
        rows = network_policy.discover(dump, firewall, dhcp, meta)['networks']
        self.assertFalse(rows[0]['eligible'])
        self.assertFalse(rows[1]['eligible'])

    def test_validates_requests_against_current_discovery(self):
        data = discovery()
        for modes in ({'uplink': 'portal'}, {'gone': 'portal'}, {'office': 'unmanaged'}, {'visitors': 'bad'}, None):
            with self.assertRaises(ValueError):
                network_policy.validate_modes(data, modes)

    def test_generated_rules_use_discovered_gateway_fas_zone_and_vlan(self):
        config = network_policy.compile_config(discovery(), {'office': 'auto_auth', 'visitors': 'portal'})
        self.assertIn('extra br-guest.37', config['devices'])
        self.assertIn('172.20.7.0/24', config['guard'])
        self.assertIn('snat ip to 172.16.5.1', config['guard'])
        self.assertIn('tcp dport 8090', config['guard'])
        self.assertEqual(config['dhcp'], {'pool_visitors': '114,http://login.office.test'})
        self.assertTrue(any(r.get('dest') == 'internet' for r in config['firewall'].values()))
        serialized = json.dumps(config)
        for hardcoded in ('eth2', 'br-lan', '10.0.0.', '192.168.1.'):
            self.assertNotIn(hardcoded, serialized)

    def test_unmanaged_removes_attachment_but_keeps_native_device(self):
        config = network_policy.compile_config(discovery(), {'office': 'portal', 'visitors': 'unmanaged'})
        self.assertEqual(config['devices'], 'primary br-office\n')
        self.assertEqual(config['firewall'], {})
        self.assertNotIn('iifname', config['guard'])

    def test_install_transaction_has_rollback_and_never_restarts_opennds(self):
        config = network_policy.compile_config(discovery(), {'office': 'auto_auth', 'visitors': 'portal'})
        script = network_policy.install_script(config)
        self.assertIn('dispatch-rollback.nft', script)
        self.assertIn('trap rollback EXIT', script)
        self.assertNotIn('/etc/init.d/opennds restart', script)
        self.assertIn('[ "$(pidof opennds)" = "$old_pid" ]', script)

    def test_installed_assets_match_discovery_hashes_byte_for_byte(self):
        data = discovery()
        config = network_policy.compile_config(data, data['modes'])
        script = network_policy.install_script(config)
        # Execute only staged file writes in a temporary directory, never the
        # firewall/UCI/service transaction. Include every generated asset.
        writes = list(re.finditer(r"printf '%s' .*? > (/[^\n]+\.manager-new)\nchmod ", script, re.S))
        self.assertEqual(len(writes), 5)
        expected = {
            'libopennds.sh': (Path(network_policy.__file__).parent / 'router/libopennds-extra-wrapper.sh').read_bytes(),
            'opennds-extra-interface.sh': (Path(network_policy.__file__).parent / 'router/opennds-extra-interface.sh').read_bytes(),
            'opennds-extra-interface': (Path(network_policy.__file__).parent / 'router/opennds-extra-interface.init').read_bytes(),
            'networks.conf': config['devices'].encode(),
            'networks-guard.nft': config['guard'].encode(),
        }
        installed = {}
        with tempfile.TemporaryDirectory() as temporary:
            for write in writes:
                destination = Path(temporary) / Path(write[1]).name
                command = write[0].rsplit('\nchmod ', 1)[0]
                command = command[:command.rfind(write[1])] + shlex.quote(str(destination))
                subprocess.run(['sh', '-c', command], check=True, capture_output=True)
                name = destination.name.removesuffix('.manager-new')
                installed[name] = destination.read_bytes()
                self.assertEqual(installed[name], expected[name], name)
        for key, name in [('wrapper_sha', 'libopennds.sh'), ('helper_sha', 'opennds-extra-interface.sh'),
                          ('init_sha', 'opennds-extra-interface')]:
            self.assertEqual(hashlib.sha256(installed[name]).hexdigest(), config['helpers'][key])


class NetworkManagerTests(unittest.TestCase):
    setUp = optimization.OptimizationTests.setUp
    patch = optimization.OptimizationTests.patch
    state = optimization.OptimizationTests.state
    control = optimization.OptimizationTests.control

    def policy(self, modes=None):
        data = discovery(modes)
        self.patch('_networks_data', data)
        return data

    def test_client_groups_use_cached_discovery_without_mutating_snapshot(self):
        self.policy()
        records = {
            'office': {'ip': '172.16.5.99', 'online': True},
            'guest': {'ip': '172.20.7.99', 'online': True},
            'offline': {'ip': '172.20.7.98', 'online': False, 'state': 'Offline'},
            'unknown': {'ip': '203.0.113.42'},
            'missing': {'ip': ''},
            'wan': {'ip': '198.51.100.10'},
        }
        snapshot = {'ok': True, 'data': {'clients': records}, 'sampled_at': 1}
        original = copy.deepcopy(snapshot)
        self.patch('_clients_cache_data', snapshot)
        self.patch('_with_live_wan_usage', lambda payload: payload)
        response = self.client.get('/api/clients', headers=self.headers).get_json()
        clients = response['data']['clients']
        self.assertEqual((clients['office']['network'], clients['office']['interface']),
                         ('office', 'br-office'))
        self.assertEqual(clients['guest']['network'], 'visitors')
        self.assertEqual(clients['offline']['network'], 'visitors')
        for name in ('unknown', 'missing', 'wan'):
            self.assertEqual(clients[name]['network'], '')
            self.assertEqual(clients[name]['interface'], '')
        self.assertEqual([n['name'] for n in response['data']['networks']], ['office', 'visitors'])
        self.assertEqual(snapshot, original)
        app.ssh.assert_not_called()

    def test_initial_empty_snapshot_still_exposes_lan_groups(self):
        self.policy()
        response = self.client.get('/api/clients', headers=self.headers).get_json()
        self.assertEqual(response['data']['clients'], {})
        self.assertEqual([n['device'] for n in response['data']['networks']],
                         ['br-office', 'br-guest.37'])
        app.ssh.assert_not_called()

    def test_infrastructure_rows_hidden_without_changing_control_or_history(self):
        self.policy()
        self.patch('HOST', '172.16.5.2')
        self.patch('FAS_BASE_URL', 'http://172.16.5.200:8090')
        addresses = {
            'manager': '172.16.5.200', 'ssh-router': '172.16.5.2',
            'gateway': '172.16.5.1', 'guest-gateway': '172.20.7.1',
            'wan-router': '198.51.100.2', 'guest-vm': '172.20.7.99',
            'ordinary-lan': '172.16.5.99', 'off-manager': '172.16.5.200',
            'off-client': '172.20.7.98',
        }
        records = {key: {'ip': ip, 'state': 'Offline' if key.startswith('off-') else 'Authenticated'}
                   for key, ip in addresses.items()}
        snapshot = {'ok': True, 'data': {'clients': records}, '_live_clients': copy.deepcopy(records),
                    'sampled_at': 1}
        original = copy.deepcopy(snapshot)
        self.patch('_clients_cache_data', snapshot)
        self.patch('_with_live_wan_usage', lambda payload: payload)
        self.state('SEEN_FILE', records)
        for _ in range(2):
            response = self.client.get('/api/clients', headers=self.headers).get_json()
            self.assertEqual(set(response['data']['clients']), {'guest-vm', 'ordinary-lan', 'off-client'})
            self.assertNotIn('_live_clients', response)
        self.assertEqual(snapshot, original)
        self.assertEqual(app._load_json(app.SEEN_FILE, {}), records)
        app.ssh.assert_not_called()

    def test_hidden_addresses_follow_cached_discovery_and_manager_config(self):
        data = self.policy()
        self.patch('HOST', 'router.test')
        self.patch('FAS_BASE_URL', 'http://172.16.5.201:8090')
        self.assertIn('172.16.5.201', app._infrastructure_client_ips())
        self.assertIn('172.16.5.200', app._infrastructure_client_ips())
        data['networks'][1]['addresses'] = [{'address': '172.20.8.1', 'subnet': '172.20.8.0/24'}]
        self.assertIn('172.20.8.1', app._infrastructure_client_ips())
        self.assertNotIn('172.20.7.1', app._infrastructure_client_ips())
        app.ssh.assert_not_called()

    def test_infrastructure_filter_tolerates_missing_discovery_and_non_numeric_config(self):
        self.patch('HOST', 'router.test')
        self.patch('FAS_BASE_URL', 'http://[invalid')
        self.assertEqual(app._infrastructure_client_ips(), set())
        app.ssh.assert_not_called()

    def test_connected_count_matches_visible_clients_without_affecting_accounting_inputs(self):
        self.policy()
        self.patch('FAS_BASE_URL', 'http://172.16.5.200:8090')
        records = {key: {'ip': ip, 'mac': mac, 'last_active': 1000}
                   for key, ip, mac in [('manager', '172.16.5.200', MAC),
                                        ('router', '172.20.7.1', '02:00:00:00:00:97'),
                                        ('guest-vm', '172.20.7.99', SECOND)]}
        self.assertEqual(app._connected_count({'clients': records}, 1001), 1)
        addresses, _ = app._wan_usage_inputs(records.values(), 1001)
        self.assertIn('172.16.5.200', addresses)
        self.assertIn('172.20.7.99', addresses)
        app.ssh.assert_not_called()

    def test_behavior_and_queue_scope_are_independent(self):
        self.policy({'office': 'portal', 'visitors': 'auto_auth'})
        primary = {'ip': '172.16.5.99'}
        guests = {'ip': '172.20.7.99'}
        self.assertEqual(app._client_mode(primary), 'portal')
        self.assertFalse(app._client_is_extra_network(primary))
        self.assertEqual(app._client_mode(guests), 'auto_auth')
        self.assertTrue(app._client_is_extra_network(guests))
        self.assertEqual(app._client_mode({'ip': '198.51.100.99'}), 'unmanaged')

    def test_changing_primary_to_portal_does_not_logout_other_networks(self):
        data = self.policy({'office': 'auto_auth', 'visitors': 'auto_auth'})
        first = self.control()
        first['ip'] = '172.16.5.99'
        app._clients_cache_data['_live_clients'][SECOND] = {**first, 'mac': SECOND, 'ip': '172.20.7.99'}
        self.state('MODE_FILE', {'mode': 'auto_auth', 'auto_authed': [MAC, SECOND]})
        data['applied_config'] = network_policy.compile_config(data, data['modes'])
        data['metadata'].update(data['applied_config']['helpers'])
        nds = self.patch('ndsctl', Mock(return_value=(0, 'Deauthenticated')))
        self.assertTrue(app._apply_network_modes({'office': 'portal'})[0])
        nds.assert_called_once_with('deauth ' + MAC)
        self.assertEqual(app._load_mode()['auto_authed'], [SECOND])
        self.assertEqual(self.commands, [])

    def test_leaving_auto_trust_untrusts_only_changed_lan(self):
        data = self.policy({'office': 'auto_trust', 'visitors': 'auto_trust'})
        first = self.control('Preauthenticated', 'auto_trust')
        first['ip'] = '172.16.5.99'
        app._clients_cache_data['_live_clients'][SECOND] = {**first, 'mac': SECOND, 'ip': '172.20.7.99'}
        self.state('MODE_FILE', {'mode': 'auto_trust', 'auto_trusted': [MAC, SECOND]})
        app._trusted_macs_cache = {MAC, SECOND}
        data['applied_config'] = network_policy.compile_config(data, data['modes'])
        data['metadata'].update(data['applied_config']['helpers'])
        nds = self.patch('ndsctl', Mock(return_value=(0, 'Untrusted')))
        self.assertTrue(app._apply_network_modes({'office': 'portal'})[0])
        nds.assert_called_once_with('untrust ' + MAC)
        self.assertEqual(app._load_mode()['auto_trusted'], [SECOND])

    def test_network_refresh_and_punish_queue_update_cannot_deadlock(self):
        data = self.policy({'office': 'auto_auth', 'visitors': 'portal'})
        data['applied_config'] = network_policy.compile_config(data, data['modes'])
        data['metadata'].update(data['applied_config']['helpers'])
        self.patch('_live_clients_for_control', Mock(return_value=[]))
        self.patch('_auth_control_lock', threading.Lock())
        self.patch('_networks_lock', threading.RLock())
        queue_lock = self.patch('_punishment_tc_lock', threading.Lock())
        queue_held, control_started = threading.Event(), threading.Event()
        results, errors = {}, []

        def control():
            # Mode changes must remain serialized through reconciliation.
            self.assertTrue(app._auth_control_lock.locked())
            control_started.set()
            if not queue_lock.acquire(timeout=2):
                raise AssertionError('network refresh blocked the Punish network read')
            try:
                results['mode'] = app._network_state()['modes']['office']
            finally:
                queue_lock.release()

        self.patch('_control_once_locked', control)

        def punish():
            with queue_lock:
                queue_held.set()
                self.assertTrue(control_started.wait(2))
                results['interface'] = app._client_tc_interface({'ip': '172.16.5.99'})

        def refresh():
            results['apply'] = app._apply_network_modes({'office': 'portal'})

        def run(callback):
            try:
                callback()
            except BaseException as exc:
                errors.append(exc)

        punishment = threading.Thread(target=run, args=(punish,), daemon=True)
        refresh_thread = threading.Thread(target=run, args=(refresh,), daemon=True)
        punishment.start()
        self.assertTrue(queue_held.wait(2))
        refresh_thread.start()
        refresh_thread.join(4)
        punishment.join(4)
        self.assertFalse(refresh_thread.is_alive(), 'network refresh hung')
        self.assertFalse(punishment.is_alive(), 'Punish queue update hung')
        self.assertEqual(errors, [])
        self.assertTrue(results['apply'][0])
        self.assertEqual(results['mode'], 'portal')
        self.assertEqual(results['interface'], 'br-office')
        self.assertEqual(self.commands, [])

    def test_failed_network_apply_does_not_reconcile_queues(self):
        self.policy({'office': 'auto_auth', 'visitors': 'unmanaged'})
        app.ssh.side_effect = None
        app.ssh.return_value = (1, b'', 'failed transaction')
        control = self.patch('_control_once_locked', Mock())
        self.assertFalse(app._apply_network_modes({'visitors': 'portal'})[0])
        control.assert_not_called()

    def test_router_apply_failure_preserves_previous_behavior(self):
        data = self.policy({'office': 'auto_auth', 'visitors': 'unmanaged'})
        app.ssh.return_value = (1, b'', 'failed transaction')
        app.ssh.side_effect = None
        ok, _ = app._apply_network_modes({'visitors': 'portal'})
        self.assertFalse(ok)
        self.assertEqual(app._network_state()['modes']['visitors'], 'unmanaged')
        self.assertIn('failed', app._network_state()['error'])

    def test_unavailable_managed_lan_retains_guard_until_explicitly_unmanaged(self):
        data = self.policy()
        data['networks'][1].update(eligible=False, reason='Enable DHCP')
        self.assertFalse(app._apply_network_modes({})[0])
        self.assertEqual(self.commands, [])
        self.assertEqual(app._network_state()['modes']['visitors'], 'portal')
        self.assertTrue(app._apply_network_modes({'visitors': 'unmanaged'})[0])
        self.assertEqual(app._network_state()['modes']['visitors'], 'unmanaged')

    def test_scan_does_not_apply_router_changes_and_preserves_modes(self):
        self.policy()
        dump, firewall, dhcp, meta = topology()
        dump['interface'][1]['ipv4-address'][0]['address'] = '172.30.8.1'
        raw = (json.dumps(dump) + '\n@@FIREWALL\n' + json.dumps({'values': firewall}) +
               '\n@@DHCP\n' + json.dumps({'values': dhcp}) + '\n@@META\n' +
               '\n'.join(k+'='+v for k,v in meta.items())).encode()
        app.ssh.side_effect = None
        app.ssh.return_value = (0, raw, '')
        response = self.client.get('/api/networks', headers=self.headers)
        self.assertTrue(response.get_json()['ok'])
        guests = response.get_json()['networks'][1]
        self.assertEqual(guests['mode'], 'portal')
        self.assertEqual(guests['subnets'], ['172.30.8.0/24'])
        self.assertEqual(app.ssh.call_count, 1)
        self.assertNotIn('uci set', app.ssh.call_args.args[0])

    def test_failed_scan_preserves_cached_topology(self):
        data = self.policy()
        app.ssh.side_effect = None
        app.ssh.return_value = (0, b'not json', '')
        response = self.client.get('/api/networks', headers=self.headers)
        self.assertEqual(response.status_code, 502)
        self.assertEqual(app._network_state(), data)


class RouterHelperTests(unittest.TestCase):
    def run_helper(self, legacy=False, managed=True):
        dispatch = [('nds_mangle','ndsPRE','ndsTRU'), ('nds_mangle','ndsPRE','ndsOUT'),
                    ('nds_mangle','ndsPOST','ndsINC'), ('nds_mangle','ndsINC','ndsDLR'),
                    ('nds_mangle','ndsINC','nds_ft_INC'), ('nds_nat','ndsPRE','ndsOUT'),
                    ('nds_filter','ndsINP','ndsRTR'), ('nds_filter','ndsFWD','ndsNET')]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config, guard, checksum = (root / name for name in ('config', 'guard', 'checksum'))
            config.write_text('primary br-office\n' + ('extra br-guest.37\n' if managed else ''))
            guard.write_text('test guard')
            checksum.write_text(hashlib.sha256(guard.read_bytes()).hexdigest())
            cases = {}
            for i, (table, chain, target) in enumerate(dispatch):
                tag = f'manager-extra-{table}-{chain}-{target}' if legacy else f'manager-extra-br-guest.37-{table}-{chain}-{target}'
                cases[table+'/'+chain] = cases.get(table+'/'+chain, '') + f' iifname "br-guest.37" counter jump {target} comment "{tag}" # handle {100+i}\n'
            cases['nds_filter/ndsNET'] = 'counter reject\n0x00030000 == 0x00030000\n'
            (root/'fixtures.json').write_text(json.dumps(cases))
            nft = root/'nft'
            nft.write_text(f'#!{sys.executable}\n' + '''import json,os,pathlib,sys
args=sys.argv[1:]
if 'list' in args:
 if 'chain' in args:
  table,chain=args[-2:]
  print(json.loads(pathlib.Path(os.environ['NFT_FIXTURES']).read_text()).get(table+'/'+chain,''))
 sys.exit(0)
batch=pathlib.Path(args[-1]).read_text()
deletes=[line for line in batch.splitlines() if line.startswith('delete rule')]
if len(deletes)!=len(set(deletes)): sys.exit('duplicate rule deletion')
if '-c' not in args: pathlib.Path(os.environ['NFT_APPLIED']).write_text(batch)
''')
            nft.chmod(0o755)
            logger=root/'logger';logger.write_text('#!/bin/sh\nexit 0\n');logger.chmod(0o755)
            source=(Path(__file__).parents[1]/'router/opennds-extra-interface.sh').read_text()
            source=source.replace('config=/etc/opennds-manager/networks.conf', f'config={config}')
            source=source.replace('guard_file=/etc/opennds-manager/networks-guard.nft', f'guard_file={guard}')
            source=source.replace('/tmp/opennds-networks-guard-sum', str(checksum))
            helper=root/'helper.sh';helper.write_text(source)
            result=subprocess.run(['sh',str(helper),'once'],capture_output=True,text=True,
                env={**os.environ,'PATH':str(root)+os.pathsep+os.environ['PATH'],
                     'NFT_FIXTURES':str(root/'fixtures.json'),'NFT_APPLIED':str(root/'applied')})
            self.assertEqual(result.returncode, 0, result.stderr)
            return (root/'applied').read_text() if (root/'applied').exists() else ''

    def test_legacy_dispatch_migration_deletes_each_handle_once(self):
        batch=self.run_helper(legacy=True)
        self.assertEqual(sum(line.startswith('delete rule') for line in batch.splitlines()),8)
        self.assertEqual(sum(line.startswith('add rule') for line in batch.splitlines()),8)

    def test_shared_chain_preserves_all_current_dispatch_targets(self):
        self.assertEqual(self.run_helper(), '')

    def test_unmanaged_removes_only_owned_dispatch(self):
        batch=self.run_helper(managed=False)
        self.assertEqual(sum(line.startswith('delete rule') for line in batch.splitlines()),8)
        self.assertNotIn('add rule',batch)


if __name__ == '__main__':
    unittest.main()
