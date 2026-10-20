"""Explicit, isolated real-packet WAN test. Never connects to the live router.

Run only in a disposable user/network/mount namespace or a disposable container
with its own network namespace. Requires iproute2/nftables/iperf3 and kernel
IFB, CAKE, HTB, netem and ctinfo support. See WAN-SQM-COMPATIBILITY.md.
"""
import json
import pathlib
import subprocess
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import wan_shaping as qos


def run(command, data=None, timeout=15):
    result = subprocess.run(command, shell=True, input=data, capture_output=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(command + ': ' + result.stderr.decode())
    return result.stdout.decode()


def ssh(command, data=None, timeout=15):
    result = subprocess.run(command, shell=True, input=data, capture_output=True, timeout=timeout)
    return result.returncode, result.stdout, result.stderr.decode()


processes = []
networks = {'lan0': {'subnets': ['192.0.2.0/24']}, 'lan1': {'subnets': ['198.51.100.0/24']}}
clients = {'02:00:00:00:00:99': {'interface': 'lan0', 'ip': '192.0.2.2'},
           '02:00:00:00:00:98': {'interface': 'lan1', 'ip': '198.51.100.2'}}
state = qos.identities({}, networks, clients)
interfaces = {'download': 'ifb-test', 'upload': 'wan0'}
totals = {'download': 20000000, 'upload': 20000000}
desired = {'02:00:00:00:00:99': {'download_cap': 2000, 'upload_cap': 1000},
           '02:00:00:00:00:98': {'download_cap': 4000, 'upload_cap': 3000}}


def apply(daily=None):
    specs = qos.nodes(networks, clients, desired, daily or {}, state, totals)
    layouts = qos.inspect(ssh, interfaces)
    commands = qos.plan(interfaces, layouts, specs)
    if commands:
        run('set -e; ' + '; '.join(commands))
    after = qos.inspect(ssh, interfaces)
    remaining = qos.plan(interfaces, after, specs)
    assert not remaining, remaining


def throughput(namespace, target='203.0.113.2', port=5201, reverse=False, udp=False):
    flags = (' -R' if reverse else '') + (' -u -b 10M' if udp else '')
    result = json.loads(run(f'ip netns exec {namespace} iperf3 -c {target} -p {port} -t 3 -O 1 -J{flags}', timeout=15))
    assert 'error' not in result, result.get('error')
    summary = result['end'].get('sum_received', result['end'].get('sum'))
    return summary['bits_per_second'] / 1000000


try:
    for namespace, dev, peer, subnet in [('a', 'lan0', 'a0', '192.0.2'),
                                        ('b', 'lan1', 'b0', '198.51.100'),
                                        ('server', 'wan0', 's0', '203.0.113')]:
        run(f'ip netns add {namespace}; ip link add {dev} type veth peer name {peer}; ip link set {peer} netns {namespace}; '
            f'ip addr add {subnet}.1/24 dev {dev}; ip link set {dev} up; '
            f'ip netns exec {namespace} ip addr add {subnet}.2/24 dev {peer}; '
            f'ip netns exec {namespace} ip link set {peer} up; ip netns exec {namespace} ip link set lo up; '
            f'ip netns exec {namespace} ip route add default via {subnet}.1')
    run('nft -f -', data=b'table ip lab_nat {\n chain post { type nat hook postrouting priority srcnat; oifname "wan0" masquerade; }\n}\n')
    run('ip link add ifb-test type ifb; ip link set ifb-test up; '
        'tc qdisc add dev wan0 root cake bandwidth 20Mbit besteffort nat; '
        'tc qdisc add dev ifb-test root cake bandwidth 20Mbit besteffort nat; '
        'tc qdisc add dev wan0 handle ffff: ingress; '
        'tc filter add dev wan0 parent ffff: protocol all pref 10 u32 match u32 0 0 action mirred egress redirect dev ifb-test')
    apply()
    nft, _ = qos.nft_rules('wan0', networks, clients, state)
    run('nft -f -', data=nft.encode())
    run(qos.ingress_command('wan0'))
    assert qos.ingress_status(run('tc filter show dev wan0 parent ffff:'))
    for namespace, port in [('server', 5201), ('b', 5202)]:
        processes.append(subprocess.Popen(['ip', 'netns', 'exec', namespace, 'iperf3', '-s', '-p', str(port)],
                                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
    time.sleep(.3)
    results = {}
    for namespace, direction, cap, reverse in [('a', 'up', 1, False), ('a', 'down', 2, True),
                                               ('b', 'up', 3, False), ('b', 'down', 4, True)]:
        value = throughput(namespace, reverse=reverse)
        assert cap * .45 < value <= cap * 1.25, (namespace, direction, value, cap)
        results[namespace + '_' + direction] = round(value, 3)
    apply({'lan0': {'download': 500, 'upload': 1000}})
    for namespace, cap in [('a', 1), ('b', 4)]:
        value = throughput(namespace, reverse=True)
        assert cap * .45 < value <= cap * 1.25, ('daily isolation', namespace, value)
        results['daily_' + namespace + '_down'] = round(value, 3)
    apply()  # Midnight/disable restores this LAN without touching the other.
    value = throughput('a', reverse=True)
    assert .9 < value <= 2.5, ('restore', value)
    results['restored_a_down'] = round(value, 3)
    udp = throughput('a', reverse=True, udp=True)
    assert .7 < udp <= 2.5, ('UDP cap', udp)
    results['udp_a_down'] = round(udp, 3)
    desired['02:00:00:00:00:99'].update(delay_ms=100, loss_pct='0')
    apply()
    external = run('ip netns exec a ping -c 4 -i .3 203.0.113.2')
    local = run('ip netns exec a ping -c 4 -i .3 198.51.100.2')
    import re
    average = lambda text: float(re.search(r'= [0-9.]+/([0-9.]+)/', text)[1])
    assert average(external) >= 90, external
    assert average(local) < 30, local
    results['wan_ping_ms'] = average(external)
    results['local_ping_ms'] = average(local)
    local_rate = throughput('a', target='198.51.100.2', port=5202)
    assert local_rate > 20, ('local traffic should bypass WAN queues', local_rate)
    results['local_mbps'] = round(local_rate, 3)
    # Remove Punish without deleting stable class identities.
    desired['02:00:00:00:00:99'].update(delay_ms=0, loss_pct='0')
    apply()
    for direction, dev in interfaces.items():
        text = run(f'tc -s class show dev {dev}')
        assert re.search(r'Sent [1-9][0-9]* bytes [1-9][0-9]* pkt', text), (direction, text)
    print(json.dumps({'ok': True, 'measurements': results}, indent=2), flush=True)
finally:
    for process in processes:
        process.terminate()
        process.wait(timeout=5)
    for namespace in ('a', 'b', 'server'):
        subprocess.run(['ip', 'netns', 'del', namespace], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
