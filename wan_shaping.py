"""WAN-only policy queues. No background workers or router access at import time.

Client identity uses reserved connmark bits 20..31, restored by ctinfo before
SQM's ingress redirect. Neither private-IP filters on WAN nor CAKE's own NAT
isolation are sufficient for selecting per-client classes before DNAT.
"""
import copy
import hashlib
import ipaddress
import json
import re
import shlex

MAJOR = '7ea0'
MASK = 0xfff00000
KEEP = 0x000fffff
PREF = 1
# Let u32 select this priority's hash table; SQM may already own 800:.
HANDLE = '::1'
TABLE = 'nds_mgr_wan_qos'
IFACE = re.compile(r'[A-Za-z0-9_.-]{1,15}\Z')
MAC = re.compile(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\Z')


def placements(queues, lans, wan):
    """Prefer an enabled LAN queue, otherwise use the enabled WAN queue.

    Disabled LAN sections do not obstruct WAN fallback. Ambiguous and enabled
    non-CAKE configurations remain explicit failures rather than being ignored.
    """
    result = {}
    for lan in lans:
        own = [q for q in queues if q.get('interface') == lan]
        uplink = [q for q in queues if q.get('interface') == wan]
        selected = own if any(q.get('enabled') == '1' for q in own) else uplink
        if len(own) > 1 or len(selected) > 1:
            result[lan] = {'placement': 'unavailable', 'error': 'Duplicate SQM queues'}
        elif len(selected) != 1 or selected[0].get('enabled') != '1':
            result[lan] = {'placement': 'unavailable', 'error': 'No enabled LAN or WAN SQM queue'}
        elif selected[0].get('qdisc') != 'cake':
            result[lan] = {'placement': 'unavailable', 'error': 'Hard caps and delay require CAKE SQM'}
        elif any(int(selected[0].get(k) or 0) <= 0 for k in ('download', 'upload')):
            result[lan] = {'placement': 'unavailable', 'error': 'Positive SQM rates are required in both directions'}
        else:
            result[lan] = {'placement': 'lan' if selected[0].get('interface') == lan else 'wan',
                           'queue_interface': selected[0]['interface'], 'queue': selected[0], 'error': ''}
    return result


def identities(saved, networks, clients):
    state = copy.deepcopy(saved)
    state.setdefault('lan_ids', {})
    state.setdefault('client_ids', {})
    for mapping, keys, start, stop in ((state['lan_ids'], networks, 0x20, 0x100),
                                      (state['client_ids'], clients, 0x200, 0x1000)):
        values = list(mapping.values())
        if any(not isinstance(n, int) or not start <= n < stop for n in values) or len(set(values)) != len(values):
            raise ValueError('Invalid WAN class identities; queues left unchanged')
        for key in sorted(keys):
            if key not in mapping:
                used = set(mapping.values())
                value = next((n for n in range(start, stop) if n not in used), None)
                if value is None:
                    raise ValueError('WAN class identities exhausted')
                mapping[key] = value
    return state


def mark(minor):
    return hex(minor << 20)


def nft_rules(wan, networks, clients, state):
    if not IFACE.fullmatch(wan) or any(not IFACE.fullmatch(i) for i in networks):
        raise ValueError('Invalid WAN/LAN device')
    rules = []
    for lan, network in sorted(networks.items()):
        # Mark both directions after routing, preserving openNDS's low bits.
        # Download classification before DNAT reads this connection mark.
        for direction in ('up', 'down'):
            field, ingress, egress = ('saddr', lan, wan) if direction == 'up' else ('daddr', wan, lan)
            prefix = f'iifname {json.dumps(ingress)} oifname {json.dumps(egress)} '
            for mac, client in sorted(clients.items()):
                if client['interface'] != lan:
                    continue
                ip = str(ipaddress.IPv4Address(client['ip']))
                rules.append(prefix + f'ip {field} {ip} ' + _mark_rule(state['client_ids'][mac]))
            for subnet in network.get('subnets', []):
                subnet = str(ipaddress.IPv4Network(subnet, strict=False))
                rules.append(prefix + f'ip {field} {subnet} ' + _mark_rule(state['lan_ids'][lan] + 0xe0))
    body = '\n'.join(rules)
    digest = hashlib.sha256(body.encode()).hexdigest()
    # add is idempotent; delete/recreate is one atomic nft transaction.
    return (f'add table inet {TABLE}\ndelete table inet {TABLE}\n'
            f'table inet {TABLE} {{\n comment "manager-{digest}"\n'
            ' chain classify { type filter hook forward priority 300; policy accept;\n'
            + body + '\n }\n}\n'), digest


def _mark_rule(minor):
    return (f'ct mark set (ct mark & {hex(KEEP)}) | {mark(minor)} '
            f'meta mark set (meta mark & {hex(KEEP)}) | {mark(minor)} counter return')


def rate_bits(value):
    match = re.fullmatch(r'([0-9.]+)([kKmMgG]?)bit', value)
    if not match:
        raise ValueError('Unsupported WAN queue rate: ' + value)
    return round(float(match[1]) * {'': 1, 'k': 1000, 'm': 1000000, 'g': 1000000000}[match[2].lower()])


def parse(text):
    layout = {'qdiscs': {}, 'classes': {}, 'filters': {}}
    current = None
    for line in text.splitlines():
        match = re.match(r'qdisc (\w+) ([0-9a-f]+): (.*)', line)
        if match:
            kind, handle, options = match.groups()
            parent = re.search(r'parent (' + MAJOR + r':[0-9a-f]+)\b', options)
            key = parent[1] if parent else 'root' if options.startswith('root') else None
            current = {'kind': kind, 'handle': handle, 'options': options, 'backlog': 0}
            if key:
                layout['qdiscs'][key] = current
        backlog = re.search(r'backlog \S+ (\d+)p', line)
        if backlog and current is not None:
            current['backlog'] = int(backlog[1])
        match = re.match(r'class htb (' + MAJOR + r':[0-9a-f]+) (?:root|parent (\S+)).*?rate (\S+) ceil (\S+)', line)
        if match:
            cid, parent, rate, ceil = match.groups()
            layout['classes'][cid] = {'parent': parent or MAJOR + ':', 'rate': rate_bits(rate), 'ceil': rate_bits(ceil)}
        match = re.search(r'pref (\d+) fw .*?handle (0x[0-9a-f]+)(?:/(0x[0-9a-f]+))? .*?(?:classid|flowid) (' + MAJOR + r':[0-9a-f]+)', line)
        if match:
            pref, value, mask, cid = match.groups()
            layout['filters'][cid] = {'priority': int(pref), 'mark': int(value, 16), 'mask': int(mask or '0xffffffff', 16)}
    return layout


def inspect(ssh, interfaces):
    commands = []
    for direction, dev in interfaces.items():
        if not IFACE.fullmatch(dev):
            raise ValueError('Invalid WAN queue device')
        dev = shlex.quote(dev)
        commands += [f'echo @@WAN_{direction}', f'tc -s qdisc show dev {dev}',
                     f'tc class show dev {dev}', f'tc filter show dev {dev} parent {MAJOR}:']
    rc, output, error = ssh('set -e; ' + '; '.join(commands))
    if rc:
        raise ValueError(error or 'WAN queue inspection failed')
    parts = re.split(r'^@@WAN_(download|upload)\s*$', output.decode(errors='replace'), flags=re.M)
    layouts = {parts[i]: parse(parts[i + 1]) for i in range(1, len(parts), 2)}
    if set(layouts) != {'download', 'upload'}:
        raise ValueError('Incomplete WAN queue inspection')
    return layouts


def nodes(networks, clients, desired, daily_rates, state, totals):
    """Build shared WAN parents and stable per-client leaves in both directions."""
    result = {}
    for direction, total in totals.items():
        direction_nodes = {'1': {'parent': MAJOR + ':', 'rate': total, 'ceil': total},
                           '10': {'parent': MAJOR + ':1', 'rate': min(1000, total), 'ceil': total, 'kind': 'cake'}}
        for lan in sorted(networks):
            minor = state['lan_ids'][lan]
            # Daily rates retain LAN ingress/egress API semantics.
            cap = int(daily_rates.get(lan, {}).get('upload' if direction == 'download' else 'download') or 0) * 1000
            maximum = min(cap or total, total)
            parent = format(minor, 'x')
            direction_nodes[parent] = {'parent': MAJOR + ':1', 'rate': min(1000, maximum), 'ceil': maximum}
            direction_nodes[format(minor + 0xe0, 'x')] = {
                'parent': MAJOR + ':' + parent, 'rate': min(1000, maximum), 'ceil': maximum, 'kind': 'cake'}
        for mac, client in sorted(clients.items()):
            profile = desired.get(mac, {})
            maximum = direction_nodes[format(state['lan_ids'][client['interface']], 'x')]['ceil']
            cap = int(profile.get(direction + '_cap') or 0) * 1000
            maximum = min(cap or maximum, maximum)
            delay = int(profile.get('delay_ms') or 0) if direction == 'download' else 0
            loss = str(profile.get('loss_pct') or '0') if direction == 'download' else '0'
            direction_nodes[format(state['client_ids'][mac], 'x')] = {
                'parent': MAJOR + ':' + format(state['lan_ids'][client['interface']], 'x'),
                'rate': min(1000, maximum), 'ceil': maximum,
                'kind': 'netem' if delay or float(loss) else 'cake', 'delay_ms': delay, 'loss_pct': loss}
        result[direction] = direction_nodes
    return result


def _cake_options(layout):
    root = layout['qdiscs'].get('root', {})
    leaf = root if root.get('kind') == 'cake' else layout['qdiscs'].get(MAJOR + ':10', {})
    options = re.sub(r'^(?:root|parent ' + MAJOR + r':10)(?: refcnt \d+)? ', '', leaf.get('options', ''))
    if leaf.get('kind') != 'cake' or not re.fullmatch(r'[A-Za-z0-9._:/ -]+', options) or not re.search(r'\bbandwidth [0-9.]+[KMGkmg]?bit\b', options):
        raise ValueError('WAN client queues require positive CAKE roots in both directions')
    return options


def plan(interfaces, layouts, specs):
    """Preflight both directions before returning any proposed mutations."""
    commands = []
    for direction, dev in interfaces.items():
        layout, expected = layouts[direction], specs[direction]
        root = layout['qdiscs'].get('root', {})
        options = _cake_options(layout)
        if root.get('kind') == 'cake':
            commands.append(f'tc qdisc replace dev {dev} root handle {MAJOR}: htb default 10')
            layout = {'classes': {}, 'qdiscs': {}, 'filters': {}}
        elif (root.get('kind') != 'htb' or root.get('handle') != MAJOR or
              not re.search(r'\bdefault (?:0x)?10\b', root.get('options', ''))):
            raise ValueError('WAN queue layout requires SQM recovery')
        # Retire filters before their leaves; persistent IDs are never reused.
        removed = set(layout['classes']) - {MAJOR + ':' + n for n in expected}
        moved = {MAJOR + ':' + minor for minor, node in expected.items()
                 if MAJOR + ':' + minor in layout['classes'] and
                 layout['classes'][MAJOR + ':' + minor]['parent'] != node['parent']}
        for cid in sorted(removed | moved, key=lambda c: int(c.split(':')[1], 16), reverse=True):
            old_filter = layout['filters'].get(cid)
            if old_filter:
                commands.append(f'tc filter delete dev {dev} parent {MAJOR}: protocol ip pref {old_filter["priority"]} '
                                f'handle {hex(old_filter["mark"])}/{hex(MASK)} fw')
            if cid in layout['qdiscs']:
                commands.append(f'tc qdisc delete dev {dev} parent {cid}')
            commands.append(f'tc class delete dev {dev} classid {cid}')
        # Parent IDs sort before their leaves and children.
        for minor, node in sorted(expected.items(), key=lambda item: int(item[0], 16)):
            cid = MAJOR + ':' + minor
            old = None if cid in moved else layout['classes'].get(cid)
            wanted = {k: node[k] for k in ('parent', 'rate', 'ceil')}
            if old != wanted:
                commands.append(f'tc class {"change" if old else "add"} dev {dev} parent {node["parent"]} '
                                f'classid {cid} htb rate {node["rate"]}bit ceil {node["ceil"]}bit')
            if 'kind' not in node:
                continue
            leaf = None if cid in moved else layout['qdiscs'].get(cid)
            if node['kind'] == 'cake':
                parameters = re.sub(r'\bbandwidth \S+', f'bandwidth {node["ceil"]}bit', options, count=1)
                correct = leaf and leaf['kind'] == 'cake' and rate_bits(re.search(r'\bbandwidth (\S+)', leaf['options'])[1]) == node['ceil']
            else:
                parameters = f'delay {node["delay_ms"]}ms loss {node["loss_pct"]}%'
                delay = re.search(r'\bdelay ([0-9.]+)(ms|us|s)\b', leaf['options']) if leaf else None
                loss = re.search(r'\bloss ([0-9.]+)%', leaf['options']) if leaf else None
                delay_ms = float(delay[1]) * {'ms': 1, 'us': .001, 's': 1000}[delay[2]] if delay else 0
                correct = leaf and leaf['kind'] == 'netem' and delay_ms == node['delay_ms'] and float(loss[1] if loss else 0) == float(node['loss_pct'])
            if not correct:
                if leaf and leaf['kind'] != node['kind']:
                    commands.append(f'tc qdisc delete dev {dev} parent {cid}')
                operation = 'change' if leaf and leaf['kind'] == node['kind'] else 'add'
                commands.append(f'tc qdisc {operation} dev {dev} parent {cid} handle {minor}: {node["kind"]} {parameters}')
            if minor == '10':
                continue
            value = int(minor, 16)
            desired_filter = {'priority': value, 'mark': value << 20, 'mask': MASK}
            old_filter = None if cid in moved else layout['filters'].get(cid)
            if old_filter and old_filter != desired_filter:
                raise ValueError('WAN filter ownership conflict')
            if not old_filter:
                commands.append(f'tc filter add dev {dev} parent {MAJOR}: protocol ip pref {value} '
                                f'handle {mark(value)}/{hex(MASK)} fw classid {cid}')
    return commands


def ingress_handle(text):
    # Other rules at pref 1 would prevent reliable ctinfo-before-redirect ordering.
    rows = [row for row in text.splitlines() if re.search(r'\bpref 1\b', row)]
    sections = re.split(r'(?=^filter )', text, flags=re.M)
    handles = {match[1] for part in sections
               if re.search(r'\bpref 1\b', part) and 'ctinfo' in part and hex(MASK) in part
               for match in [re.search(r'\bfh ([0-9a-f]+::1)(?:\s|$)', part)] if match}
    handle = next(iter(handles)) if len(handles) == 1 else None
    allowed = {handle, handle.split('::')[0] + ':'} if handle else set()
    foreign = any(' u32 ' not in row + ' ' or
                  (' fh ' in row and re.search(r'\bfh (\S+)', row)[1] not in allowed)
                  for row in rows)
    if rows and (not handle or foreign):
        raise ValueError('WAN ingress priority 1 is already in use; classification left unchanged')
    return handle


def ingress_status(text):
    return bool(ingress_handle(text))


def ingress_command(wan):
    if not IFACE.fullmatch(wan):
        raise ValueError('Invalid WAN device')
    return (f'tc filter replace dev {wan} parent ffff: protocol ip pref {PREF} handle {HANDLE} '
            f'u32 match u32 0 0 action ctinfo cpmark {hex(MASK)} continue')
