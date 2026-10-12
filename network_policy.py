"""OpenWrt LAN discovery and generated openNDS attachment configuration.

No router reads or writes at import time. The manager supplies SSH/state/locks.
"""
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import shlex

NAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}\Z")
MODES = {"portal", "auto_auth", "auto_trust", "unmanaged"}
HELPER_FILES = {"wrapper_sha": "libopennds-extra-wrapper.sh", "helper_sha": "opennds-extra-interface.sh",
                "init_sha": "opennds-extra-interface.init"}


def as_list(value):
    return value if isinstance(value, list) else str(value or "").split()


def discover(dump, firewall, dhcp, metadata):
    zones = [s for s in firewall.values() if s.get(".type") == "zone"]
    leases = {s.get("interface"): s for s in dhcp.values() if s.get(".type") == "dhcp"}
    gateway = metadata.get("gatewayaddress", "").split(":")[0]
    rows = []
    for interface in dump.get("interface", []):
        name = interface.get("interface", "")
        device = interface.get("l3_device") or interface.get("device", "")
        if not NAME.fullmatch(name) or not NAME.fullmatch(device) or device == "lo":
            continue
        addresses = []
        for address in interface.get("ipv4-address", []):
            try:
                parsed = ipaddress.IPv4Interface(f"{address['address']}/{address['mask']}")
                if not parsed.ip.is_loopback:
                    addresses.append({"address": str(parsed.ip), "subnet": str(parsed.network)})
            except (KeyError, ValueError):
                continue
        primary = device == metadata.get("gatewayinterface") or any(a["address"] == gateway for a in addresses)
        matching_zones = [z for z in zones if name in as_list(z.get("network")) or
                          device in as_list(z.get("device"))]
        zone = matching_zones[0].get("name", "") if len(matching_zones) == 1 else ""
        upstream = (any(str(r.get("mask")) == "0" and r.get("nexthop") for r in interface.get("route", [])) or
                    any(z.get("masq") == "1" for z in matching_zones))
        lease = leases.get(name, {})
        dhcp_enabled = bool(lease) and lease.get("ignore", "0") != "1"
        reason = ("Upstream / WAN" if upstream else "Interface is down" if not interface.get("up") else
                  "No IPv4 subnet" if not addresses else "Requires static IPv4" if interface.get("proto") != "static" else
                  "Enable IPv4 DHCP in OpenWrt" if not dhcp_enabled else
                  "Requires one firewall zone" if not zone or not NAME.fullmatch(zone) else "")
        if not primary and not reason and metadata.get("version") != "10.3.1":
            reason = "Additional LAN support requires openNDS 10.3.1"
        rows.append({"name": name, "device": device, "addresses": addresses,
                     "subnets": [a["subnet"] for a in addresses], "zone": zone,
                     "up": bool(interface.get("up")), "primary": primary,
                     "dhcp": dhcp_enabled, "dhcp_section": lease.get(".name", ""),
                     "eligible": not reason, "reason": reason, "role": "WAN" if upstream else "LAN",
                     "mode": "unmanaged"})
    primary_rows = [r for r in rows if r["primary"]]
    if len(primary_rows) != 1:
        raise ValueError("Could not identify the running openNDS gateway from OpenWrt")
    primary = primary_rows[0]
    # Reject ambiguous addressing/device aliases rather than applying policy to a different LAN.
    conflicts = [row for row in rows if row["eligible"] and any(other is not row and other["eligible"] and
            (other["device"] == row["device"] or any(ipaddress.IPv4Network(a).overlaps(ipaddress.IPv4Network(b))
                for a in row["subnets"] for b in other["subnets"])) for other in rows)]
    for row in conflicts:
        row["eligible"], row["reason"] = False, "Shared device or overlapping LAN subnet"
    return {"networks": sorted(rows, key=lambda r: (not r["primary"], r["role"] == "WAN", r["name"])),
            "primary_device": primary["device"], "gateway_ip": gateway or primary["addresses"][0]["address"],
            "metadata": metadata}


def validate_modes(discovery, requested):
    if not isinstance(requested, dict):
        raise ValueError("Network modes must be an object")
    available = {r["name"]: r for r in discovery["networks"]}
    for name, mode in requested.items():
        if name not in available or mode not in MODES:
            raise ValueError("Unknown network or invalid behavior; scan again")
        row = available[name]
        if mode != "unmanaged" and not row["eligible"]:
            raise ValueError(f"{name}: {row['reason']}")
        if row["primary"] and mode == "unmanaged":
            raise ValueError("The native openNDS LAN must have an authentication behavior")
    return requested


def attachments(discovery, modes):
    return [r for r in discovery["networks"] if not r["primary"] and r["eligible"] and
            modes.get(r["name"], "unmanaged") != "unmanaged"]


def compile_config(discovery, modes):
    """Generate the guard, device admission list and narrowly scoped firewall rules."""
    validate_modes(discovery, modes)
    extra = attachments(discovery, modes)
    meta = discovery["metadata"]
    primary = discovery["primary_device"]
    if extra and (not meta.get("fasremoteip") or not meta.get("fasport") or meta.get("faspath") != "/fas"):
        raise ValueError("Configure the manager FAS in Portal before attaching additional LANs")
    gateway_ip = str(ipaddress.IPv4Address(discovery["gateway_ip"]))
    fas_ip = str(ipaddress.IPv4Address(meta["fasremoteip"])) if extra else "127.0.0.1"
    fas_port, gateway_port = int(meta.get("fasport") or 8080), int(meta.get("gatewayport") or 2050)
    if not 1 <= fas_port <= 65535 or not 1 <= gateway_port <= 65535:
        raise ValueError("Invalid FAS or gateway port")
    fas_row = next((r for r in discovery["networks"] if any(ipaddress.IPv4Address(fas_ip) in
                    ipaddress.IPv4Network(n) for n in r["subnets"])), None)
    wan_zones = sorted({r["zone"] for r in discovery["networks"] if r["role"] == "WAN" and r["zone"]})
    if extra and (not fas_row or not fas_row["zone"] or not wan_zones):
        raise ValueError("Additional LANs require a reachable IPv4 FAS on a discovered LAN and an upstream zone")
    lines = ["table inet nds_extra_guard {", " chain forward {",
             "  type filter hook forward priority -50; policy accept;"]
    for row in extra:
        dev, networks = row["device"], ", ".join(row["subnets"])
        lines += [f'  iifname "{dev}" meta nfproto ipv6 counter drop',
                  f'  oifname "{dev}" meta nfproto ipv6 counter drop',
                  f'  iifname "{dev}" ip saddr != {{ {networks} }} counter drop',
                  f'  iifname "{dev}" ip daddr {fas_ip} tcp dport {fas_port} counter accept',
                  f'  iifname "{dev}" meta mark & 0x30000 != 0x30000 meta mark & 0x30000 != 0x20000 counter drop']
    lines += [" }", " chain fas_return {", "  type nat hook postrouting priority 95; policy accept;"]
    for row in extra:
        # SNAT only the FAS origin. WAN accounting retains client source addresses.
        fas_gateway = next(a["address"] for a in fas_row["addresses"] if ipaddress.IPv4Address(fas_ip) in ipaddress.IPv4Network(a["subnet"]))
        lines.append(f'  iifname "{row["device"]}" oifname "{fas_row["device"]}" ip daddr {fas_ip} tcp dport {fas_port} counter snat ip to {fas_gateway}')
    lines += [" }", "}"]
    devices = "\n".join([f"primary {primary}"] + [f"extra {r['device']}" for r in extra]) + "\n"
    firewall = {}
    for row in extra:
        prefix = "nds_mgr_" + hashlib.sha256(row["name"].encode()).hexdigest()[:12]
        for suffix, fields in {
            "gateway": {"src": row["zone"], "dest_ip": gateway_ip, "dest_port": str(gateway_port), "proto": "tcp"},
            "dns": {"src": row["zone"], "dest_port": "53", "proto": "tcp udp"},
            "dhcp": {"src": row["zone"], "dest_port": "67", "proto": "udp"},
            "fas": {"src": row["zone"], "dest": fas_row["zone"], "dest_ip": fas_ip,
                    "dest_port": str(fas_port), "proto": "tcp"},
        }.items():
            firewall[prefix + "_" + suffix] = {"type": "rule", "name": prefix + "_" + suffix,
                                               "family": "ipv4", "target": "ACCEPT", **fields}
        for i, zone in enumerate(wan_zones):
            firewall[prefix + f"_wan{i}"] = {"type": "forwarding", "src": row["zone"], "dest": zone}
    hashes = {key: hashlib.sha256((Path(__file__).parent / 'router' / filename).read_bytes()).hexdigest()
              for key, filename in HELPER_FILES.items()}
    return {"schema": 3, "helpers": hashes, "devices": devices, "guard": "\n".join(lines) + "\n", "firewall": firewall,
            "dhcp": {r["dhcp_section"]: "114,http://" + meta.get("gatewayfqdn", "") for r in extra
                     if NAME.fullmatch(r["dhcp_section"]) and re.fullmatch(r"[A-Za-z0-9.-]+", meta.get("gatewayfqdn", ""))}}


def install_script(config, previous=None):
    """Return a reviewed shell transaction; only manager-owned rules/files change."""
    previous = previous or {}
    assets = {
        "/usr/lib/opennds/opennds-extra-interface.sh": (Path(__file__).parent / "router/opennds-extra-interface.sh").read_text(),
        "/usr/lib/opennds/libopennds.sh": (Path(__file__).parent / "router/libopennds-extra-wrapper.sh").read_text(),
        "/etc/init.d/opennds-extra-interface": (Path(__file__).parent / "router/opennds-extra-interface.init").read_text(),
        "/etc/opennds-manager/networks.conf": config["devices"],
        "/etc/opennds-manager/networks-guard.nft": config["guard"],
    }
    uploads = []
    for path, content in assets.items():
        # Preserve exact bytes: an extra heredoc newline makes every discovery
        # detect changed helpers and reload the firewall again.
        uploads.append(f"printf '%s' {shlex.quote(content)} > {shlex.quote(path + '.manager-new')}\n"
                       f"chmod {755 if path.endswith('.sh') or '/init.d/' in path else 600} {shlex.quote(path + '.manager-new')}\n"
                       f"mv {shlex.quote(path + '.manager-new')} {shlex.quote(path)}")
    files = list(assets) + ["/etc/config/firewall", "/etc/config/dhcp", "/usr/lib/opennds/libopennds-extra-base.sh"]
    uci = []
    for name in sorted(set(previous.get("firewall", {})) | set(config["firewall"])):
        if NAME.fullmatch(name) and name.startswith("nds_mgr_"):
            uci.append(f"delete firewall.{name}")
    for name, fields in config["firewall"].items():
        uci.append(f"set firewall.{name}={shlex.quote(fields['type'])}")
        uci.extend(f"set firewall.{name}.{key}={shlex.quote(str(value))}" for key, value in fields.items() if key != "type")
    for name, option in previous.get("dhcp", {}).items():
        if NAME.fullmatch(name):
            uci.append(f"del_list dhcp.{name}.dhcp_option_force={shlex.quote(option)}")
    for name, option in config["dhcp"].items():
        uci += [f"del_list dhcp.{name}.dhcp_option_force={shlex.quote(option)}",
                f"add_list dhcp.{name}.dhcp_option_force={shlex.quote(option)}"]
    file_words = " ".join(shlex.quote(p) for p in files)
    uci_commands = "\n".join("uci -q " + line + (" || true" if line.startswith(("delete ", "del_list ")) else "")
                             for line in uci + ["commit firewall", "commit dhcp"])
    return r'''set -eu
opennds -v 2>&1 | grep -Eq '(^|[^0-9])10\.3\.1([^0-9]|$)'
backup_dir="/root/opennds-manager-backups/networks-$(date +%Y%m%d-%H%M%S)-$$"
mkdir -p "$backup_dir" /etc/opennds-manager
chmod 700 "$backup_dir"
''' + f"for file in {file_words}; do\n" + r'''    if [ -e "$file" ]; then cp -p "$file" "$backup_dir/$(basename "$file")"; fi
done
nft list table inet nds_extra_guard > "$backup_dir/live-guard.nft" 2>/dev/null || true
old_pid="$(pidof opennds)"
dispatch() {
    while read -r table chain; do
        nft -a list chain ip "$table" "$chain" 2>/dev/null |
        while IFS= read -r rule; do
            case "$rule" in
                *'comment "manager-extra-'*)
                    if [ "$1" = delete ]; then
                        printf 'delete rule ip %s %s handle %s\n' "$table" "$chain" "${rule##*# handle }"
                    else
                        printf 'add rule ip %s %s %s\n' "$table" "$chain" "${rule%# handle *}"
                    fi
                    ;;
            esac
        done
    done <<'DISPATCH_CHAINS'
nds_mangle ndsPRE
nds_mangle ndsPOST
nds_mangle ndsINC
nds_nat ndsPRE
nds_filter ndsINP
nds_filter ndsFWD
DISPATCH_CHAINS
}
dispatch add > "$backup_dir/dispatch-restore.nft"
rollback() {
    /etc/init.d/opennds-extra-interface stop 2>/dev/null || true
    uci -q revert firewall || true
    uci -q revert dhcp || true
''' + f"    for file in {file_words}; do\n" + r'''        if [ -e "$backup_dir/$(basename "$file")" ]; then
            cp -p "$backup_dir/$(basename "$file")" "$file"
        else rm -f "$file"; fi
    done
    if [ -s "$backup_dir/live-guard.nft" ]; then
        { echo 'delete table inet nds_extra_guard'; cat "$backup_dir/live-guard.nft"; } | nft -f - || true
    fi
    { dispatch delete; cat "$backup_dir/dispatch-restore.nft"; } > "$backup_dir/dispatch-rollback.nft"
    nft -f "$backup_dir/dispatch-rollback.nft" || true
    rm -f /tmp/opennds-networks-guard-sum
    /etc/init.d/firewall reload || true
    /etc/init.d/dnsmasq reload || true
    /etc/init.d/opennds-extra-interface restart 2>/dev/null || true
    echo "Network apply failed; restored files from $backup_dir" >&2
}
trap rollback EXIT
/etc/init.d/opennds-extra-interface stop 2>/dev/null || true
if ! grep -q 'exec /usr/lib/opennds/libopennds-extra-base.sh' /usr/lib/opennds/libopennds.sh; then
    cp -p /usr/lib/opennds/libopennds.sh /usr/lib/opennds/libopennds-extra-base.sh
fi
''' + "\n".join(uploads) + "\n" + r'''
rm -f /tmp/opennds-networks-guard-sum
/usr/lib/opennds/opennds-extra-interface.sh once
''' + uci_commands + r'''
fw4 check
/etc/init.d/firewall reload
/etc/init.d/dnsmasq reload
/etc/init.d/opennds-extra-interface enable
/etc/init.d/opennds-extra-interface restart
[ "$(pidof opennds)" = "$old_pid" ]
trap - EXIT
printf 'Network attachments applied. Backup: %s\n' "$backup_dir"
'''
