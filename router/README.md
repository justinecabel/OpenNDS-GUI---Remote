# Discovered OpenWrt LANs

Open the manager's **Networks** page (`/#mode`), choose **Scan OpenWrt**,
select each LAN's behavior, and use **Apply networks**. Available choices are
Portal, Auto-auth, Auto-trust, and Router defaults for additional LANs.
The native openNDS LAN always has an authentication behavior.

The manager reads netifd's interface dump, firewall-zone membership, DHCP
configuration, and the running openNDS gateway identity. Bridges and VLAN
interfaces work without fixed device names or subnet addresses. WAN/default
route interfaces, down interfaces, absent IPv4/DHCP, ambiguous zones, and
shared devices/overlapping LANs display a reason instead of an editable mode.
An unconfigured NIC needs an OpenWrt interface, static IPv4, DHCP and firewall
zone before it can be adopted here. IP/DHCP setup stays in OpenWrt.

Persistent `data/networks.json` saves behavior by OpenWrt interface name.
A background scan every minute reconciles changed addresses and devices;
new LANs retain Router defaults until selected. Previous `PORTAL_SUBNETS`
configuration is imported once when no saved network settings exist.
The compatibility `/api/mode` endpoint changes the native LAN only.
Switching one LAN to Portal logs out affected automatic sessions without
changing the other LANs. Manual trusted MACs remain trusted.

Additional LAN attachment supports **openNDS 10.3.1** and shares its original
process/client registry. `network_policy.py` generates the router configuration,
firewall permissions, device admission map and independent authentication
guard from the current scan. It uses the router's configured FAS address and
port. Configure the manager FAS under Portal before attaching an additional
LAN; the FAS must be IPv4 and directly reachable through a discovered LAN.

The generated files live in `/etc/opennds-manager/networks.conf` and
`networks-guard.nft`. The library wrapper delegates to the saved base library,
preserving the existing connected-page modification. The procd helper adds
or removes only comment-tagged `manager-extra-` dispatch rules; native client
rules, session counters and primary dispatch stay intact. Its independent
guard denies unauthenticated forwarding and additional-LAN IPv6 forwarding.
Only the FAS origin is source-NATed so the portal host needs no client-subnet
return route. Other network access remains subject to OpenWrt's firewall.

Application backs up files and the guard/dispatch configuration in
`/root/opennds-manager-backups/networks-<timestamp>-<pid>`, restores them on
failure, and checks that the openNDS PID is unchanged. Stopping the helper
retains existing rules and the guard. Ordinary native openNDS restarts are
repaired by the helper. An openNDS package upgrade can replace the wrapper;
review compatibility and reapply attachments after an upgrade.

All selected LANs use native session limits, WAN accounting and DNS history.
SQM hard caps, added latency, overuse queues and Punish remain limited to the
primary managed LAN. Additional LANs show **Session limits**, not TC pending.
Coins, vouchers and paid-time accounting are not implemented.

The previous fixed-interface installer has been replaced by the Networks UI.
