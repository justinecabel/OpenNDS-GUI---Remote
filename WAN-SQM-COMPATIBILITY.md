# LAN and WAN SQM policy placement

Implemented 10 October 2026, superseding the earlier incompatibility investigation.

The manager automatically places hard caps, delay, Punish and overuse limits on an enabled CAKE queue for the client's LAN. If that LAN queue is disabled or absent, it uses the enabled CAKE queue on `WAN_IFACE`. Different LANs can use different placements simultaneously. Duplicate queues, enabled non-CAKE queues, or zero rates in either direction produce an explicit runtime error.

## Choosing placement

Use SQM → Add interface to configure the WAN device. Enable WAN CAKE with positive download/upload rates, then disable the LAN queues that should use WAN shaping. Keeping an enabled LAN CAKE queue makes that LAN retain its existing behavior. Enabling it again moves its policies back automatically. The manager does not change your queue selection on deployment.

Daily rules remain associated with each LAN and its own tracked WAN usage. They appear with their LAN in SQM, including enabled rules without a LAN queue; Add interface can open a LAN's daily settings without applying a base queue. A WAN editor does not expose a combined daily rule. Each LAN's threshold, forced activation and restore rates remain independent.

## Feature behavior

| Feature | LAN placement | WAN placement |
| --- | --- | --- |
| Per-device hard upload/download caps | Existing private-IP classification | NAT-aware connection marks and per-device classes |
| Added delay, Punish delay/loss/caps | LAN download leaf | WAN download IFB leaf |
| Overuse detection and final cap | Existing detection and LAN enforcement | Same detection, WAN enforcement |
| Daily WAN usage rule | Changes that LAN queue's aggregate rates | Changes only that LAN's parents under the shared WAN aggregate |
| Native openNDS session timeout, quotas and rate parameters | Existing authentication/refresh path | Same path; separate from kernel queue placement |
| Local traffic | Traffic traversing the LAN's shaped interface can be affected | LAN-to-LAN traffic is excluded from the WAN classifier |

The WAN aggregate remains an upper bound shared by all traffic using that WAN queue. Each LAN's daily ceiling and each device's ceiling can reduce its share further. Trusted clients remain excluded from device caps, delay, loss and overuse; aggregate queue limits still apply.

## Runtime status

SQM and Limits show one row per LAN, its actual LAN/WAN placement, device-policy count and active daily rule. Settings polling reads `/api/qos/status` from memory and does not reload form fields or create extra router requests.

- **Active:** applicable limits and kernel queues/classifiers were verified.
- **Ready:** queue checks passed; no device or daily policies are currently active.
- **Pending/Error:** verification is incomplete or an operation/prerequisite failed; the reason is shown.
- **Not verified:** the controller's status is stale or a status fetch failed.

Verification checks installed classes, qdisc settings and classifier identities. It does not imply the manager continuously measures end-to-end throughput for every real client. Native openNDS session state still has its existing separate pending indicators.

## WAN implementation and prerequisites

`wan_shaping.py` builds one HTB hierarchy, root handle `7ea0:`, on the actual WAN ingress IFB and WAN egress device. LAN parents and device leaves have persistent, non-reused identities in `/data/wan-qos.json`. Compatible rate changes preserve roots and marks. Leaf-kind changes replace only the affected leaf. Recovery uses scoped SQM restart with backoff; it does not restart firewall, networking or openNDS.

The independent `inet nds_mgr_wan_qos` nft table classifies forwarded IPv4 traffic after normal firewall acceptance. It marks connections and packets in both directions while preserving bits 0–19. Bits 20–31 (`0xfff00000`) are reserved for these classes. `ctinfo cpmark` restores those identity bits before SQM's ingress redirect, so download selection works before destination NAT. Private-IP WAN header filters alone cannot do this. See the primary [Linux ctinfo implementation](https://raw.githubusercontent.com/torvalds/linux/master/net/sched/act_ctinfo.c) and [iproute2 ctinfo manual](https://raw.githubusercontent.com/iproute2/iproute2/main/man/man8/tc-ctinfo.8).

WAN policy shaping requires:

- Positive CAKE aggregate rates in both directions and exactly one discoverable IFB redirect.
- Software and hardware flow offloading disabled; offloaded flows bypass these queues. The manager reports this prerequisite and does not silently change firewall settings.
- `act_ctinfo` / `kmod-sched-ctinfo`. The manager first loads the module, then attempts installation with `apk` if needed when WAN policy placement is selected. Failures remain visible and retry with backoff.
- No conflicting ingress filter at priority 1, connmark-bit allocation, or custom conntrack zones. This implementation uses the ordinary OpenWrt IPv4 NAT/zone-0 path. IPv6 per-device shaping and TCP/UDP port bypass rules are not implemented.

Cleanup checks ownership, deletes only its own nft table and ingress action, verifies removal, and restores ordinary enabled WAN SQM when all LANs move back. Failed cleanup retains ownership/error state for retry.

## Validation

- **187 offline Python tests passed**, including mixed placement, disabled/deleted LAN fallback, native session refresh, overuse dispatch, NAT classification, unique identities, direction mapping, per-LAN daily caps, LAN→WAN→LAN restore points, partial failures, cleanup ownership, stale status and verification failures.
- **5 dependency-free JavaScript checks passed.** Targeted Firefox checks cover both themes at phone/tablet/desktop sizes, every status state, failed/stale reads, safe text, settings drafts during polling and navigation, and all nine pages. Full optional Playwright suite was not rerun.
- **Real packet lab passed** in isolated Linux user/network/mount namespaces. Two private client networks used ordinary WAN masquerade, actual HTB/CAKE/IFB/ctinfo/fw/nft classifiers, TCP and UDP traffic. Measured caps: client A ≈1.05/2.10 Mb/s upload/download; client B ≈2.80/3.84 Mb/s. A's daily download ceiling reduced it to ≈1.05 Mb/s while B remained ≈3.84 Mb/s; restoring A returned ≈2.10 Mb/s. Configured 100ms WAN delay measured ≈100ms; local routed ping remained under 1ms and local throughput exceeded the WAN aggregate. Punish removal and nonzero kernel class counters were verified.
- Deployment retained the existing enabled `br-lan` and `eth2` queues/rates. Live checks showed verified LAN limits, fresh Clients and healthy APIs. No real client, mode or SQM selection was changed for experimental testing. WAN deployment on the actual router has not been throughput-tested.

Reproduce offline tests:

```sh
docker run --rm --network none \
  --mount "type=bind,source=$PWD,target=/work,readonly" \
  -w /work -e PYTHONDONTWRITEBYTECODE=1 \
  opennds-opennds-manager:latest \
  python -m unittest discover -s tests -q
```

The explicit packet lab is `tests/wan_packet_lab.py`; never run it directly in the host network namespace. With `ip`, `tc`, `nft`, `iperf3`, `ping` and the required kernel support available, run:

```sh
unshare --user --map-root-user --net --mount sh -c '
  mount -t tmpfs tmpfs /run
  echo 1 > /proc/sys/net/ipv4/ip_forward
  python3 -B tests/wan_packet_lab.py
'
```

It creates and removes disposable interfaces/processes/namespaces. The runtime Docker VM can have a different kernel/module set from the host; its missing IFB/CAKE modules do not establish a failure of the OpenWrt implementation.
