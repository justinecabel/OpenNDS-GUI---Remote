# LAN and WAN SQM policy placement

Implemented 10 October 2026; shared WAN Daily and SQM display names added 13 October 2026.

The manager automatically places hard caps, delay, Punish and overuse limits on an enabled CAKE queue for the client's LAN. If that LAN queue is disabled or absent, it uses the enabled CAKE queue on `WAN_IFACE`. Different LANs can use different placements simultaneously. Duplicate queues, enabled non-CAKE queues, or zero rates in either direction produce an explicit runtime error.

## Choosing placement

SQM mode offers **Single interface** and **Multiple interfaces**. Existing installations default to Multiple without changing queues. Single enables the selected configured interface and disables the others, including their Daily rules, while retaining their normal bandwidth/settings. It shows only the selected queue, with one inline runtime badge; the separate all-queue status card is hidden in Single mode. Multiple retains its status list. Switching back to Multiple preserves the current enabled flags; enable additional queues individually. Configure additional interfaces in Multiple mode before selecting them in Single. Apply mode is explicit and may briefly interrupt affected queues; it does not restart openNDS or networking. The single-interface restriction is also enforced by the settings API.

Use SQM → Add interface to configure the WAN device. Enable WAN CAKE with positive download/upload rates, then disable the LAN queues that should use WAN shaping. Keeping an enabled LAN CAKE queue makes that LAN retain its existing behavior. Enabling it again moves its policies back automatically. The manager does not change your queue selection on deployment.

Daily is now tied to its own interface’s enabled Baseline. Turning that Baseline off automatically turns its Daily rule off, clears forced activation, and grays its controls; turning Baseline back on leaves Daily off. Device policies still fall back to WAN independently. For WAN-only SQM, use the shared WAN Daily rule.

Daily rules remain associated with each LAN and its own tracked WAN usage. They appear with their LAN in SQM, including enabled rules without a LAN queue; Add interface can open a LAN's daily settings without applying a base queue. Each LAN's threshold, forced activation and restore rates remain independent. The WAN editor also offers one optional shared Daily rule. It compares tracked RX + TX on `WAN_IFACE` (all LANs, router traffic and both IP families) with its own threshold and caps the WAN aggregate when reached. Apply until midnight forces that shared cap for today; midnight or disabling restores the saved WAN Baseline. Positive Daily rates and an enabled WAN CAKE queue are required. Per-LAN and per-device ceilings remain in place beneath the shared aggregate, so the tighter applicable cap wins. Shared usage comes from `wan-traffic.json`, independently of the client-only Overview and per-LAN IPv4 counters. Accounting cannot reconstruct unobserved traffic.

## Feature behavior

| Feature | LAN placement | WAN placement |
| --- | --- | --- |
| Per-device hard upload/download caps | Existing private-IP classification | NAT-aware connection marks and per-device classes |
| Added delay, Punish delay/loss/caps | LAN download leaf | WAN download IFB leaf |
| Overuse detection and final cap | Existing detection and LAN enforcement | Same detection, WAN enforcement |
| Daily WAN usage rule | Changes that LAN queue's aggregate rates | Changes only that LAN's parents under the shared WAN aggregate |
| Native openNDS session timeout, quotas and rate parameters | Existing authentication/refresh path | Same path; separate from kernel queue placement |
| Local traffic | Traffic traversing the LAN's shaped interface can be affected | LAN-to-LAN traffic is excluded from the WAN classifier |

SQM entries support saved display names such as `Internet (eth0)`; names live in manager-local `sqm-names.json` and never rename router devices or apply queues. Blank restores the discovered network name.

SQM status lists the actual configured queues, including WAN, with rates and an Active/Off/Checking/Error badge. Full diagnostics are expandable under Details. Limits retains the separate per-LAN policy placement view.

The WAN aggregate remains an upper bound shared by all traffic using that WAN queue. Each LAN's daily ceiling and each device's ceiling can reduce its share further. Trusted clients remain excluded from device caps, delay, loss and overuse; aggregate queue limits still apply.

SQM settings load from a manager-side snapshot published by the existing controller about every 10 seconds, reusing its existing router reads. Cold, invalidated or over-30-second snapshots show the loader until refreshed. Reload and post-save verification read the router directly; writes always validate current router settings. Runtime verification remains separate from this settings snapshot.

## Runtime status

SQM and Limits show one row per LAN, its actual LAN/WAN placement, device-policy count and active daily rule. Settings polling reads `/api/qos/status` from memory and does not reload form fields or create extra router requests.

- **Active:** applicable limits and kernel queues/classifiers were verified.
- **Ready:** queue checks passed; no device or daily policies are currently active.
- **Pending/Error:** verification is incomplete or an operation/prerequisite failed; the reason is shown.
- **Not verified:** the controller's status is stale or a status fetch failed.

Verification checks installed classes, qdisc settings and classifier identities. It does not imply the manager continuously measures end-to-end throughput for every real client. Native openNDS session state still has its existing separate pending indicators.

## WAN implementation and prerequisites

`wan_shaping.py` builds one HTB hierarchy, root handle `7ea0:`, on the actual WAN ingress IFB and WAN egress device. LAN parents and device leaves have persistent, non-reused identities in `/data/wan-qos.json`. Compatible rate changes preserve roots and marks. Leaf-kind changes replace only the affected leaf. Recovery uses scoped SQM restart with backoff; it does not restart firewall, networking or openNDS.

The independent `inet nds_mgr_wan_qos` nft table classifies forwarded IPv4 traffic after normal firewall acceptance. It marks connections and packets in both directions while preserving bits 0–19. Bits 20–31 (`0xfff00000`) are reserved for these classes. The priority-1 u32 rule requests node `::1` so the kernel allocates its hash table separately from SQM’s existing priority-10 u32 redirect. Ownership and cleanup use the inspected handle and ctinfo mask. `ctinfo cpmark` restores those identity bits before SQM's ingress redirect, so download selection works before destination NAT. Private-IP WAN header filters alone cannot do this. See the primary [Linux ctinfo implementation](https://raw.githubusercontent.com/torvalds/linux/master/net/sched/act_ctinfo.c) and [iproute2 ctinfo manual](https://raw.githubusercontent.com/iproute2/iproute2/main/man/man8/tc-ctinfo.8).

WAN policy shaping requires:

- Positive CAKE aggregate rates in both directions and exactly one discoverable IFB redirect.
- Software and hardware flow offloading disabled; offloaded flows bypass these queues. The manager reports this prerequisite and does not silently change firewall settings.
- `act_ctinfo` / `kmod-sched-ctinfo`. The manager first loads the module, then attempts installation with `apk` if needed when WAN policy placement is selected. Failures remain visible and retry with backoff.
- No conflicting ingress filter at priority 1, connmark-bit allocation, or custom conntrack zones. This implementation uses the ordinary OpenWrt IPv4 NAT/zone-0 path. IPv6 per-device shaping and TCP/UDP port bypass rules are not implemented.

Cleanup checks ownership, deletes only its own nft table and ingress action, verifies removal, and restores ordinary enabled WAN SQM when all LANs move back. Failed cleanup retains ownership/error state for retry.

## Validation

- **187 offline Python tests passed**, including mixed placement, disabled/deleted LAN fallback, native session refresh, overuse dispatch, NAT classification, unique identities, direction mapping, per-LAN daily caps, LAN restore points, partial failures, cleanup ownership, stale status and verification failures.
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
