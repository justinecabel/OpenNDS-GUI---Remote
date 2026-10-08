# openNDS Manager - AI Agent Handover

Context for any AI agent continuing work on this project. Read fully before editing.

## 1. Purpose

A web UI, running in a Docker container, to manage an **openNDS** captive portal that runs on an **OpenWrt VM**. The container does not run openNDS. It controls the router over SSH.

```
Browser/client -> Flask/gunicorn (container :8080)
                       |
                       +--SSH (ControlMaster)--> OpenWrt VM (192.168.1.1): ndsctl, uci, nft, logread
openNDS FAS redirect --------------------------> manager /fas (192.168.1.198:8080)
```

## 2. Environment facts (verified)

| Item | Value |
|---|---|
| Docker host | Debian, user `justine`, project dir `/home/justine/Data/Open NDS` |
| Router | OpenWrt VM, `192.168.1.1`, SSH as `root` with key `./ssh/id_ed25519` (mounted at `/ssh`) |
| openNDS | version 10.3.1, config in UCI `/etc/config/opennds` |
| Package manager | `apk` (NOT `opkg`) |
| SQM | `sqm-scripts` and `kmod-netem` installed; queue config in `/etc/config/sqm` (interface `br-lan`, cake) |
| Portal files | Manager-local `./data/hosted-portal`; the previous router directory is archived after FAS setup |
| Managed interface | `br-lan`; clients are on 192.168.1.0/24 |
| UI auth | HTML sign-in form with a 12-hour session cookie; credentials and `SESSION_SECRET` are in `docker-compose.yml` (`ADMIN_USER` / `ADMIN_PASS`) |

The host's own `ssh` to the router needs `-o UserKnownHostsFile=/tmp/kh` or similar. The container manages its own known_hosts (`/tmp/known_hosts`).

## 3. File layout

```
app.py                 Flask backend (all logic)
templates/index.html   Single-page UI (vanilla JS, no build step)
static/classic.css     Saved original manager theme and base layout
static/themes.css      Hacker palette and responsive theme selectors
static/themes.js       Early theme restore and cross-tab preference sync
static/buttons.css     Shared manager/sign-in button hierarchy
static/navigation.css  Responsive masthead/navigation styles
static/clients.css     Compact mobile client table/actions
static/settings.css    Flat settings sections with independent heights
static/overview.css    Full-width DNS ranking and watchlist dialog
Dockerfile             python:3.12-slim + openssh-client, gunicorn gthread
docker-compose.yml     env config + volumes (./ssh:/ssh:ro, ./data:/data)
portal/                built-in hosted captive-portal default
ssh/                   SSH key pair (id_ed25519) - secret, do not commit
data/                  Persistent state written by the app (see section 6)
AGENTS.md              This file
```

## 4. Deploy / operate

```
cd "/home/justine/Data/Open NDS"
docker compose up -d --build        # rebuild after ANY change to app.py/templates/Dockerfile
docker compose logs --tail 50       # app log + gunicorn access log
```

UI: http://localhost:8080. After a UI change tell the user to hard-reload (Ctrl+Shift+R). Templates are baked into the image, so a rebuild is required for every edit.

Quick API checks (use credentials from compose):
```
curl -s -u USER:PASS localhost:8080/api/clients
curl -s -u USER:PASS localhost:8080/api/mode
```
The first request right after a restart can return 502 while the SSH connection comes up.

## 5. Backend architecture (`app.py`)

- `ssh(cmd, data=None, timeout=15)`: runs a command on the router via the `ssh` CLI. Uses `ControlMaster=auto` / `ControlPersist=60` for speed. Serialised with `_ssh_lock`. Logs non-zero exits and timeouts. Returns `(rc, stdout bytes, stderr str)`.
- One manager-side collector owns periodic `ndsctl json` reads (`CLIENTS_SNAPSHOT_INTERVAL`, default 3 seconds). Auto-auth and the Client list consume its snapshot; the one-second Overview loop reads only kernel interface counters. `/api/clients` serves the latest snapshot immediately, so browser tabs do not create competing SSH/conntrack reads; the UI shows the snapshot age and stale state. Runtime trust state is refreshed separately at the low `NDS_STATUS_INTERVAL` cadence (default 15 seconds).
- `ndsctl(args)`: wraps `ssh("ndsctl ...")` and retries up to 6 times (0.5 s) when openNDS replies "busy".
- Global error handlers: `TimeoutExpired` -> 504, any other exception -> logged traceback + 500 JSON.
- `requires_auth` decorator: browser requests without a session redirect to `/login`; API calls can use the session or the existing Basic credentials for scripts such as `curl`.
- Input validation: MACs via `MAC_RE`; SQM values validated against allow-lists; hosted portal paths normalised and confined to `HOSTED_PORTAL_DIR`; all shell arguments built with `shlex.quote` or validated first.

### API routes

| Route | Method | Function |
|---|---|---|
| `/` | GET | UI |
| `/login` | GET/POST | HTML sign-in page |
| `/logout` | POST | End browser session |
| `/api/status` | GET | `ndsctl status` text |
| `/api/overview` | GET | Connected-client count plus tracked all-WAN traffic and live rates (small 1-second response) |
| `/api/overview/history` | GET | 24-hour WAN traffic history for the overview chart (latest hour per-second; earlier history per-minute) |
| `/api/domains` | GET | Counts for explicitly tracked LAN DNS domains, including queried subdomains and requesting hostnames |
| `/api/domains/watch` | PUT | Replace the tracked-domain watch list and reset its counts |
| `/api/clients` | GET | Merged client list (see 5.1) |
| `/api/clients/<mac>/history` | GET | Local per-client WAN rate history for the expanded Client view (latest hour per-second; older history per-minute; no router read) |
| `/api/clients/<mac>/dns` | GET | Refresh and return retained DNS lookups for one expanded client; queried only while its dialog is open |
| `/api/clients/name` | PUT | Save or clear a persistent custom display name for a MAC |
| `/api/action` | POST | `auth`, `deauth`, `trust`, `untrust`, `block`, `unblock`, `punish`, `unpunish`, `delete` (offline history), `debuglevel`, `start/stop/restart` |
| `/api/config` | GET/PUT | Read/write `/etc/config/opennds` (writes `.bak` first) |
| `/api/logs` | GET | `logread \| grep -i nds \| tail -n N` |
| `/api/portal` | GET | List manager-hosted portal files |
| `/api/portal/file?name=` | GET/PUT/DELETE | Read/save/delete a local portal file |
| `/api/portal/upload` | POST | Multipart upload to the local portal |
| `/api/portal/template/<current\|default>` | GET | Download local portal ZIP or saved local baseline |
| `/api/portal/template` | POST | Validate and replace the local portal ZIP; preserves local `.bak` |
| `/api/portal/template/folder` | POST | Package and host a selected browser folder; strips one wrapper folder and ignores macOS metadata |
| `/api/portal/fas` | GET/POST | Read or configure secure level-1 FAS; config backs up the router file, disables ThemeSpec, switches manager mode to portal, then restarts openNDS |
| `/api/portal/router/archive` | POST | After FAS verification, archive router portal files to a timestamped backup |
| `/fas` | GET | Public FAS page; validates request and supplies the openNDS continue action |
| `/portal-content/<path>` | GET | Serve public local portal assets with scripts disabled |
| `/portal-preview/<path>` | GET | Local asset preview served with `Content-Security-Policy: sandbox` |
| `/api/sqm` | GET/PUT | Read/write first `sqm.@queue[0]` via `uci`, then restart sqm |
| `/api/mode` | GET/PUT | Operation mode (section 7) |
| `/api/limits` | GET/PUT | Default + per-MAC limits, including gateway latency (section 7) |
| `/api/limits/profile` | PUT/DELETE | Save or remove an editable named Limits profile |
| `/api/punishment` | GET/PUT | Extra gateway delay plus rate caps for manually punished clients (section 7) |

### 5.1 `/api/clients` merge logic

One combined SSH call returns: router epoch, whether the `nds_block` nft table exists, trusted MACs (from `ndsctl status`), and `/tmp/dhcp.leases`. Then:
- `ndsctl json` clients get `hostname` (from DHCP leases, then history), `online`, `trusted`, `blocked`, and WAN-only usage.
- Each current client gets its configured added gateway delay and whether it is in the persistent punishment list.
- **online** = `last_active` within `ONLINE_SECS` (default 300 s) of the router's clock.
- **Offline** entries are synthesised from the history in `data/seen.json`, DHCP leases, and the blocked/trusted MAC sets. They appear with key `off-<mac>` and `state: "Offline"`.
- If blocked MACs exist but the router's nft table is missing (e.g. router reboot), blocks are re-applied.

## 6. Persistent state (`./data`, mounted at `/data`)

| File | Content |
|---|---|
| `seen.json` | `{mac: {mac, ip, hostname, last_seen}}` history for offline display |
| `client-names.json` | `{mac: custom display name}` overrides for client-list hostnames |
| `deleted.json` | list of MACs dismissed from offline display; automatically cleared when a device reconnects |
| `blocked.json` | list of blocked MACs |
| `mode.json` | `{"mode": "portal"|"auto_trust"|"auto_auth", "auto_trusted": [macs], "auto_authed": [macs]}` |
| `limits.json` | `{"default": {...}, "devices": {mac: {...}}, "profiles": {name: {...}}}` limit profiles |
| `applied.json` | `{mac: signature}` last limits pushed to openNDS |
| `session-refresh.json` | Pending explicit Limits saves by MAC, with logout/login stage; retries survive manager restarts |
| `punishment.json` | manual punishment policy (added delay, caps, punished MACs) |
| `punishment-tc.json` | managed traffic-control hierarchy state used to restore or refresh SQM safely |
| `sqm-conditional.json` | daily-usage SQM rule, its current state, and the rates to restore |
| `traffic.json` | LAN interface counter baseline, one-second traffic-rate history (60 minutes), and daily/monthly totals |
| `wan-traffic.json` | WAN interface counter baseline, live rates, latest-hour per-second and 24-hour per-minute rate history, and persistent daily/monthly totals used by Overview and the SQM daily-usage rule |
| `wan-usage.json` | per-client (MAC identity with current IPv4 displayed) WAN-only `today` and `month` totals, active connection-counter baselines, router boot ID, and server-calculated rates |
| `client-wan-history.json` | local 24-hour history of one-minute per-client WAN down/up rate samples for the expanded Client graph |
| `domain-rank.json` | tracked-domain list, 24-hour DNS count buckets, dnsmasq log offset, and the last 100 distinct DNS names per MAC |
| `portal-default.zip` | legacy snapshot of the prior router-hosted portal |
| `hosted-portal/` | active portal files served by the manager; previous version is `hosted-portal.bak/` |
| `hosted-portal-default.zip` | manager-hosted portal baseline captured on first download |
| `fas.key` | generated shared secret for level-1 FAS; persistent and never returned by the API |

## 7. Features and how they work

### Block / unblock
**openNDS 10.3.1's `ndsctl` has NO block/unblock/allow commands.** Only: `status json stop auth deauth trust untrust debuglevel b64decode b64encode`. Block is implemented by the manager: `deauth` the client, then maintain an nft table on the router:

```
table inet nds_block { set blocked { type ether_addr; elements = {...} }
  chain pre { type filter hook prerouting priority -300; policy accept; ether saddr @blocked drop } }
```
The whole table is deleted and re-created atomically on each change (`_apply_blocks`). State of truth is `data/blocked.json`.

### Trust / untrust
`ndsctl trust|untrust <mac>`. This is **runtime only** in openNDS (lost on openNDS restart). Trusted MACs are listed under "Trusted MAC addresses:" in `ndsctl status`; the client JSON `state` does NOT show trusted, so the UI derives `trusted` from the status output. Trusted clients have no quota, rate limit or timeout.

### Operation modes (`/api/mode`)
- `portal` (default): normal captive portal.
- `auto_trust`: a daemon thread (`_auto_trust_loop` -> `_control_once`, every `AUTOTRUST_INTERVAL` s, default 3) trusts every client from `ndsctl json` that is not already trusted and not blocked, recording them in `mode.json -> auto_trusted`. Trusted clients are never limited.
- `auto_auth`: logs in every Preauthenticated client with `ndsctl auth <mac> timeout up down upq downq` using its effective limits; recorded in `auto_authed`. Its FAS request is redirected straight back to openNDS for authentication, so the portal page is not shown. Switching to `portal` deauths them.
- Switching away from `auto_trust` untrusts only the `auto_trusted` MACs (manual trusts are preserved), then clears the list.
- The auto-control and traffic-sampler threads start at import time; gunicorn runs **1 worker**, so there is exactly one of each. Do not raise `--workers` without moving the loops to a single owner.

### Limits (portal and auto_auth modes)
Units in the UI: timeout minutes, rates KB/s, quotas kB, and gateway latency ms; blank = openNDS global setting (or, for a device latency field, inherit the default), 0 = unlimited rates/quotas or no added latency. Rates are converted to the kbit/s required by `ndsctl` before being applied. Effective limits = device override, else default. A non-zero effective rate is also a hard per-client HTB/CAKE cap on both shared SQM directions, so it cannot be exceeded by openNDS's adaptive packet-rate limiter; it requires active CAKE SQM. Default policy can optionally configure an overuse policy: it applies only to devices without a saved device override, and the Default Up and Down rates are the allowable maximums; when a direction stays near its allowable cap (95%) for the chosen trigger period, CAKE applies the actual final limit. It remains applied until a rolling average of its three latest control samples (about nine seconds) stays below 90% of its final cap for the reset period, then restores the normal allowable rate. The rule is per direction and can repeat while high use continues. Gateway latency is applied gateway-to-client through the same hierarchy and does not reauthenticate or restart a session. A manual Punish cap and a Limits cap combine at the lower rate. The editable Open, Standard, and Guest profiles are safe starters only and never apply until copied into Default or a Device profile. openNDS only accepts auth parameters for a Preauthenticated client, so when an authenticated client needs a changed profile the control loop deauthenticates then immediately reauthenticates it with the complete profile. If that auth does not complete, it retries the profile while the client remains Preauthenticated rather than leaving a portal-mode client stranded. It also compares configured live rate/quota fields with `ndsctl json`, which recovers after an openNDS/router restart invalidates the runtime profile. All-blank openNDS limits never trigger an auth call. Re-auth restarts session counters.

### Punishment
**Punish** is manual. It adds the configured delay (default 100 ms) to gateway-to-client traffic, optional packet loss (default 0%), and configured download/upload caps (defaults 128/64 KB/s). The client table shows the total added ping (Limits latency plus manual punishment delay) rather than measuring or thresholding ICMP latency. A low download cap plus 1–3% packet loss makes adaptive live streams buffer more readily. For every active punished, rate-limited, or latency-limited IPv4 client, the manager creates a separate HTB class on `br-lan` for download and on SQM's ingress IFB (`ifb4br-lan`) for upload. A Limits class uses its effective non-zero rate; a manual punishment and Limits class uses the lower rate. A latency-only class retains the SQM bandwidth. Delay/loss is added only to the download class. This requires `kmod-netem`, installed with `apk add kmod-netem`. The action applies or removes this queue immediately; when no active managed client remains, it restarts SQM to restore its UCI-managed qdisc. An SQM apply may briefly reset this hierarchy; the control loop re-applies it within `AUTOTRUST_INTERVAL`. A punished device remains in `punishment.json` until **Unpunish** and is re-applied when it reconnects. Trusted and blocked devices are excluded from delay, loss, and caps.

### SQM
Sets `enabled`, `interface`, `download` (ingress) and `upload` (egress) on `sqm.@queue[0]`, then `uci commit sqm` and `/etc/init.d/sqm restart`. The SQM UI lets the administrator display and enter rates as `KB/s`, `Mb/s`, or `MB/s`; the manager converts the selected display unit to its canonical KB/s value before converting to kbit/s for UCI. On the managed LAN bridge, ingress is traffic from the client (client upload) and egress is traffic to a client (client download); the UI labels this explicitly. The "install sqm-scripts" button was removed because the router uses `apk`.

The optional daily usage rule compares all RX + TX traffic crossing `WAN_IFACE` for the current `TRAFFIC_TZ` day against a GB threshold every 30 seconds. Local LAN traffic is excluded. When reached, it switches SQM ingress/download and egress/upload to the configured KB/s rates. It snapshots the previous SQM rates and restores them when the total drops below the threshold, normally at midnight. WAN totals begin when the persistent counter is installed; traffic before installation or during an unobserved outage is not retroactively reconstructed.
The SQM daily WAN rule also has **Apply now for today**, which enables the rule, applies its configured rates immediately without waiting for the threshold, and keeps them active until the current traffic date ends.

### Overview
The traffic sampler reads both `br-lan` and `WAN_IFACE` byte counters every `TRAFFIC_INTERVAL` seconds (default 1). Overview and its graph use `WAN_IFACE` only: WAN RX is download and WAN TX is upload, so local LAN traffic is excluded. The router-side `opennds-wan-counter` service persistently accumulates WAN bytes in `/etc/opennds-manager/wan-counter.state`; the manager reads that cumulative counter so recorded month totals survive router reboots without restarting networking or firewall rules. It retains the latest hour at a nominal one-second cadence, plus a compact one-minute WAN-rate series for 24 hours. The graph connects close samples and leaves longer gaps visible. It also records live byte rates plus calendar-day and calendar-month totals in `wan-traffic.json`. A delayed interval spanning midnight is divided proportionally between its calendar periods. If the persistent counter file is unavailable, the manager falls back to the live interface counter and starts a fresh baseline on a counter reset. Totals still cannot include traffic from before accounting was installed or during an unobserved outage. Days and months are grouped in `TRAFFIC_TZ` (default `Asia/Manila`).

Client WAN usage is read from NATed IPv4 conntrack flows every `WAN_USAGE_INTERVAL` seconds (default 1), independent of whether the Client list is open. Device identity is the MAC address, with its current IPv4 shown in the UI so a DHCP address change does not lose the current-period totals. The client/IP map is refreshed by the three-second openNDS collector, but the rate and byte counters are overlaid into Client API responses every second without another `ndsctl` call. The manager keeps the latest hour of each active MAC's rates in memory at the same one-second cadence as Overview, and retains a separate one-minute sample per active MAC for 24 hours in a local history file. The client graph endpoint merges these local series and never adds a router read. Each conntrack interval is checked against the same `WAN_IFACE` byte-counter interval; if attribution would exceed physical WAN traffic, the per-client deltas are proportionally capped. The client state is versioned, and the v2 migration discards earlier over-counted client totals and establishes a fresh baseline. Only clients with `last_active` within `ONLINE_SECS` accrue usage; inactive clients retain their totals but cannot continue accumulating. `today` resets at the first `TRAFFIC_TZ` sample of a new date and `month` resets at the first sample of a new calendar month. Rates are calculated from router-side sample timestamps, not browser timing. The saved totals persist across manager restarts, but a new manager process, router boot-ID change, date rollover, month rollover, or gap of at least `WAN_USAGE_MAX_GAP` seconds (default 8) establishes a fresh conntrack baseline and renders the rate unavailable until the next sample, preventing stale traffic from being attributed to a new interval or day.

### Tracked WAN domains
Overview counts only domains that the administrator explicitly adds to the tracked-domain watch list, including their subdomains. The total is a DNS-request count, not a confirmed web visit. Selecting a tracked domain shows its queried hostnames/subdomains and DHCP hostname (or IPv4 address when unnamed) counts. The collector stores its current bucket plus 30-minute buckets in `domain-rank.json`, reads a manager-owned RAM dnsmasq log once a minute, and prunes data older than 24 hours. It discards non-tracked query names immediately after retaining each DHCP MAC's 100 most recent distinct DNS names for the Client-list modal. It enables `logqueries` and `/tmp/opennds-dns-queries.log` only when dnsmasq has no existing log facility; an administrator-configured different facility is never overwritten.

### Manager-hosted portal
The Portal tab hosts files under `data/hosted-portal/`; content is not uploaded to OpenWrt. Folder/ZIP uploads require `index.html`, strip one common outer folder, ignore macOS metadata, and enforce the 200-file / 100-MiB limits. Replacements are staged locally and the previous local directory is retained as `data/hosted-portal.bak/`.

The public `/fas` endpoint implements openNDS secure FAS level 1. It decodes the FAS request, computes the openNDS return token with a generated persistent `data/fas.key`, and renders the local `index.html` with `{{CONTINUE_FORM}}` replaced by the gateway authentication form. Uploaded JavaScript is disabled by CSP; local assets should use `/portal-content/...` URLs. This HTTP service is intended for the trusted LAN. The configured manager address must be reachable from both the router and unauthenticated clients.

The Portal tab's **Configure openNDS** action keeps openNDS enabled, switches the manager from auto-login/trust to captive-portal mode, configures router FAS, removes `themespec_path`, backs up `/etc/config/opennds`, and restarts openNDS. This logs out clients previously auto-authenticated by the manager. **Archive old router portal files** is separate and only allowed after matching FAS settings are verified; it moves the old directory to a timestamped backup rather than deleting it.

### UI behaviour (`templates/index.html`)
- Self-scheduling poll (`poll()`) refreshes only the active read-only tab every second. It skips when the page is hidden or `busy` (an action is in flight) so it never races `ndsctl`. Config/Portal/SQM/Mode are not polled (would clobber edits).
- Overview and client charts use rounded curves through the actual samples, subtle fills, and lighter colors; missing-data gaps remain visible. Their last selected ranges are saved separately in browser localStorage (`opennds-overview-range`, `opennds-client-range`), with a one-hour fallback if storage is invalid or unavailable.
- Overview is the default tab. It shows active clients (within `ONLINE_SECS`), current down/up rates, tracked usage today and this month, distinct download/upload traffic waves for the last 24 hours, and administrator-selected domain counts. Its Time range selector selects 1, 5, 15, or 30 minutes, or 1, 6, or 24 hours. The compact Watchlist button opens a native dialog for adding/removing domains; the DNS ranking spans the full page width. Dialog errors stay visible beside the draft, pending saves serialize, and Escape/backdrop/Close return focus to the trigger. Adding/removing a domain resets those counts; a selected row shows its total requests, queried subdomains, and requesting client-hostname counts.
- Tabs are URL-addressable with fragments such as `/#portal`; refreshes, pasted links, and browser back/forward restore the selected tab. The active navigation button is visibly highlighted and announced as the current page. Status and Config share the `/#status` tab; legacy `/#config` and `?tab=config` links map to it. Only live status is polled; the config file loads once per page and retains unsaved edits across tab changes. Explicit reload asks before discarding edits. The Tools tab has been removed; client action results appear on Clients, and the openNDS restart control is beside Config.
- All tabs share a centered, responsive frame up to 1600px, aligned with the header. Settings (Portal, SQM, Limits, Mode, Punishment, and Status/Config) use full-width stacked sections with plain headings, dividers, and independent content heights; do not use paired/equal-height cards. Wide screens align section labels in a left column and controls on the right; below 900px labels sit above the controls. Fields use compact responsive grids, and Mode is a plain radio list. Overview keeps its metric tiles and side-by-side domain watch/table on desktop, stacked below 900px. Portal groups design, FAS, upload, and downloads; guides/archive remain expandable. Its result reports flattening, ignored metadata, and errors.
- Client table: online indicator, hostname, MAC, IP, state (`BLOCKED`/`TRUSTED`/`PUNISHED` override or `THROTTLED DOWN`/`THROTTLED UP` while an active default-policy overuse throttle is running), last active, stacked WAN Down/Up `Today` and `Month` totals (auto units, 1024 base), server-calculated WAN Down/s and Up/s, and configured total added gateway ping (Limits latency plus manual punishment delay). Punished and trusted devices cannot enter overuse throttle mode. The hostname has an `edit` control for saving a persistent custom display name per MAC; leaving it blank restores the router/DHCP hostname. The list is served from the background client snapshot and shows its sample age/stale state. Selecting a hostname opens the same WAN-wave chart used by Overview, but filtered to that MAC's WAN down/up usage; its Time range selector provides 1, 5, 15, or 30 minutes, or 1, 6, or 24 hours. It is followed by 100 most recent distinct DNS-requested domains and timestamps; the DNS list is refreshed immediately and every three seconds only while that dialog is open. Its Play/Pause button also freezes the green new-entry highlight fade and stops DNS polling while paused. It is not confirmation of a completed site visit. A missing rate is shown as `—` while a fresh baseline is being established; a displayed `0.0` is an actual zero-traffic sample. WAN usage is derived from NATed IPv4 connection tracking on `WAN_IFACE`, so local LAN traffic is excluded; it begins when the manager first sees a connection. On narrow screens, its table scrolls horizontally within the Client-list panel rather than widening the whole page. The pinned right-hand WAN rate/action columns use solid tinted backgrounds and subtle row separators without vertical dividers; offline text is muted without reducing cell opacity. Their sticky offsets are measured from the actual column widths to prevent overlap. At 900px and below, rates scroll with the data and only a neutral 48px action column is pinned. Its three-dot button opens a compact native action dialog with hostname/IP/MAC; desktop and dialog actions share the same eligibility and handlers. The floating bottom scrollbar is desktop-only; mobile uses the table’s own scrollbar. Row buttons toggle: block/unblock, trust/untrust, punish/unpunish; offline rows also have a delete button that removes their saved history entry without changing router state. The API rejects a manual deauth while auto-login is active because it would immediately reconnect.
- SQM Daily WAN includes **Apply now for today**, which manually activates the configured after-threshold rates until midnight; normal threshold-based activation remains available.
- Navigation uses a sticky dark masthead and white icon links, grouped as Overview/Clients, policy pages, then Status/Logs. Below 1100px the current-page button opens a compact two-/three-column menu; selection, Escape, outside clicks, and viewport changes close it. Native fragment links support copying/opening a tab, and keyboard focus returns to the mobile toggle when its menu closes. Scroll margins keep headings visible on direct fragment links.
- UI copy assumes an expert: concise headings/actions, DL/UL labels, WAN (day/month), short client states, relative Seen times, and brief results. Keep units and re-auth/restart effects clear. Gateway Status is a compact summary with full `ndsctl` output under Raw; errors retain diagnostic detail. Avoid restoring instructional paragraphs.
- Manager tabs, client actions, dialogs, and sign-in share `static/buttons.css`: filled blue primary Save/Apply actions, outlined secondary actions, quiet Refresh/Close controls, red destructive actions, and amber disruptive actions. Compact row controls share the same hover, keyboard-focus, disabled, and touch sizing rules. Docker includes the static directory.
- Read-only table refreshes preserve keyboard focus by MAC/control; client and DNS dialogs restore focus to their current row on close. DNS detail stays open across ranking refreshes. Long host/domain names wrap within dialogs and watchlist chips.
- Client-to-Limits navigation awaits the actual settings response. Empty/invalid Device MACs cannot save Default. Limits/SQM actions stay disabled until initial load succeeds; failed loads/saves retain drafts and show errors. Settings saves serialize, disable action controls while pending, and restore them after failures.
- Appearance has Classic (preserved light theme) and Hacker (dark green/cyan terminal theme). Choose in the desktop masthead, mobile navigation footer, or sign-in. `opennds-theme` in localStorage remembers the browser choice and syncs tabs; new/invalid/unavailable preferences default to Hacker. The early shared script restores the theme before paint. Switching redraws both chart palettes/legends and preserves drafts, ranges, dialogs, and polling. Hacker CSS is scoped to `html[data-theme=hacker]`; keep Classic/component styles intact. Manager themes do not replace the hosted captive portal.
- All dynamic text is set via `textContent` (avoid `innerHTML` with server data).

## 8. Gotchas and lessons learned

1. **"busy" from openNDS**: concurrent `ndsctl` calls are rejected. Hence the lock, retries, and pausing the poll during actions.
2. **Gunicorn crash history**: the original single sync worker hit `WORKER TIMEOUT` when the browser held an idle connection. Fixed with `--workers 1 --threads 8 --timeout 90`. Check `docker compose logs` first for any "crash" report.
3. **Router uses `apk`, not `opkg`.** Never emit `opkg` commands.
4. **`ndsctl` command set is smaller than documentation for other versions.** Check `ndsctl` usage on the router before adding features.
5. **ndsctl `json` client fields**: `mac, ip, state (Preauthenticated|Authenticated), session_start, last_active (epoch), download_this_session, upload_this_session (kB), token, ...`. There are no `downloaded`/`uploaded` fields.
6. Files are created in a previous step with `create_file`, which fails on existing files; use edit tools. Avoid multi-replace calls that include an empty/no-op replacement.
7. The SSH key must be in `./ssh/` of the project (an earlier attempt created it in `~/ssh`).
8. Environment values in compose such as `ADMIN_PASS: 2000` are YAML ints; the container receives them as strings, which is fine.

## 9. Security notes

- Form sign-in is still over plain HTTP: recommend trusted LAN only or a TLS reverse proxy.
- The container holds a root SSH key to the router. Keep `ssh/` private (`chmod 600`, never commit).
- Change the default `ADMIN_PASS` if it is weak.
- Blocking and trust are MAC based; devices with randomised MACs can evade or lose them.

## 10. Known limitations / ideas

- Trust is runtime-only; to persist, write `trustedmac` entries to UCI (`uci add_list opennds.@opennds[0].trustedmac=...`) and handle removal.
- Block is global to the router (`prerouting`, drops all traffic from the MAC, including to the router itself).
- No voucher / FAS / ThemeSpec management.
- The per-client punishment hierarchy is rebuilt from SQM's CAKE roots when a policy or punished-client mapping changes, so it can briefly interrupt traffic.
- No user accounts or CSRF protection beyond Basic auth; fine for a LAN admin tool.
- Auto-trust loop trusts clients seen in `ndsctl json`, which only includes devices openNDS has seen (preauthenticated or authenticated).

## 11. Config reference (`docker-compose.yml` env)

`ADMIN_USER`, `ADMIN_PASS`, `SESSION_SECRET`, `OWRT_HOST`, `OWRT_USER`, `OWRT_KEY`, `OWRT_PORT`, `WAN_IFACE` (`eth0`), `WAN_COUNTER_REMOTE` (`/etc/opennds-manager/wan-counter.state`), `NDS_CONF` (`/etc/config/opennds`), `PORTAL_DIR` (`/etc/opennds/htdocs`), `HOSTED_PORTAL_DIR` (`/data/hosted-portal`), `HOSTED_PORTAL_DEFAULT_DIR` (`/portal-default` in Docker), `FAS_BASE_URL` (`http://192.168.1.198:8080`), `FAS_KEY_FILE` (`/data/fas.key`), and optional `SEEN_FILE`, `CLIENT_NAMES_FILE` (`/data/client-names.json`), `DELETED_FILE`, `BLOCK_FILE`, `MODE_FILE`, `PORTAL_DEFAULT_FILE`, `ONLINE_SECS` (300), `AUTOTRUST_INTERVAL` (3), `CLIENTS_CACHE_SECS` (0.75; legacy response coalescing), `CLIENTS_SNAPSHOT_INTERVAL` (3), `NDS_STATUS_INTERVAL` (15), `TRAFFIC_FILE`, `TRAFFIC_IFACE` (`br-lan`), `WAN_TRAFFIC_FILE`, `WAN_USAGE_FILE`, `WAN_USAGE_INTERVAL` (1), `WAN_USAGE_MAX_GAP` (8), `TRAFFIC_TZ` (`Asia/Manila`), `TRAFFIC_INTERVAL` (1), `DOMAIN_RANK_FILE`, `DOMAIN_LOG_FILE` (`/tmp/opennds-dns-queries.log`), `DOMAIN_REFRESH_INTERVAL` (1800), `SQM_CONDITIONAL_FILE`, `SQM_CONDITIONAL_INTERVAL` (30), `PUNISH_FILE`, `PUNISH_TC_FILE`, `PUNISH_IFB` (`ifb4br-lan`).

## 12. Working agreements with the user

- Keep answers short; no emojis; rebuild the container and verify via `curl` after changes when possible.
- Do not change the live router state (trust/block/mode/SQM apply) just to test, other than with dummy MACs like `02:00:00:00:00:99`.
- The user has asked to keep the project simple (Flask + vanilla JS, no build tooling).

## 13. Portal types

`/api/portal/types` (GET/POST) lists and applies built-in portals: `default` (`portal/`) and `custom` (`portal-custom/`, animated cats converted from the user's ThemeSpec script in `temp/`). Applying copies the type into `data/hosted-portal` (previous kept as `hosted-portal.bak`); the active type is in `data/portal-type.json` (`uploaded` after a ZIP/folder upload). Portal pages may use `{{CONTINUE_FORM}}` or the placeholders `{{AUTH_ACTION}}`, `{{TOKEN}}`, `{{REDIR}}`. `/fas` CSP now permits inline/same-origin scripts in an opaque-origin sandbox (no admin cookie access), superseding the earlier "scripts disabled" statement. Env: `HOSTED_PORTAL_CUSTOM_DIR` (`/portal-custom`).

`{{CONNECTED}}` in a portal renders `1` in auto_auth/auto_trust mode, on the post-login landing, and for already-authenticated clients (`/fas?status=authenticated`), else `0`; the custom portal uses it to show the "Connected" bubble. On the router, `check_authenticated()` in `/usr/lib/opennds/libopennds.sh` was patched to redirect to `FAS_BASE_URL/fas?status=authenticated` (original saved as `libopennds.sh.manager-orig`); an openNDS package upgrade overwrites it.

## 14. Connection-preserving optimization (October 2026)

This section supersedes earlier descriptions of automatic limits reauthentication, SQM root rebuilding, and DNS logging setup.

- Saving changed timeout/quota/session-rate limits schedules automatic logout/login only for affected authenticated, non-trusted, non-blocked clients. Login follows logout immediately; failures retry from fresh collector samples, including in portal mode, and pending work persists in `session-refresh.json`. Latency/overuse-only changes and no-op saves do not restart sessions. Existing sessions are preserved on startup without a queued explicit save. A brief interruption and session-counter reset are possible; `/api/clients` exposes `limits_pending`, `limits_pending_fields`, `limits_pending_message`, and `tc_pending_message`. Existing openNDS session caps can constrain live rate increases.
- Manager-hosted portal Continue forms now submit their opaque FAS request to public `GET /fas/continue` via `tok`. The manager verifies the return hash with `ndsctl json <rhid>`, checks the corresponding MAC/state/block list, and authenticates only a Preauthenticated client with its saved profile. Authenticated clients simply redirect without restarting their sessions. Auto-login FAS follows the same path. Uploaded templates using `{{AUTH_ACTION}}` and `{{TOKEN}}` retain the same form structure.
- One auth-control lock coordinates FAS completion and auto-login. Auto-login attempts are gated by collector timestamps; repeated/stale samples cannot repeat the same authentication. The collector's monotonic start time stays internal.
- Existing HTB/CAKE roots are adopted by inspecting both directions together. `punishment-tc.json` v2 adds persistent MAC-to-class `bindings` and per-MAC `pending` messages. Existing class/filter handles remain stable. Client additions and compatible changes affect leaves only. Removed-client filters detach first; a later inspection removes empty leaves/classes. Shared roots and default queues remain even when no managed clients remain.
- Active queue-type changes remain pending. For a Preauthenticated client they detach filters, drain, and change the leaf in a later pass. Unknown roots, identities, structural SQM changes, or failures never trigger an automatic root replacement or service restart.
- Manual bandwidth-only SQM updates and daily-rule activation/restoration use in-place `tc change`, then persist UCI rates. LAN bridge ingress/download still maps to client upload; bridge egress/upload maps to client download. Structural changes return HTTP 409 and require maintenance.
- The traffic thread owns combined interface/conntrack reads, preserving separate configured due times; there is no separate client-WAN sampler thread. Keep gunicorn at one worker. Parsed client accounting lives in memory; save cadence remains unchanged. JSON snapshots use atomic replacement, preserving existing file permissions/ownership, with accounting disk writes outside reader locks.
- Both history endpoints accept optional `since` and `generation`. Responses retain full history when omitted; `reset`, `cursor`, `generation`, `history_start_at`, and `recent_start_at` support incremental merging, restart/gap recovery, and conversion of old seconds to minutes. Delta responses include mutable boundary points. The browser ignores obsolete client-dialog responses and suspends hidden-dialog requests.
- DNS refreshes coalesce within three seconds across tabs. Collection only inspects existing dnsmasq logging and never enables logging or reloads DNS automatically; missing logging is reported.
- Regression checks run without router access: `docker run --rm --network none --mount 'type=bind,source=/home/justine/Data/Open NDS,target=/work,readonly' -w /work opennds-opennds-manager:latest python -B -m unittest discover -s tests` and the same mount with `node:22-alpine node tests/test_browser.cjs`.
- `tests/dry_run_router.py` is an explicitly invoked, read-only deployment check: mount the workspace at `/work`, existing data read-only at `/data`, and SSH keys read-only at `/ssh`. It suppresses threads, copies state to temporary files, records proposed queue changes without executing them, and checks combined reads and an existing client's FAS verification.

## 15. Responsive browser QA

`tests/ui_qa.cjs` uses synthetic data and intercepts every API call (including writes); it never connects to the router. It sweeps widths from 320 to 2560px in 32px steps plus exact breakpoints, exercises long names/dialogs, checks text contrast, and verifies delayed loads, failed reloads/saves, keyboard focus, range/unit persistence, and Device-MAC validation. Playwright/Chromium are optional external test tools, not app dependencies. Run from the project directory with `PLAYWRIGHT_MODULE=/tmp/node_modules/playwright CHROMIUM_PATH=/usr/bin/chromium node tests/ui_qa.cjs`; use `--layout-only` or `--behavior-only` for targeted checks. Use `UI_THEME=classic` (default) or `UI_THEME=hacker` to check a skin. Results/screenshots go to `/tmp/opennds-ui-qa` (override with `UI_QA_OUTPUT`).

## 16. Current working workflow

- Use only `main` in `/home/justine/Data/Open NDS`. The user cancelled the separate development branch/worktree and its synthetic preview.
- The active manager/final preview remains `http://localhost:8080`, Docker Compose project `opennds`.
- Develop and run the relevant mocked/offline checks in this main workspace. Rebuild and verify read-only APIs/UI after application changes, as described above.
- Do not create another branch/worktree or a second router controller unless the user explicitly requests it. Do not change live router state solely to test.
- Keep AGENTS.md updated with architecture, UI behavior, testing, and deployment changes. Local credentials, SSH keys, and runtime data remain excluded from Git.
