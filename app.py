import json
import copy
import base64
import hashlib
import html
import io
import ipaddress
import hmac
import logging
import mimetypes
import os
import posixpath
import re
import shlex
import shutil
import stat
import subprocess
import threading
import time
import tarfile
import zipfile
import secrets
import tempfile
from urllib.parse import unquote, urlencode, urlsplit
from decimal import Decimal, InvalidOperation
from datetime import datetime, timedelta, timezone
from functools import wraps
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from flask import Flask, Response, jsonify, make_response, redirect, render_template, request, session, url_for
import network_policy
import wan_shaping

HOST = os.environ.get("OWRT_HOST", "192.168.1.1")
SSH_USER = os.environ.get("OWRT_USER", "root")
SSH_KEY = os.environ.get("OWRT_KEY", "/ssh/id_ed25519")
SSH_PORT = os.environ.get("OWRT_PORT", "22")
CONF = os.environ.get("NDS_CONF", "/etc/config/opennds")
PORTAL = posixpath.normpath(os.environ.get("PORTAL_DIR", "/etc/opennds/htdocs"))
HOSTED_PORTAL = os.path.abspath(os.environ.get("HOSTED_PORTAL_DIR", "/data/hosted-portal"))
HOSTED_PORTAL_DEFAULT = os.path.abspath(os.environ.get(
    "HOSTED_PORTAL_DEFAULT_DIR", os.path.join(os.path.dirname(__file__), "portal")))
HOSTED_PORTAL_CUSTOM = os.path.abspath(os.environ.get(
    "HOSTED_PORTAL_CUSTOM_DIR", os.path.join(os.path.dirname(__file__), "portal-custom")))
PORTAL_TYPE_FILE = os.environ.get("PORTAL_TYPE_FILE", "/data/portal-type.json")
PORTAL_TYPES = {"default": ("Default", HOSTED_PORTAL_DEFAULT), "custom": ("Custom (animated cats)", HOSTED_PORTAL_CUSTOM)}
FAS_BASE_URL = os.environ.get("FAS_BASE_URL", "http://192.168.1.198:8080").rstrip("/")
FAS_KEY_FILE = os.environ.get("FAS_KEY_FILE", "/data/fas.key")
PORTAL_DEFAULT_FILE = os.environ.get("PORTAL_DEFAULT_FILE", "/data/hosted-portal-default.zip")
USER = os.environ.get("ADMIN_USER", "admin")
PASS = os.environ.get("ADMIN_PASS", "changeme")
SESSION_SECRET = os.environ.get("SESSION_SECRET", "")
SEEN_FILE = os.environ.get("SEEN_FILE", "/data/seen.json")
CLIENT_NAMES_FILE = os.environ.get("CLIENT_NAMES_FILE", "/data/client-names.json")
SQM_NAMES_FILE = os.environ.get("SQM_NAMES_FILE", "/data/sqm-names.json")
SQM_MODE_FILE = os.environ.get("SQM_MODE_FILE", "/data/sqm-mode.json")
DELETED_FILE = os.environ.get("DELETED_FILE", "/data/deleted.json")
ONLINE_SECS = int(os.environ.get("ONLINE_SECS", "300"))
BLOCK_FILE = os.environ.get("BLOCK_FILE", "/data/blocked.json")
TRAFFIC_FILE = os.environ.get("TRAFFIC_FILE", "/data/traffic.json")
TRAFFIC_IFACE = os.environ.get("TRAFFIC_IFACE", "br-lan")
WAN_IFACE = os.environ.get("WAN_IFACE", "eth0")
WAN_QOS_FILE = os.environ.get("WAN_QOS_FILE", "/data/wan-qos.json")
# Networks that always require an explicit portal login, independently of the
# primary LAN's operation mode. Invalid configuration fails at startup.
PORTAL_SUBNETS = tuple(ipaddress.IPv4Network(value.strip()) for value in
                       os.environ.get("PORTAL_SUBNETS", "").split(",") if value.strip())
NETWORKS_FILE = os.environ.get("NETWORKS_FILE", "/data/networks.json")
WAN_COUNTER_REMOTE = os.environ.get("WAN_COUNTER_REMOTE", "/etc/opennds-manager/wan-counter.state")
WAN_USAGE_FILE = os.environ.get("WAN_USAGE_FILE", "/data/wan-usage.json")
CLIENT_WAN_HISTORY_FILE = os.environ.get("CLIENT_WAN_HISTORY_FILE", "/data/client-wan-history.json")
WAN_TRAFFIC_FILE = os.environ.get("WAN_TRAFFIC_FILE", "/data/wan-traffic.json")
WAN_USAGE_INTERVAL = max(1.0, float(os.environ.get("WAN_USAGE_INTERVAL", "1")))
WAN_USAGE_MAX_GAP = max(WAN_USAGE_INTERVAL * 2, float(os.environ.get("WAN_USAGE_MAX_GAP", "8")))
WAN_USAGE_SAMPLER_ID = secrets.token_hex(16)
WAN_USAGE_SCHEMA_VERSION = 2
CLIENT_WAN_HISTORY_SECS = 24 * 60 * 60
CLIENT_WAN_HISTORY_BUCKET_SECS = 60
CLIENT_WAN_LIVE_HISTORY_SECS = 60 * 60
try:
    CLIENTS_CACHE_SECS = min(3.0, max(0.0, float(os.environ.get("CLIENTS_CACHE_SECS", "0.75"))))
except ValueError:
    CLIENTS_CACHE_SECS = 0.75
try:
    CLIENTS_SNAPSHOT_INTERVAL = max(1.0, float(os.environ.get("CLIENTS_SNAPSHOT_INTERVAL", "3")))
except ValueError:
    CLIENTS_SNAPSHOT_INTERVAL = 3.0
try:
    NDS_STATUS_INTERVAL = max(CLIENTS_SNAPSHOT_INTERVAL,
                              float(os.environ.get("NDS_STATUS_INTERVAL", "15")))
except ValueError:
    NDS_STATUS_INTERVAL = 15.0
TRAFFIC_TZ = os.environ.get("TRAFFIC_TZ", "Asia/Manila")
TRAFFIC_INTERVAL = max(1.0, float(os.environ.get("TRAFFIC_INTERVAL", "1")))
TRAFFIC_HISTORY_SECS = 60 * 60
WAN_TRAFFIC_HISTORY_SECS = 24 * 60 * 60
WAN_TRAFFIC_HISTORY_BUCKET_SECS = 60
SQM_CONDITIONAL_FILE = os.environ.get("SQM_CONDITIONAL_FILE", "/data/sqm-conditional.json")
SQM_CONDITIONAL_INTERVAL = max(5.0, float(os.environ.get("SQM_CONDITIONAL_INTERVAL", "30")))
PUNISH_FILE = os.environ.get("PUNISH_FILE", "/data/punishment.json")
PUNISH_TC_FILE = os.environ.get("PUNISH_TC_FILE", "/data/punishment-tc.json")
PUNISH_IFB = os.environ.get("PUNISH_IFB", "")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("opennds-manager")
_ssh_lock = threading.Lock()
_telemetry_ssh_lock = threading.Lock()
_history_lock = threading.Lock()
_traffic_lock = threading.Lock()
_wan_usage_lock = threading.Lock()
_wan_traffic_lock = threading.Lock()
_clients_cache_lock = threading.Lock()
_portal_lock = threading.Lock()
_punishment_lock = threading.Lock()
_punishment_tc_lock = threading.Lock()
# Router settings snapshots are separate from runtime QoS verification.
_sqm_cache_lock = threading.Lock()
_sqm_cache_data = None
_sqm_observed_data = None
_sqm_cache_error = ""
_sqm_cache_generation = 0
_sqm_cache_published = -1
_sqm_cache_attempted_at = 0.0
SQM_CACHE_INTERVAL = 10
SQM_CACHE_MAX_AGE = 30
_qos_status_lock = threading.Lock()
_qos_status_data = {"checked_at": 0, "networks": [], "queues": []}
_networks_lock = threading.RLock()
_networks_data = None
_networks_checked_at = 0.0
_throttle_lock = threading.Lock()
_sqm_conditional_lock = threading.Lock()
_traffic_data = None
_wan_traffic_data = None
_wan_usage_live = {}
_wan_usage_data = None
_client_wan_history_data = None
_client_wan_live_history = {}
_overview_clients = None
_clients_cache_data = None
_clients_cache_until = 0.0
_trusted_macs_cache = set()
_trusted_macs_cache_at = 0.0
_last_sqm_conditional_check = 0.0
_auth_attempts = {}
_auth_control_lock = threading.Lock()
HISTORY_GENERATION = secrets.token_hex(8)

MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
CONNTRACK_TUPLE_RE = re.compile(
    r"\bsrc=(?P<src>\S+)\s+dst=(?P<dst>\S+)(?P<fields>(?:(?!\bsrc=).)*?)\bbytes=(?P<bytes>\d+)")
CONNTRACK_PORTS_RE = re.compile(r"\bsport=(\d+)\s+dport=(\d+)")
RATE_KEYS = {"up", "down"}
PUNISH_DELAY_MAX = 10_000
PUNISH_CAP_MAX = 10_000_000
PUNISH_LOSS_MAX = Decimal("100")
SQM_CONDITIONAL_GB_MAX = Decimal("100000")
PORTAL_TEMPLATE_MAX_BYTES = 100 * 1024 * 1024
PORTAL_TEMPLATE_MAX_FILES = 200
# A ZIP has small directory/header overhead beyond the extracted portal files.
PORTAL_TEMPLATE_UPLOAD_MAX_BYTES = PORTAL_TEMPLATE_MAX_BYTES + PORTAL_TEMPLATE_MAX_FILES * 1024
app = Flask(__name__)
if not SESSION_SECRET:
    SESSION_SECRET = secrets.token_urlsafe(32)
    log.warning("SESSION_SECRET is unset; browser sessions will end after a container restart")
app.config.update(SECRET_KEY=SESSION_SECRET, PERMANENT_SESSION_LIFETIME=timedelta(hours=12),
                  SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")


@app.after_request
def disable_api_cache(response):
    """Client/status data is live; never let a browser reuse an old API reply."""
    if request.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    if request.method != "GET" and request.path in {"/api/action", "/api/mode", "/api/limits", "/api/punishment"}:
        _invalidate_clients_cache()
    if (request.method == "PUT" and request.path in
            {"/api/sqm", "/api/sqm/mode", "/api/sqm/conditional", "/api/networks"}
            and response.status_code not in (400, 401, 403, 409)):
        # Even a failed operation may have partially changed the router.
        _invalidate_sqm_cache()
    return response


def _invalidate_clients_cache():
    global _clients_cache_until
    with _clients_cache_lock:
        _clients_cache_until = 0.0


def _cache_client_snapshot(f):
    """Coalesce duplicate live client polls without letting browsers cache them."""
    @wraps(f)
    def wrapper(*a, **kw):
        global _clients_cache_data, _clients_cache_until
        if not CLIENTS_CACHE_SECS:
            return f(*a, **kw)
        with _clients_cache_lock:
            if _clients_cache_data is not None and time.monotonic() < _clients_cache_until:
                return jsonify(_clients_cache_data)
            response = app.make_response(f(*a, **kw))
            payload = response.get_json(silent=True)
            if response.status_code == 200 and isinstance(payload, dict) and payload.get("ok") is True:
                _clients_cache_data = payload
                _clients_cache_until = time.monotonic() + CLIENTS_CACHE_SECS
            return response
    return wrapper


def requires_auth(f):
    @wraps(f)
    def wrapper(*a, **kw):
        auth = request.authorization
        session_ok = session.get("authenticated") is True and session.get("username") == USER
        basic_ok = auth and hmac.compare_digest(auth.username or "", USER) and \
            hmac.compare_digest(auth.password or "", PASS)
        if not session_ok and not basic_ok:
            if request.path.startswith("/api/"):
                return jsonify(ok=False, output="authentication required"), 401
            return redirect(url_for("login", next=request.full_path))
        return f(*a, **kw)
    return wrapper


def _safe_login_next(value):
    return value if isinstance(value, str) and value.startswith("/") and not value.startswith("//") else url_for("index")


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("authenticated") is True and session.get("username") == USER:
        return redirect(_safe_login_next(request.values.get("next", "")))
    next_url = _safe_login_next(request.values.get("next", ""))
    error = ""
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if hmac.compare_digest(username, USER) and hmac.compare_digest(password, PASS):
            session.clear()
            session.permanent = True
            session["authenticated"] = True
            session["username"] = USER
            return redirect(next_url)
        error = "Incorrect username or password."
    return render_template("login.html", error=error, next_url=next_url)


@app.route("/logout", methods=["POST"])
@requires_auth
def logout():
    session.clear()
    return redirect(url_for("login"))


def ssh(command: str, data: bytes | None = None, timeout=15, *, telemetry=False):
    """Run SSH; kernel-only telemetry must not wait for slow ndsctl/control reads."""
    with (_telemetry_ssh_lock if telemetry else _ssh_lock):
        try:
            p = subprocess.run(
                ["ssh", "-i", SSH_KEY, "-p", SSH_PORT,
                 "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new",
                 "-o", "UserKnownHostsFile=/tmp/known_hosts", "-o", "ConnectTimeout=5",
                 "-o", "ControlMaster=auto", "-o", "ControlPath=/tmp/ssh-%C", "-o", "ControlPersist=60",
                 f"{SSH_USER}@{HOST}", command],
                input=data, capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            log.error("ssh timeout (%ss): %s", timeout, command[:120])
            raise
    err = p.stderr.decode(errors="replace")
    if p.returncode != 0:
        log.warning("ssh rc=%s cmd=%r err=%r", p.returncode, command[:120], err.strip()[:300])
    return p.returncode, p.stdout, err


def ndsctl(args: str):
    # openNDS answers "busy" if another ndsctl request is being handled
    for attempt in range(6):
        rc, out, err = ssh("ndsctl " + args)
        text = out.decode(errors="replace") + err
        if "busy" not in text.lower():
            break
        time.sleep(0.5)
    return rc, text


def _loads_nds_json(value):
    """Read openNDS client JSON, including its occasional raw control chars."""
    # openNDS 10.3.1 can put a literal newline in a client's `custom` value
    # after preemptive authentication. It is otherwise JSON, so accepting
    # control characters retains the complete client record rather than
    # treating the whole response as unavailable.
    return json.loads(value, strict=False)


def respond(rc, text):
    return jsonify(ok=rc == 0, output=text), (200 if rc == 0 else 502)


def portal_path(name):
    if not isinstance(name, str) or "\x00" in name:
        return None
    normalized = posixpath.normpath(name.replace("\\", "/"))
    if normalized in ("", ".", "..") or normalized.startswith("../") or normalized.startswith("/"):
        return None
    path = os.path.realpath(os.path.join(HOSTED_PORTAL, *normalized.split("/")))
    try:
        if os.path.commonpath((HOSTED_PORTAL, path)) != HOSTED_PORTAL or path == HOSTED_PORTAL:
            return None
    except ValueError:
        return None
    return path


def _template_entry_name(name):
    if not isinstance(name, str):
        return None
    name = posixpath.normpath(name)
    if name in ("", ".", "..") or name.startswith("../") or name.startswith("/"):
        return None
    return name


def _current_portal_template():
    archive = io.BytesIO()
    try:
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as target:
            total = 0
            count = 0
            for root, dirs, files in os.walk(HOSTED_PORTAL):
                dirs[:] = sorted(d for d in dirs if not os.path.islink(os.path.join(root, d)))
                for filename in sorted(files):
                    path = os.path.join(root, filename)
                    if os.path.islink(path) or not os.path.isfile(path):
                        continue
                    name = _template_entry_name(os.path.relpath(path, HOSTED_PORTAL).replace(os.sep, "/"))
                    if not name:
                        raise ValueError("invalid portal file path")
                    total += os.path.getsize(path)
                    count += 1
                    if total > PORTAL_TEMPLATE_MAX_BYTES or count > PORTAL_TEMPLATE_MAX_FILES:
                        raise ValueError("portal template exceeds its size or file-count limit")
                    with open(path, "rb") as source:
                        target.writestr(name, source.read())
    except (OSError, ValueError) as e:
        raise RuntimeError(f"could not package portal template: {e}")
    return archive.getvalue()


def _default_portal_template():
    try:
        with open(PORTAL_DEFAULT_FILE, "rb") as f:
            return f.read()
    except OSError:
        template = _current_portal_template()
        os.makedirs(os.path.dirname(PORTAL_DEFAULT_FILE), exist_ok=True)
        temporary = PORTAL_DEFAULT_FILE + ".new"
        with open(temporary, "wb") as f:
            f.write(template)
        os.replace(temporary, PORTAL_DEFAULT_FILE)
        return template


def _uploaded_portal_template(upload):
    if len(upload) > PORTAL_TEMPLATE_UPLOAD_MAX_BYTES:
        raise ValueError("portal template is too large")
    output = io.BytesIO()
    names, total = set(), 0
    try:
        with zipfile.ZipFile(io.BytesIO(upload)) as source, tarfile.open(fileobj=output, mode="w") as target:
            files = [entry for entry in source.infolist() if not entry.is_dir()]
            if not files or len(files) > PORTAL_TEMPLATE_MAX_FILES:
                raise ValueError("template must contain 1 to 200 files")
            for entry in files:
                name = _template_entry_name(entry.filename)
                mode = entry.external_attr >> 16
                if not name or name in names or stat.S_ISLNK(mode):
                    raise ValueError("invalid template file path")
                names.add(name)
                total += entry.file_size
                if total > PORTAL_TEMPLATE_MAX_BYTES:
                    raise ValueError("portal template is too large")
                content = source.read(entry)
                if len(content) != entry.file_size:
                    raise ValueError("invalid template file")
                target_info = tarfile.TarInfo(name)
                target_info.size = len(content)
                target_info.mode = 0o644
                target.addfile(target_info, io.BytesIO(content))
    except (NotImplementedError, OSError, RuntimeError, zipfile.BadZipFile, ValueError) as e:
        raise ValueError(str(e) or "invalid ZIP template")
    return output.getvalue(), len(names)


def _folder_portal_template(uploaded):
    """Turn browser-selected folder files into the same validated template as a ZIP."""
    if not uploaded:
        raise ValueError("choose a folder containing portal files")
    # A macOS folder selection can include both the real file and metadata.
    # Bound the request before holding any of its file contents in memory.
    if len(uploaded) > PORTAL_TEMPLATE_MAX_FILES * 3:
        raise ValueError("folder contains too many files")

    source_files, ignored, total = [], 0, 0
    for uploaded_file in uploaded:
        filename = (uploaded_file.filename or "").replace("\\", "/")
        name = _template_entry_name(filename)
        parts = name.split("/") if name else []
        if "__MACOSX" in parts or (parts and (parts[-1] == ".DS_Store" or parts[-1].startswith("._"))):
            ignored += 1
            continue
        if not name or "\x00" in filename:
            raise ValueError("invalid folder file path")
        remaining = PORTAL_TEMPLATE_MAX_BYTES - total
        content = uploaded_file.read(remaining + 1)
        total += len(content)
        if total > PORTAL_TEMPLATE_MAX_BYTES:
            raise ValueError("portal template is too large")
        source_files.append((name, content))

    if not source_files:
        raise ValueError("folder contains no portal files")
    roots = {name.split("/", 1)[0] for name, _ in source_files}
    stripped_root = ""
    if len(roots) == 1 and all("/" in name for name, _ in source_files):
        stripped_root = roots.pop()
        source_files = [(name.split("/", 1)[1], content) for name, content in source_files]

    archive = io.BytesIO()
    names = set()
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as target:
        for name, content in source_files:
            if not name or name in names:
                raise ValueError("folder contains duplicate file paths")
            names.add(name)
            target.writestr(name, content)
    template, files = _uploaded_portal_template(archive.getvalue())
    notes = []
    if stripped_root:
        notes.append(f'removed outer folder "{stripped_root}"')
    if ignored:
        notes.append(f"ignored {ignored} macOS metadata file{'s' if ignored != 1 else ''}")
    return template, files, notes


def _replace_portal_template(template):
    if not any(name == "index.html" for name in _template_names(template)):
        raise RuntimeError("portal folder must contain an index.html")
    os.makedirs(os.path.dirname(HOSTED_PORTAL), exist_ok=True)
    replacement, backup = HOSTED_PORTAL + ".new", HOSTED_PORTAL + ".bak"
    if os.path.islink(replacement) or os.path.isfile(replacement):
        os.unlink(replacement)
    elif os.path.isdir(replacement):
        shutil.rmtree(replacement)
    os.makedirs(replacement)
    moved_current = False
    try:
        with tarfile.open(fileobj=io.BytesIO(template), mode="r:") as archive:
            archive.extractall(replacement, filter="data")
        if os.path.islink(backup) or os.path.isfile(backup):
            os.unlink(backup)
        elif os.path.isdir(backup):
            shutil.rmtree(backup)
        if os.path.exists(HOSTED_PORTAL):
            os.replace(HOSTED_PORTAL, backup)
            moved_current = True
        os.replace(replacement, HOSTED_PORTAL)
    except (OSError, tarfile.TarError) as e:
        if os.path.isdir(replacement):
            shutil.rmtree(replacement)
        if moved_current and not os.path.exists(HOSTED_PORTAL) and os.path.isdir(backup):
            os.replace(backup, HOSTED_PORTAL)
        raise RuntimeError(f"could not install local portal template: {e}")
    return ""


def _template_names(template):
    try:
        with tarfile.open(fileobj=io.BytesIO(template), mode="r:") as archive:
            return [entry.name for entry in archive if entry.isfile()]
    except tarfile.TarError as e:
        raise RuntimeError(f"invalid portal package: {e}")


def _install_portal_template(template, portal_type="uploaded"):
    with _portal_lock:
        result = _replace_portal_template(template)
        _save_json(PORTAL_TYPE_FILE, {"type": portal_type})
        return result


def _current_portal_type():
    data = _load_json(PORTAL_TYPE_FILE, {})
    value = data.get("type") if isinstance(data, dict) else None
    return value if value in PORTAL_TYPES or value == "uploaded" else "default"


def _directory_template(directory):
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode="w") as target:
        for root, dirs, files in os.walk(directory):
            dirs.sort()
            for filename in sorted(files):
                path = os.path.join(root, filename)
                if os.path.islink(path) or not os.path.isfile(path):
                    continue
                info = tarfile.TarInfo(os.path.relpath(path, directory).replace(os.sep, "/"))
                info.size, info.mode = os.path.getsize(path), 0o644
                with open(path, "rb") as source:
                    target.addfile(info, source)
    return archive.getvalue()


def _ensure_hosted_portal():
    if os.path.isfile(os.path.join(HOSTED_PORTAL, "index.html")):
        return
    source = os.path.join(HOSTED_PORTAL_DEFAULT, "index.html")
    if not os.path.isfile(source):
        raise RuntimeError(f"hosted portal default is missing: {source}")
    os.makedirs(HOSTED_PORTAL, exist_ok=True)
    shutil.copy2(source, os.path.join(HOSTED_PORTAL, "index.html"))
    with open(PORTAL_TYPE_FILE, "w") as marker:
        json.dump({"type": "default"}, marker)


_ensure_hosted_portal()


def _r(result, ok_msg):
    rc, _, err = result
    return rc, (err or ok_msg)


def _kbytes_to_kbits(value, maximum):
    """Convert a UI rate in KB/s to the integer kbit/s expected by OpenWrt."""
    try:
        rate = Decimal(str(value))
    except (InvalidOperation, ValueError):
        raise ValueError("rate")
    if not rate.is_finite() or rate < 0:
        raise ValueError("rate")
    kbits = rate * 8
    if kbits != kbits.to_integral_value() or kbits > maximum:
        raise ValueError("rate")
    return int(kbits)


def _kbits_to_kbytes(value):
    rate = Decimal(str(value)) / 8
    text = format(rate, "f")
    return text.rstrip("0").rstrip(".") if "." in text else text


def _load_seen():
    try:
        with open(SEEN_FILE) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def _save_seen(seen):
    try:
        if seen != _load_seen():
            _save_json(SEEN_FILE, seen)
    except OSError:
        pass


def _load_client_names():
    data = _load_json(CLIENT_NAMES_FILE, {})
    if not isinstance(data, dict):
        return {}
    return {mac.lower(): name.strip() for mac, name in data.items()
            if isinstance(mac, str) and MAC_RE.match(mac)
            and isinstance(name, str) and name.strip()}


def _save_client_names(names):
    _save_json(CLIENT_NAMES_FILE, names)


def _load_deleted():
    try:
        with open(DELETED_FILE) as f:
            return {m.lower() for m in json.load(f) if MAC_RE.match(m)}
    except (OSError, ValueError, TypeError):
        return set()


def _save_deleted(deleted):
    try:
        _save_json(DELETED_FILE, sorted(deleted))
    except OSError:
        pass


def _load_blocked():
    try:
        with open(BLOCK_FILE) as f:
            return set(json.load(f))
    except (OSError, ValueError):
        return set()


def _apply_blocks(blocked):
    # openNDS 10.x ndsctl has no block command; drop the MAC in an nft table ahead of it
    elems = ", ".join(sorted(blocked))
    rules = ("table inet nds_block {\n set blocked { type ether_addr; "
             + (f"elements = {{ {elems} }}; " if blocked else "")
             + "}\n chain pre { type filter hook prerouting priority -300; policy accept;\n"
             "  ether saddr @blocked drop\n }\n}\n")
    return ssh("nft delete table inet nds_block 2>/dev/null; nft -f -", rules.encode())


def _save_blocked(blocked):
    _save_json(BLOCK_FILE, sorted(blocked))


@app.errorhandler(subprocess.TimeoutExpired)
def timeout(_):
    return jsonify(ok=False, output="ssh timeout"), 504


@app.errorhandler(Exception)
def unhandled(e):
    from werkzeug.exceptions import HTTPException
    if isinstance(e, HTTPException):
        return e
    log.exception("unhandled error on %s %s", request.method, request.path)
    return jsonify(ok=False, output=f"internal error: {e}"), 500


@app.route("/")
@requires_auth
def index():
    return render_template("index.html")


@app.route("/api/status")
@requires_auth
def status():
    return respond(*ndsctl("status"))


@app.route("/api/clients")
@requires_auth
def clients():
    networks = [{key: row.get(key) for key in
                 ("name", "device", "subnets", "mode", "primary", "up")}
                for row in _network_state().get("networks", [])
                if row.get("subnets") and row.get("role") == "LAN"]
    with _clients_cache_lock:
        snapshot = _clients_cache_data
    if snapshot is None:
        return jsonify(ok=True, data={"clients": {}, "networks": networks}, sampled_at=0, stale=True,
                       output="collecting client snapshot")
    payload = dict(snapshot)
    # The collector keeps the unmodified openNDS records for the auto-control
    # loop. They are an implementation detail, not part of the public API.
    payload.pop("_live_clients", None)
    payload.pop("_collection_started_at", None)
    payload = _with_live_wan_usage(payload)
    hidden_ips = _infrastructure_client_ips()
    payload["data"] = {**payload.get("data", {}), "clients": {
        key: dict(client) for key, client in payload.get("data", {}).get("clients", {}).items()
        if client.get("ip") not in hidden_ips}}
    primary_mode = _load_mode()["mode"]
    payload["data"]["networks"] = networks
    for client in payload.get("data", {}).get("clients", {}).values():
        client["authentication_mode"] = _client_mode(client, primary_mode)
        network = _client_network(client)
        if network and network.get("role") != "LAN":
            network = None
        client["network"] = network["name"] if network else ""
        client["interface"] = network["device"] if network else ""
    try:
        payload["stale"] = int(time.time()) - int(payload.get("sampled_at", 0)) > \
            max(CLIENTS_SNAPSHOT_INTERVAL * 3, 10)
    except (TypeError, ValueError):
        payload["stale"] = True
    return jsonify(payload)


def _infrastructure_client_ips():
    """Known manager/router addresses, excluded from Clients/Overview; no router reads."""
    state = _network_state()
    candidates = [HOST, state.get("gateway_ip"), state.get("metadata", {}).get("fasremoteip")]
    try:
        candidates.append(urlsplit(FAS_BASE_URL).hostname)
    except ValueError:
        pass
    for network in state.get("networks", []):
        candidates.extend(address.get("address") for address in network.get("addresses", []))
    addresses = set()
    for candidate in candidates:
        try:
            addresses.add(str(ipaddress.ip_address(candidate)))
        except (ValueError, TypeError):
            pass
    return addresses


@app.route("/api/clients/<mac>/history")
@requires_auth
def client_wan_history(mac):
    mac = mac.lower()
    if not MAC_RE.match(mac):
        return jsonify(ok=False, output="invalid MAC"), 400
    return jsonify(ok=True, **_history_response(_client_wan_history(mac)))


def _collect_clients_snapshot():
    # This is the sole periodic owner of openNDS control reads. The one-second
    # traffic loop reads only kernel byte counters; auto-auth consumes this
    # snapshot rather than submitting another ndsctl json request.
    collection_started = time.monotonic()
    _, raw, _ = ssh(
        "attempt=1; while :; do nds_json=\"$(ndsctl json 2>&1)\"; nds_rc=$?; "
        "if ! printf '%s' \"$nds_json\" | grep -qi busy || [ \"$attempt\" -ge 6 ]; then break; fi; "
        "attempt=$((attempt + 1)); sleep 0.5; done; printf '%s\\n' \"$nds_json\"; "
        "echo @@NDS_JSON_END; echo @@NDS_RC:$nds_rc; "
        "date +%s; nft list set inet nds_block blocked >/dev/null 2>&1 && echo yes || echo no; "
        "echo @@LEASES; cat /tmp/dhcp.leases")
    lines = raw.decode(errors="replace").splitlines()
    try:
        json_marker = lines.index("@@NDS_JSON_END")
        nds_json = "\n".join(lines[:json_marker])
        data = _loads_nds_json(nds_json)
    except ValueError:
        return {"ok": False, "output": locals().get("nds_json") or "could not read openNDS clients"}
    current_clients = data.get("clients") or {}
    # Keep a clean copy for auto-auth before adding UI-only history and usage
    # fields below.
    live_clients = {key: dict(value) for key, value in current_clients.items()
                    if isinstance(value, dict)}
    try:
        now = int(lines[json_marker + 2])
    except (IndexError, ValueError):
        now = int(time.time())
    marker = lines.index("@@LEASES") if "@@LEASES" in lines else len(lines)
    boot_marker = lines.index("@@BOOT_ID") if "@@BOOT_ID" in lines else marker
    trusted = _trusted_macs()
    blocked = _load_blocked()
    punishment_policy = _punishment_policy_snapshot()
    limits = _load_limits()
    applied_profiles = _load_json(APPLIED_FILE, {})
    tc_state = _punishment_tc_state()
    punished = set(punishment_policy["punished"])
    throttle_excluded = blocked | trusted | punished
    if blocked and len(lines) > json_marker + 3 and lines[json_marker + 3] == "no":
        log.info("nft block table missing on router, re-applying %d MACs", len(blocked))
        _apply_blocks(blocked)
    leases = {}
    for line in lines[marker + 1:boot_marker]:
        f = line.split()
        if len(f) >= 4:
            leases[f[1].lower()] = {"ip": f[2], "hostname": "" if f[3] == "*" else f[3]}
    wan_usage = _live_wan_usage()
    with _history_lock:
        seen = _load_seen()
        names = _load_client_names()
        deleted = _load_deleted()
        clients = data.get("clients") or {}
        visible = {}
        for k, c in clients.items():
            mac = c.get("mac", k).lower()
            usage = wan_usage.get(mac, {})
            c["wan_today_download_bytes"] = usage.get("today_download", 0)
            c["wan_today_upload_bytes"] = usage.get("today_upload", 0)
            c["wan_month_download_bytes"] = usage.get("month_download", 0)
            c["wan_month_upload_bytes"] = usage.get("month_upload", 0)
            c["wan_download_rate"] = usage.get("download_rate")
            c["wan_upload_rate"] = usage.get("upload_rate")
            c["trusted"] = mac in trusted
            c["blocked"] = mac in blocked
            c["punished"] = mac in punished
            pending = _session_pending(c, _effective(mac, limits), mac in trusted,
                                       applied_profiles, tc_state)
            c.update(pending)
            c["throttle"] = _throttle_status(mac, limits, throttle_excluded)
            c["added_ping_ms"] = _gateway_latency_ms(mac, limits, punishment_policy,
                                                       mac in punished, mac in blocked, mac in trusted)
            router_hostname = leases.get(mac, {}).get("hostname") or seen.get(mac, {}).get("hostname", "")
            c["custom_name"] = names.get(mac, "")
            c["hostname"] = c["custom_name"] or router_hostname
            try:
                c["online"] = now - int(c.get("last_active", 0)) < ONLINE_SECS
            except ValueError:
                c["online"] = False
            if c["online"]:
                deleted.discard(mac)
                seen[mac] = {"mac": mac, "ip": c.get("ip", ""), "hostname": router_hostname,
                             "last_seen": int(c.get("last_active") or now)}
            elif mac in deleted:
                continue
            elif mac not in seen:
                seen[mac] = {"mac": mac, "ip": c.get("ip", ""), "hostname": router_hostname,
                             "last_seen": int(c.get("last_active") or now)}
            visible[k] = c
        present = {c.get("mac", k).lower() for k, c in clients.items()}
        for mac, l in leases.items():
            if mac not in deleted and mac not in seen:
                seen[mac] = {"mac": mac, "ip": l["ip"], "hostname": l["hostname"], "last_seen": 0}
        for mac in blocked | trusted:
            if mac not in deleted:
                seen.setdefault(mac, {"mac": mac, "ip": "", "hostname": "", "last_seen": 0})
        for mac, s in seen.items():
            if mac not in deleted and mac not in present:
                usage = wan_usage.get(mac, {})
                clients["off-" + mac] = {**s, "hostname": names.get(mac) or s.get("hostname", ""),
                                         "custom_name": names.get(mac, ""), "state": "Offline", "online": False,
                                         "last_active": s["last_seen"],
                                         "trusted": mac in trusted, "blocked": mac in blocked,
                                         "punished": mac in punished,
                                         "throttle": {"download": False, "upload": False, "until": 0},
                                         "wan_today_download_bytes": usage.get("today_download", 0),
                                         "wan_today_upload_bytes": usage.get("today_upload", 0),
                                         "wan_month_download_bytes": usage.get("month_download", 0),
                                         "wan_month_upload_bytes": usage.get("month_upload", 0),
                                         "wan_download_rate": None, "wan_upload_rate": None,
                                         "added_ping_ms": _gateway_latency_ms(
                                             mac, limits, punishment_policy, mac in punished,
                                             mac in blocked, mac in trusted)}
        _save_seen(seen)
        _save_deleted(deleted)
        data["clients"] = visible | {k: v for k, v in clients.items() if k.startswith("off-")}
    data["sampled_at"] = now
    _set_overview_clients({"clients": live_clients}, now)
    return {"ok": True, "data": data, "_live_clients": live_clients,
            "sampled_at": now, "stale": False, "_collection_started_at": collection_started}


@app.route("/api/clients/name", methods=["PUT"])
@requires_auth
def client_name():
    body = request.get_json(force=True)
    if not isinstance(body, dict):
        return jsonify(ok=False, output="client name must be an object"), 400
    mac = str(body.get("mac", "")).lower()
    if not MAC_RE.match(mac):
        return jsonify(ok=False, output="invalid MAC"), 400
    name = body.get("name", "")
    if not isinstance(name, str):
        return jsonify(ok=False, output="name must be text"), 400
    name = name.strip()
    if len(name) > 64 or any(ord(char) < 32 for char in name):
        return jsonify(ok=False, output="name must be 64 characters or fewer"), 400
    with _history_lock:
        names = _load_client_names()
        if name:
            names[mac] = name
        else:
            names.pop(mac, None)
        _save_client_names(names)
    _invalidate_clients_cache()
    return jsonify(ok=True, name=name, output="client name saved" if name else "custom name cleared")


_SQM_QDISC = {"cake", "fq_codel"}
_SQM_SCRIPT = {"piece_of_cake.qos", "layer_cake.qos", "simple.qos", "simplest.qos"}
_IFACE_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,15}$")


def _router_interfaces():
    rc, out, _ = ssh("ip -o link show 2>/dev/null || ip link show 2>/dev/null")
    if rc != 0:
        return []
    interfaces = set()
    for line in out.decode(errors="replace").splitlines():
        match = re.match(r"^\d+:\s+([^:@]+)(?:@\S+)?:\s", line)
        if match and _IFACE_RE.match(match.group(1)):
            interfaces.add(match.group(1))
    return sorted(interfaces)


def _router_interface_roles(interfaces):
    rc, out, _ = ssh("uci -q show network")
    if rc != 0:
        return {}
    sections, devices = {}, {}
    for line in out.decode(errors="replace").splitlines():
        match = re.match(r"^network\.([^.]+)='?interface'?$", line)
        if match:
            name = match.group(1).lower()
            if name.startswith("lan"):
                sections[match.group(1)] = "LAN"
            elif name.startswith("wan"):
                sections[match.group(1)] = "WAN"
            continue
        match = re.match(r"^network\.([^.]+)\.(?:device|ifname)='?([^']*?)'?$", line)
        if match:
            devices.setdefault(match.group(1), set()).update(match.group(2).split())
    roles = {}
    for section, role in sections.items():
        for device in devices.get(section, set()):
            if _IFACE_RE.match(device):
                roles[device] = role
    for interface in interfaces:
        if interface.startswith("br-lan"):
            roles.setdefault(interface, "LAN")
        elif interface == "wan" or interface.endswith("-wan"):
            roles.setdefault(interface, "WAN")
    return roles


def _network_state():
    global _networks_data
    with _networks_lock:
        if _networks_data is None:
            raw = _load_json(NETWORKS_FILE, {})
            _networks_data = raw if isinstance(raw, dict) else {}
        return _networks_data


def _save_network_state(state):
    global _networks_data
    _save_json(NETWORKS_FILE, state)
    _networks_data = state


def _scan_networks():
    """Read netifd, firewall membership and DHCP together; never change router config."""
    command = ("ubus call network.interface dump || exit 1; echo @@FIREWALL; "
               "ubus call uci get '{\"config\":\"firewall\"}' || exit 1; echo @@DHCP; "
               "ubus call uci get '{\"config\":\"dhcp\"}' || exit 1; echo @@META; "
               "cat /tmp/ndscids/ndsinfo 2>/dev/null || true; "
               "for field in gatewayinterface gatewayport fasremoteip fasport faspath gatewayfqdn; do "
               "value=$(uci -q get opennds.@opennds[0].$field || true); "
               "printf '%s=%s\\n' \"$field\" \"$value\"; done; "
               "printf 'wrapper_sha='; sha256sum /usr/lib/opennds/libopennds.sh 2>/dev/null | cut -d' ' -f1; "
               "printf '\\nhelper_sha='; sha256sum /usr/lib/opennds/opennds-extra-interface.sh 2>/dev/null | cut -d' ' -f1; "
               "printf '\\ninit_sha='; sha256sum /etc/init.d/opennds-extra-interface 2>/dev/null | cut -d' ' -f1; printf '\\n'")
    with _networks_lock:
        rc, raw, err = ssh(command, timeout=20)
        if rc != 0:
            raise ValueError(err.strip() or "OpenWrt network discovery failed")
        try:
            dump, rest = raw.decode().split("@@FIREWALL\n", 1)
            firewall, rest = rest.split("@@DHCP\n", 1)
            dhcp, metadata = rest.split("@@META\n", 1)
            meta = {}
            for line in metadata.splitlines():
                key, _, value = line.partition("=")
                if value.strip('"'):
                    meta[key] = value.strip('"')
            discovery = network_policy.discover(json.loads(dump), json.loads(firewall)["values"],
                                                json.loads(dhcp)["values"], meta)
        except (KeyError, UnicodeError, ValueError) as exc:
            raise ValueError(f"Invalid OpenWrt network discovery: {exc}") from exc
        state = _network_state()
        modes = dict(state.get("modes", {}))
        if not state.get("initialized"):
            # Import the previous topology policy once, using discovered interface identities.
            for row in discovery["networks"]:
                if row["primary"]:
                    modes[row["name"]] = _load_mode()["mode"]
                elif any(ipaddress.IPv4Network(n) == legacy for n in row["subnets"] for legacy in PORTAL_SUBNETS):
                    modes[row["name"]] = "portal"
        present = {r["name"] for r in discovery["networks"]}
        for old_row in state.get("networks", []):
            if old_row["name"] not in present and modes.get(old_row["name"], "unmanaged") != "unmanaged":
                discovery["networks"].append({**old_row, "up": False, "eligible": False,
                                             "reason": "Interface missing; saved attachment retained"})
        for row in discovery["networks"]:
            row["mode"] = modes.get(row["name"], "unmanaged")
        next_state = {**state, **discovery, "modes": modes, "initialized": True,
                      "scanned_at": int(time.time())}
        _save_network_state(next_state)
        return next_state


def _networks_for_ui(state):
    return {"networks": state.get("networks", []), "scanned_at": state.get("scanned_at"),
            "primary_device": state.get("primary_device"), "error": state.get("error", ""),
            "output": state.get("output", "")}


def _apply_network_modes(requested):
    with _auth_control_lock:
        ok, message = _apply_network_modes_locked(requested)
        # Queue reconciliation takes _punishment_tc_lock and reads network
        # state. Release _networks_lock first so an in-flight Punish action
        # can finish reading that state and release its queue lock.
        if ok:
            _control_once_locked()
        return ok, message


def _apply_network_modes_locked(requested):
    """Apply and publish modes under the caller's auth-control lock."""
    with _networks_lock:
        state = _network_state()
        network_policy.validate_modes(state, requested)
        modes = {**state.get("modes", {}), **requested}
        unavailable = [r for r in state["networks"] if not r["eligible"] and modes.get(r["name"], "unmanaged") != "unmanaged"]
        if unavailable:
            error = "; ".join(f"{r['name']}: {r['reason']}" for r in unavailable) + "; existing attachments retained"
            _save_network_state({**state, "error": error})
            return False, error
        # Only attach networks that currently exist and are eligible. Save identity
        # so a temporarily down interface keeps its selected behavior when it returns.
        config = network_policy.compile_config(state, {r["name"]: modes.get(r["name"], "unmanaged")
            if r["eligible"] else "unmanaged" for r in state["networks"]})
        previous = state.get("applied_config")
        helpers_match = all(state.get("metadata", {}).get(key) == value for key, value in config["helpers"].items())
        if previous != config or not helpers_match:
            script = network_policy.install_script(config, previous)
            rc, out, err = ssh("sh -s", data=script.encode(), timeout=90)
            if rc != 0:
                error = (out.decode(errors="replace") + err).strip() or "Network attachment failed"
                _save_network_state({**state, "error": error})
                return False, error
        rows = [{**r, "mode": modes.get(r["name"], "unmanaged")} for r in state["networks"]]
        mode_state = _load_mode()
        resets = set(mode_state["network_resets"])
        for client in _live_clients_for_control() or []:
            old_row = _client_network(client)
            if old_row and modes.get(old_row["name"], "unmanaged") != old_row["mode"]:
                if modes.get(old_row["name"], "unmanaged") in ("portal", "unmanaged"):
                    resets.add(client["mac"].lower())
        _save_network_state({**state, "modes": modes, "networks": rows,
                             "metadata": {**state["metadata"], **config["helpers"]},
                             "applied_config": config, "error": "", "output": "Applied"})
        primary = next(r for r in rows if r["primary"])
        mode_state["mode"] = modes.get(primary["name"], mode_state["mode"])
        mode_state["network_resets"] = sorted(resets)
        _save_mode(mode_state)
        return True, "Applied; affected automatic sessions follow their selected network behavior"


def _sync_networks_if_due():
    global _networks_checked_at
    if time.monotonic() - _networks_checked_at < 60:
        return
    _networks_checked_at = time.monotonic()
    try:
        state = _scan_networks()
        ok, message = _apply_network_modes({})
        if not ok:
            log.warning("network policy pending: %s", message)
    except Exception as exc:
        with _networks_lock:
            _save_network_state({**_network_state(), "error": str(exc)})
        log.warning("network discovery unavailable: %s", exc)


@app.route("/api/networks", methods=["GET", "PUT"])
@requires_auth
def networks():
    try:
        state = _scan_networks()
        if request.method == "GET":
            return jsonify(ok=True, **_networks_for_ui(state))
        body = request.get_json(force=True)
        if not isinstance(body, dict):
            raise ValueError("Network settings must be an object")
        ok, output = _apply_network_modes(body.get("modes"))
        return jsonify(ok=ok, **{**_networks_for_ui(_network_state()), "output": output}), (200 if ok else 502)
    except ValueError as exc:
        return jsonify(ok=False, output=str(exc)), (400 if request.method == "PUT" else 502)


def _read_sqm_queues():
    global _sqm_observed_data
    rc, out, err = ssh("uci -q show sqm")
    if rc != 0:
        error = err or "no SQM configuration"
        with _sqm_cache_lock:
            _sqm_observed_data = {"error": error, "checked_at": time.time(),
                                  "generation": _sqm_cache_generation}
        return [], error
    sections = {}
    for line in out.decode(errors="replace").splitlines():
        match = re.fullmatch(r"sqm\.([A-Za-z0-9_]+|@queue\[\d+\])(?:\.(\w+))?=(.*)", line)
        if not match:
            continue
        section, key, raw = match.groups()
        try:
            values = shlex.split(raw)
        except ValueError:
            continue
        if len(values) == 1:
            sections.setdefault(section, {})[key or ".type"] = values[0]
    queues = [{**config, "section": section} for section, config in sections.items()
              if config.get(".type") == "queue"]
    # Reuse reads already owned by control/validation; never publish under the
    # traffic-control lock or acquire settings/conditional locks from here.
    with _sqm_cache_lock:
        _sqm_observed_data = {"queues": copy.deepcopy(queues), "checked_at": time.time(),
                              "generation": _sqm_cache_generation, "error": ""}
    return queues, ""


def _sqm_for_ui(config):
    result = {key: value for key, value in config.items() if not key.startswith(".")}
    for key in ("download", "upload"):
        try:
            result[key] = _kbits_to_kbytes(int(result[key]))
        except (KeyError, ValueError):
            pass
    return result


def _sqm_baseline_for_ui(config, policy):
    """Keep the saved normal rates separate from a daily rule's router rates."""
    baseline = (policy.get("baseline", {}) if policy.get("placement") in ("lan", "aggregate")
                else policy.get("baselines", {}).get("lan", {}))
    normal = dict(config)
    if set(baseline) == {"download", "upload"}:
        normal.update(baseline)
    return _sqm_for_ui(normal)


def _primary_sqm_command(command, interface=None):
    """Resolve an exact LAN queue, or the legacy native LAN/WAN queue."""
    if interface is not None and not _IFACE_RE.fullmatch(interface):
        raise ValueError("invalid SQM interface")
    primary, wan = shlex.quote(interface or _primary_lan_device()), shlex.quote(WAN_IFACE)
    prefix = (". /lib/functions.sh; config_load sqm; sqm_primary=; sqm_wan=; sqm_matches=0; "
              "sqm_pick() { local dev; config_get dev \"$1\" interface; "
              f"if [ \"$dev\" = {primary} ]; then sqm_primary=$1; sqm_matches=$((sqm_matches+1)); fi; "
              f"[ \"$dev\" != {wan} ] || sqm_wan=$1; "
              "return 0; }; config_foreach sqm_pick queue; "
              "[ \"$sqm_matches\" -le 1 ] || { echo 'Duplicate LAN SQM queues' >&2; exit 1; }; ")
    if interface is None:
        prefix += "sqm_primary=${sqm_primary:-$sqm_wan}; "
    missing = "No SQM queue for " + interface if interface else "No primary LAN or WAN SQM queue"
    prefix += '[ -n "$sqm_primary" ] || { echo ' + shlex.quote(missing) + ' >&2; exit 1; }; '
    prefix += 'config_get sqm_primary_iface "$sqm_primary" interface; '
    return prefix + command.replace("sqm.@queue[0]", 'sqm."$sqm_primary"')


def _sqm_apply_script(device_word, enabled_word):
    """Use runtime state to verify scoped SQM operations, whose exit codes vary.

    run.sh stop returns 1 for an interface without a state file. start can
    return 1 after successfully starting a queue if a later section is skipped.
    Both words are internally quoted literals or trusted shell expressions.
    """
    # sqm.conf probes optional iptables binaries with command -v. Those probes
    # may return 127 on nft-only OpenWrt; run.sh normally sources it without -e.
    return ('[ -r /etc/sqm/sqm.conf ] || { echo "SQM configuration unavailable" >&2; exit 1; }; '
            'set +e; . /etc/sqm/sqm.conf; set -e; '
            f'sqm_apply_iface={device_word}; sqm_apply_enabled={enabled_word}; '
            '[ -n "$SQM_STATE_DIR" ] || { echo "SQM state directory unavailable" >&2; exit 1; }; '
            'sqm_apply_state="$SQM_STATE_DIR/$sqm_apply_iface.state"; '
            'if [ -f "$sqm_apply_state" ]; then '
            '/usr/lib/sqm/run.sh stop "$sqm_apply_iface" || :; fi; '
            'if [ -f "$sqm_apply_state" ]; then '
            'echo "SQM stop failed for $sqm_apply_iface; saved config retained" >&2; exit 1; fi; '
            'if [ "$sqm_apply_enabled" = 1 ]; then '
            '/usr/lib/sqm/run.sh start "$sqm_apply_iface" || :; '
            'if [ ! -f "$sqm_apply_state" ]; then '
            'echo "SQM start failed for $sqm_apply_iface; saved config retained" >&2; '
            "logread | grep -i 'SQM:' | tail -n 12 >&2; exit 1; fi; fi")


def _save_extra_sqm(config, settings):
    """Apply only the selected interface; never restart another LAN's queues."""
    iface = shlex.quote(settings["interface"])
    commands = ["[ ! -f /etc/config/sqm ] || cp /etc/config/sqm /etc/config/sqm.manager-bak"]
    if config:
        commands.append("section=" + shlex.quote(config["section"]))
    else:
        commands.append("section=$(uci add sqm queue)")
        settings = {"linklayer": "none", **settings}
    commands += [f'uci set sqm."$section".{key}={shlex.quote(str(value))}'
                 for key, value in settings.items()]
    commands += ["uci commit sqm", _sqm_apply_script(iface, settings["enabled"])]
    rc, out, err = ssh("set -e; " + "; ".join(commands), timeout=30)
    return rc == 0, ((out.decode(errors="replace") + err).strip()
                     or f"SQM apply failed for {settings['interface']} (exit {rc})") if rc else ""


_sqm_settings_lock = threading.RLock()
_sqm_names_lock = threading.Lock()


def _invalidate_sqm_cache():
    global _sqm_cache_generation, _sqm_cache_error
    with _sqm_cache_lock:
        _sqm_cache_generation += 1
        _sqm_cache_error = ""


def _refresh_sqm_cache(force=False):
    """One existing controller owns periodic reads; only explicit Reload reads inline.

    Publish a complete snapshot after releasing router work. Cached HTTP reads
    take only the short cache lock, never the settings/SSH/conditional locks.
    """
    global _sqm_cache_data, _sqm_cache_error, _sqm_cache_published, _sqm_cache_attempted_at
    with _sqm_settings_lock:
        with _sqm_cache_lock:
            generation = _sqm_cache_generation
            dirty = _sqm_cache_published != generation
            if not force and time.monotonic() - _sqm_cache_attempted_at < SQM_CACHE_INTERVAL and not dirty:
                return
            _sqm_cache_attempted_at = time.monotonic()
            observed = copy.deepcopy(_sqm_observed_data)
            previous = copy.deepcopy(_sqm_cache_data)
        snapshot, error = None, ""
        try:
            if (not force and observed and observed["generation"] == generation
                    and time.time() - observed["checked_at"] <= SQM_CACHE_MAX_AGE):
                queues, error = observed.get("queues", []), observed.get("error", "")
                checked_at = observed["checked_at"]
            else:
                checked_at = time.time()
                queues, error = _read_sqm_queues()
            if not error:
                # Link discovery changes infrequently. Keep its own cadence so
                # routine cache publication does not add SSH traffic.
                if force or not previous or time.time() - previous["interfaces_checked_at"] >= 60:
                    interfaces = [name for name in _router_interfaces()
                                  if name != "lo" and not name.startswith("ifb")]
                    interfaces_checked_at = time.time()
                else:
                    interfaces = previous["interfaces"]
                    interfaces_checked_at = previous["interfaces_checked_at"]
                rows = _network_state().get("networks", [])
                roles = {row["device"]: row["name"] + " · " + row["role"]
                         for row in rows if row.get("device") and row.get("subnets")}
                interfaces = sorted(set(interfaces + [q["interface"] for q in queues if q.get("interface")]))
                primary = next((q for q in queues if q.get("interface") == _primary_lan_device()), None)
                primary = primary or next((q for q in queues if q.get("interface") == WAN_IFACE), None)
                with _sqm_conditional_lock:
                    rules = _load_sqm_conditional_store()["rules"]
                    baselines = [_sqm_baseline_for_ui(q, rules.get(q.get("interface"), {})) for q in queues]
                snapshot = {"queues": copy.deepcopy(queues), "interfaces": interfaces, "roles": roles,
                            "baseline_queues": baselines, "checked_at": checked_at,
                            "interfaces_checked_at": interfaces_checked_at,
                            "primary_interface": (primary or {}).get("interface", _primary_lan_device())}
        except (subprocess.TimeoutExpired, OSError) as exc:
            error = "SQM read timed out" if isinstance(exc, subprocess.TimeoutExpired) else str(exc)
        with _sqm_cache_lock:
            if generation == _sqm_cache_generation:
                _sqm_cache_data, _sqm_cache_error = snapshot, error
                # Failed reads retry at the regular cadence, without a busy loop.
                _sqm_cache_published = generation


def _load_sqm_names():
    names = _load_json(SQM_NAMES_FILE, {})
    return {iface: name.strip() for iface, name in names.items()
            if isinstance(iface, str) and _IFACE_RE.fullmatch(iface)
            and isinstance(name, str) and name.strip()} if isinstance(names, dict) else {}


def _load_sqm_mode():
    saved = _load_json(SQM_MODE_FILE, {})
    if (isinstance(saved, dict) and saved.get("mode") == "single"
            and isinstance(saved.get("interface"), str)
            and _IFACE_RE.fullmatch(saved["interface"])
            and saved["interface"] != "lo" and not saved["interface"].startswith("ifb")):
        return {"mode": "single", "interface": saved["interface"]}
    return {"mode": "multiple", "interface": ""}


def _apply_single_sqm(queues, selected):
    """Commit one enabled queue; roll back config and scoped runtime on failure."""
    interfaces = [q.get("interface", "") for q in queues]
    if len(set(interfaces)) != len(interfaces):
        return False, "Duplicate SQM queues; resolve them before choosing Single interface"
    if selected not in interfaces:
        return False, "Configure this interface's Baseline first"
    for queue in queues:
        if (not _IFACE_RE.fullmatch(queue.get("interface", ""))
                or queue["interface"] == "lo" or queue["interface"].startswith("ifb")
                or not re.fullmatch(r"[A-Za-z0-9_]+|@queue\[\d+\]", queue.get("section", ""))):
            return False, "Invalid SQM queue"
    # Stop every other interface, including any obsolete runtime state. An
    # already-enabled selected queue keeps its roots and current Daily rates.
    affected = [q for q in queues if q["interface"] != selected or q.get("enabled") != "1"]
    rollback = ["set +e", "uci revert sqm", 'cp "$sqm_mode_backup" /etc/config/sqm']
    for queue in affected:
        rollback.append("( " + _sqm_apply_script(shlex.quote(queue["interface"]),
                         "1" if queue.get("enabled") == "1" else "0")
                        + ' ) || echo "SQM rollback incomplete" >&2')
    commands = ["set -e", "sqm_mode_backup=$(mktemp)",
                'cp /etc/config/sqm "$sqm_mode_backup"',
                "cp /etc/config/sqm /etc/config/sqm.manager-bak",
                'sqm_mode_finish() { sqm_mode_rc=$?; trap - EXIT; '
                'if [ "$sqm_mode_rc" -ne 0 ]; then ' + "; ".join(rollback) + '; fi; '
                'rm -f "$sqm_mode_backup"; exit "$sqm_mode_rc"; }',
                "trap sqm_mode_finish EXIT"]
    for queue in queues:
        section = "sqm." + shlex.quote(queue["section"])
        enabled = "1" if queue["interface"] == selected else "0"
        commands.append(f"uci set {section}.enabled={enabled}")
        if enabled == "0":
            # Disabling Daily must retain the saved normal bandwidth, rather
            # than leaving its temporary throttled rates in the disabled queue.
            normal = _sqm_baseline_for_ui(queue, _load_sqm_conditional(queue["interface"]))
            for key in ("download", "upload"):
                if normal.get(key) != _sqm_for_ui(queue).get(key):
                    rate = _kbytes_to_kbits(normal[key], 10_000_000)
                    commands.append(f"uci set {section}.{key}={rate}")
    commands.append("uci commit sqm")
    for queue in affected:
        if queue["interface"] != selected:
            commands.append(_sqm_apply_script(shlex.quote(queue["interface"]), "0"))
    if any(q["interface"] == selected for q in affected):
        commands.append(_sqm_apply_script(shlex.quote(selected), "1"))
    for queue in queues:
        enabled = "1" if queue["interface"] == selected else "0"
        section = "sqm." + shlex.quote(queue["section"])
        commands.append(f'[ "$(uci -q get {section}.enabled)" = {enabled} ]')
    rc, output, error = ssh("; ".join(commands), timeout=60)
    return rc == 0, (output.decode(errors="replace") + error).strip() if rc else ""


@app.route("/api/sqm/mode", methods=["PUT"])
@requires_auth
def sqm_mode():
    body = request.get_json(force=True)
    if not isinstance(body, dict) or body.get("mode") not in ("single", "multiple"):
        return jsonify(ok=False, output="Choose Single interface or Multiple interfaces"), 400
    with _sqm_settings_lock:
        mode = {"mode": body["mode"], "interface": ""}
        if mode["mode"] == "multiple":
            _save_json(SQM_MODE_FILE, mode)
            return jsonify(ok=True, sqm_mode=mode, output="Multiple interfaces; queues unchanged")
        iface = body.get("interface")
        if (not isinstance(iface, str) or not _IFACE_RE.fullmatch(iface)
                or iface == "lo" or iface.startswith("ifb")):
            return jsonify(ok=False, output="Choose an SQM interface"), 400
        queues, error = _read_sqm_queues()
        if error:
            return jsonify(ok=False, output=error), 502
        if len([q for q in queues if q.get("interface") == iface]) != 1:
            return jsonify(ok=False, output="Configure one Baseline for " + iface + " first"), 409
        with _punishment_tc_lock:
            ok, error = _apply_single_sqm(queues, iface)
        if not ok:
            return jsonify(ok=False, output=error or "SQM mode apply failed; previous mode retained"), 502
        with _sqm_conditional_lock:
            for queue in queues:
                if queue["interface"] != iface:
                    _turn_off_sqm_daily(queue["interface"], clear_baseline=True)
        mode["interface"] = iface
        _save_json(SQM_MODE_FILE, mode)
        daily_ok, daily_message = _reconcile_sqm_conditional(force=True)
        queues_ok, queues_message = _refresh_punishment()
        pending = "; ".join(message for success, message in
                            ((daily_ok, daily_message), (queues_ok, queues_message)) if not success)
        return jsonify(ok=True, sqm_mode=mode, output="Single interface: " + iface,
                       tc_error="SQM mode saved; " + pending if pending else "")


@app.route("/api/sqm/name", methods=["PUT"])
@requires_auth
def sqm_name():
    body = request.get_json(force=True)
    if not isinstance(body, dict):
        return jsonify(ok=False, output="SQM name must be an object"), 400
    iface, name = body.get("interface"), body.get("name", "")
    if (not isinstance(iface, str) or not _IFACE_RE.fullmatch(iface)
            or iface == "lo" or iface.startswith("ifb")):
        return jsonify(ok=False, output="invalid interface"), 400
    if not isinstance(name, str):
        return jsonify(ok=False, output="name must be text"), 400
    name = name.strip()
    if len(name) > 64 or any(ord(char) < 32 for char in name):
        return jsonify(ok=False, output="name must be 64 characters or fewer without control characters"), 400
    with _sqm_names_lock:
        names = _load_sqm_names()
        if name:
            names[iface] = name
        else:
            names.pop(iface, None)
        _save_json(SQM_NAMES_FILE, names)
    return jsonify(ok=True, interface=iface, name=name)


@app.route("/api/sqm", methods=["GET", "PUT"])
@requires_auth
def sqm():
    if request.method == "GET":
        if request.args.get("refresh") == "1":
            _refresh_sqm_cache(force=True)
        with _sqm_cache_lock:
            snapshot = copy.deepcopy(_sqm_cache_data)
            error = _sqm_cache_error
            dirty = _sqm_cache_published != _sqm_cache_generation
        if error:
            return jsonify(ok=False, stale=True, output=error), 502
        age = max(0, time.time() - snapshot["checked_at"]) if snapshot else None
        if not snapshot or dirty or age > SQM_CACHE_MAX_AGE:
            return jsonify(ok=False, pending=True, stale=True, age=age, output="Refreshing SQM"), 202
        queues, interfaces, roles = snapshot["queues"], snapshot["interfaces"], snapshot["roles"]
        primary = next((q for q in queues if q.get("interface") == snapshot["primary_interface"]), None)
        mode = _load_sqm_mode()
        selected = (request.args.get("interface") or mode["interface"]
                    or (primary or {}).get("interface") or _primary_lan_device())
        matches = [q for q in queues if q.get("interface") == selected]
        if len(matches) > 1:
            return jsonify(ok=False, output="Duplicate SQM queues for " + selected), 409
        config = matches[0] if matches else {}
        baselines = snapshot["baseline_queues"]
        baseline_config = next((q for q in baselines if q.get("interface") == selected), {})
        return jsonify(ok=True, configured=bool(config), config=_sqm_for_ui(config),
                       baseline_config=baseline_config, baseline_queues=baselines,
                       checked_at=snapshot["checked_at"], age=age, stale=False, cached=True,
                       selected_interface=selected, interfaces=interfaces, interface_roles=roles,
                       queues=[_sqm_for_ui(q) for q in queues], rate_unit="KB/s",
                       interface_names=_load_sqm_names(), wan_interface=WAN_IFACE, sqm_mode=mode,
                       primary_interface=(primary or {}).get("interface", _primary_lan_device()),
                       output="" if config else "No SQM queue · Apply to create")
    with _sqm_settings_lock:
        queues, error = _read_sqm_queues()
        if error:
            return jsonify(ok=False, output=error), 502
        interfaces = [name for name in _router_interfaces() if name != "lo" and not name.startswith("ifb")]
        rows = _network_state().get("networks", [])
        roles = {row["device"]: row["name"] + " · " + row["role"]
                 for row in rows if row.get("device") and row.get("subnets")}
        for config in queues:
            if config.get("interface") and config["interface"] not in interfaces:
                interfaces.append(config["interface"])
        interfaces = sorted(set(interfaces))
        primary = next((q for q in queues if q.get("interface") == _primary_lan_device()), None)
        primary = primary or next((q for q in queues if q.get("interface") == WAN_IFACE), None)
        body = request.get_json(force=True)
        if not isinstance(body, dict):
            return jsonify(ok=False, output="SQM settings must be an object"), 400
        try:
            down = _kbytes_to_kbits(body["download"], 10_000_000)
            up = _kbytes_to_kbits(body["upload"], 10_000_000)
        except (KeyError, TypeError, ValueError):
            return jsonify(ok=False, output="download/upload must be valid KB/s values"), 400
        iface, qdisc, script = body.get("interface", ""), body.get("qdisc", "cake"), body.get("script", "piece_of_cake.qos")
        if (not isinstance(iface, str) or not _IFACE_RE.fullmatch(iface) or iface not in interfaces
                or qdisc not in _SQM_QDISC or script not in _SQM_SCRIPT):
            return jsonify(ok=False, output="invalid interface or SQM value"), 400
        matches = [q for q in queues if q.get("interface") == iface]
        if len(matches) > 1:
            return jsonify(ok=False, output="Duplicate SQM queues for " + iface), 409
        config = matches[0] if matches else {}
        settings = {"enabled": "1" if body.get("enabled") else "0", "interface": iface,
                    "qdisc": qdisc, "script": script, "download": down, "upload": up}
        mode = _load_sqm_mode()
        if mode["mode"] == "single" and iface != mode["interface"] and settings["enabled"] == "1":
            return jsonify(ok=False, output="Single interface mode: choose " + iface + " under SQM mode first"), 409
        is_primary = bool(primary and config.get("section") == primary["section"])
        if is_primary:
            if any(config.get(key) != settings[key] for key in ("enabled", "interface", "qdisc", "script")):
                with _punishment_tc_lock:
                    ok, error = _restart_sqm(settings)
            else:
                ok, error = _set_sqm_rates({"download": down, "upload": up})
        elif config and qdisc == "cake" and all(config.get(key) == settings[key]
                for key in ("enabled", "interface", "qdisc", "script")) and settings["enabled"] == "1":
            ok, error = _set_sqm_rates({"download": down, "upload": up}, iface)
        else:
            with _punishment_tc_lock:
                ok, error = _save_extra_sqm(config, settings)
        if not ok:
            return jsonify(ok=False, output=error), 502
        if settings["enabled"] == "0":
            with _sqm_conditional_lock:
                _turn_off_sqm_daily(iface, clear_baseline=True)
            queues_ok, queues_message = (_refresh_punishment() if is_primary else _refresh_punishment(iface))
            # A successful stop is saved even if another queue needs attention.
            return jsonify(ok=True, output="Disabled " + iface + "; Daily off",
                           tc_error=("Disabled " + iface + "; Daily off. Client queues pending: " + queues_message)
                           if not queues_ok else "")
        _set_sqm_conditional_baseline({"download": down, "upload": up}, iface)
        ok, message = _reconcile_sqm_conditional(force=True, interface=iface)
        queues_ok, queues_message = (_refresh_punishment() if is_primary else _refresh_punishment(iface))
        if not queues_ok:
            return jsonify(ok=False, output="SQM saved; client queues: " + queues_message), 502
        return jsonify(ok=ok, output="Applied " + iface + ("; " + message if message else "")), (200 if ok else 502)


@app.route("/api/sqm/conditional", methods=["GET", "PUT"])
@requires_auth
def sqm_conditional():
    if request.method == "GET":
        interface = request.args.get("interface") or _primary_lan_device()
        with _sqm_conditional_lock:
            return jsonify(ok=True, **_sqm_conditional_response(interface))
    body = request.get_json(force=True)
    if not isinstance(body, dict):
        return jsonify(ok=False, output="daily SQM rule must be an object"), 400
    interface = body.get("interface", _primary_lan_device())
    if not isinstance(interface, str) or interface not in _sqm_rule_interfaces():
        return jsonify(ok=False, output="Select a discovered LAN or the WAN interface"), 400
    with _sqm_settings_lock, _sqm_conditional_lock:
        policy = _load_sqm_conditional(interface)
        try:
            enabled = body.get("enabled", policy["enabled"])
            if not isinstance(enabled, bool):
                raise ValueError("enabled")
            force_today = body.get("force_today", False)
            if not isinstance(force_today, bool):
                raise ValueError("force_today")
            threshold_gb = _clean_sqm_conditional_gb(body.get("threshold_gb", policy["threshold_gb"]))
            download = _kbytes_to_kbits(body.get("download", _kbits_to_kbytes(policy["download"])),
                                         PUNISH_CAP_MAX)
            upload = _kbytes_to_kbits(body.get("upload", _kbits_to_kbytes(policy["upload"])),
                                       PUNISH_CAP_MAX)
        except (TypeError, ValueError) as error:
            return jsonify(ok=False, output=f"invalid daily SQM rule: {error}"), 400
        if enabled or force_today:
            queues, error = _read_sqm_queues()
            if error:
                return jsonify(ok=False, output=error), 502
            if not _sqm_baseline_enabled(interface, queues):
                return jsonify(ok=False, output="Enable this interface's Baseline before enabling Daily"), 409
            if interface == WAN_IFACE and (not download or not upload):
                return jsonify(ok=False, output="Shared WAN Daily requires positive download and upload rates"), 400
            queue, error = _daily_sqm_queue(interface)
            if not queue:
                return jsonify(ok=False, output=error), 409
        if force_today:
            enabled = True
            today, _ = _today_sqm_rule_usage(interface)
            policy["forced_date"] = today
        elif not enabled:
            policy["forced_date"] = ""
        policy.update(enabled=enabled, threshold_gb=threshold_gb, download=download, upload=upload,
                      error="")
        _save_sqm_conditional(policy, interface)
    ok, message = _reconcile_sqm_conditional(force=True, interface=interface)
    with _sqm_conditional_lock:
        result = _sqm_conditional_response(interface)
    return jsonify(ok=ok, output=message, **result), \
        (200 if ok else 502)


@app.route("/api/action", methods=["POST"])
@requires_auth
def action():
    body = request.get_json(force=True)
    act = body.get("action", "")
    mac = body.get("mac", "")
    if act == "delete":
        if not MAC_RE.match(mac):
            return jsonify(ok=False, output="invalid MAC"), 400
        mac = mac.lower()
        with _history_lock:
            seen = _load_seen()
            deleted = _load_deleted()
            seen.pop(mac, None)
            deleted.add(mac)
            _save_seen(seen)
            _save_deleted(deleted)
        log.info("deleted offline client history %s", mac)
        return jsonify(ok=True, output=f"deleted {mac}")
    if act in {"punish", "unpunish"}:
        if not MAC_RE.match(mac):
            return jsonify(ok=False, output="invalid MAC"), 400
        mac = mac.lower()
        target = _client_tc_interface(_cached_client(mac))
        if act == "punish" and not target:
            return jsonify(ok=False, output="Client must belong to a discovered managed LAN"), 409
        with _punishment_lock:
            previous = _load_punishment_policy()
            policy = dict(previous)
            punished = set(policy["punished"])
            if act == "punish":
                punished.add(mac)
            else:
                punished.discard(mac)
                if policy.get("auto_seen") is not None:
                    policy["auto_seen"] = sorted(set(policy["auto_seen"]) | {mac})
            policy["punished"] = sorted(punished)
            _save_punishment_policy(policy)
        ok, detail = _refresh_punishment(target) if target else _refresh_punishment()
        if not ok:
            # Do not leave a client marked as punished when its qdisc could not
            # be installed. The previous policy remains the truthful state.
            with _punishment_lock:
                restored = _load_punishment_policy()
                punished = set(restored["punished"])
                if mac in previous["punished"]:
                    punished.add(mac)
                else:
                    punished.discard(mac)
                restored["punished"] = sorted(punished)
                _save_punishment_policy(restored)
        log.info("%s %s", act, mac)
        return jsonify(ok=ok, output=f"{act}ed {mac}; {detail}"), (200 if ok else 502)
    if act in {"block", "unblock"}:
        if not MAC_RE.match(mac):
            return jsonify(ok=False, output="invalid MAC"), 400
        mac = mac.lower()
        blocked = _load_blocked()
        if act == "block":
            ndsctl(f"deauth {mac}")
            blocked.add(mac)
        else:
            blocked.discard(mac)
        _save_blocked(blocked)
        rc, out, err = _apply_blocks(blocked)
        log.info("%s %s rc=%s %s", act, mac, rc, err.strip())
        return respond(rc, err.strip() or f"{act}ed {mac}")
    if act in {"deauth", "trust", "untrust", "auth"}:
        if not MAC_RE.match(mac):
            return jsonify(ok=False, output="invalid MAC"), 400
        if act == "deauth" and _client_mode(_cached_client(mac)) == "auto_auth":
            return jsonify(ok=False, output="deauth is unavailable while auto-login is active"), 409
        if act == "auth":
            try:
                mins = int(body.get("minutes", 0))
            except (TypeError, ValueError):
                return jsonify(ok=False, output="invalid minutes"), 400
            return respond(*ndsctl(f"auth {mac} {mins}"))
        rc, text = ndsctl(f"{act} {mac}")
        if rc == 0 and act in {"trust", "untrust"}:
            trusted = _trusted_macs()
            if act == "trust":
                trusted.add(mac.lower())
            else:
                trusted.discard(mac.lower())
            _set_trusted_macs(trusted)
        return respond(rc, text)
    if act == "debuglevel":
        lvl = str(body.get("level", ""))
        if lvl not in {"0", "1", "2", "3"}:
            return jsonify(ok=False, output="invalid level"), 400
        return respond(*ndsctl(f"debuglevel {lvl}"))
    if act in {"start", "stop", "restart"}:
        rc, out, err = ssh(f"/etc/init.d/opennds {act}")
        return respond(rc, out.decode(errors="replace") + err or "done")
    return jsonify(ok=False, output="unknown action"), 400


@app.route("/api/config", methods=["GET", "PUT"])
@requires_auth
def config():
    q = shlex.quote(CONF)
    if request.method == "GET":
        rc, out, err = ssh(f"cat {q}")
        return jsonify(ok=rc == 0, content=out.decode(errors="replace"), output=err), (200 if rc == 0 else 502)
    content = request.get_json(force=True).get("content", "")
    rc, _, err = ssh(f"cp {q} {q}.bak; cat > {q}", content.encode())
    return respond(rc, err or "saved (backup: .bak); restart openNDS to apply")


@app.route("/api/logs")
@requires_auth
def logs():
    n = min(int(request.args.get("lines", 200)), 2000)
    rc, out, err = ssh(f"logread | grep -i nds | tail -n {n}")
    return jsonify(ok=True, output=out.decode(errors="replace") or err)


_fas_key_lock = threading.Lock()


def _fas_host_settings():
    parsed = urlsplit(FAS_BASE_URL)
    if (parsed.scheme != "http" or not parsed.hostname or parsed.username or parsed.password
            or parsed.path not in ("", "/") or parsed.query or parsed.fragment):
        raise ValueError("FAS_BASE_URL must be an HTTP origin such as http://192.168.1.198:8080")
    try:
        address = ipaddress.ip_address(parsed.hostname)
        port = parsed.port or 80
    except ValueError as e:
        raise ValueError("FAS_BASE_URL must use a numeric IPv4 address and valid port") from e
    if address.version != 4 or not address.is_private or not 1 <= port <= 65535:
        raise ValueError("FAS_BASE_URL must use a private IPv4 address and valid port")
    return str(address), port


def _fas_key():
    with _fas_key_lock:
        os.makedirs(os.path.dirname(FAS_KEY_FILE), exist_ok=True)
        try:
            with open(FAS_KEY_FILE, encoding="ascii") as source:
                key = source.read().strip()
        except FileNotFoundError:
            key = secrets.token_hex(32)
            try:
                fd = os.open(FAS_KEY_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            except FileExistsError:
                with open(FAS_KEY_FILE, encoding="ascii") as source:
                    key = source.read().strip()
            else:
                with os.fdopen(fd, "w", encoding="ascii") as target:
                    target.write(key + "\n")
        if not re.fullmatch(r"[0-9a-f]{64}", key):
            raise RuntimeError("stored FAS key is invalid")
        os.chmod(FAS_KEY_FILE, 0o600)
        return key


def _gateway_origin(gatewayaddress, authdir="/opennds_auth/"):
    if not isinstance(gatewayaddress, str) or len(gatewayaddress) > 128:
        raise ValueError("invalid gateway address")
    parsed = urlsplit("//" + gatewayaddress)
    try:
        address = ipaddress.ip_address(parsed.hostname or "")
        port = parsed.port or 2050
    except ValueError as e:
        raise ValueError("invalid gateway address") from e
    if parsed.path or parsed.query or parsed.fragment or parsed.username or address.version != 4:
        raise ValueError("invalid gateway address")
    auth_path = authdir if isinstance(authdir, str) and authdir else "/opennds_auth/"
    if not auth_path.startswith("/"):
        auth_path = "/" + auth_path
    if (len(auth_path) > 128 or not re.fullmatch(r"/[A-Za-z0-9_./-]+", auth_path)
            or any(part == ".." for part in auth_path.split("/"))):
        raise ValueError("invalid openNDS authentication path")
    authority = f"{address}:{port}"
    return f"http://{authority}", f"http://{authority}{auth_path}"


def _decode_fas_query(encoded):
    if not isinstance(encoded, str) or not encoded or len(encoded) > 16384:
        raise ValueError("missing or oversized FAS request")
    encoded = encoded.replace(" ", "+")
    try:
        decoded = base64.b64decode(encoded, validate=True).decode("utf-8")
    except (ValueError, UnicodeError) as e:
        raise ValueError("invalid FAS request") from e
    values = {}
    for item in decoded.split(", "):
        name, separator, value = item.partition("=")
        if separator:
            # openNDS percent-encodes values such as originurl inside the
            # base64 FAS payload. Decode them before validating or forwarding
            # the original destination; otherwise auto-auth treats every
            # normal connectivity-check URL as invalid and shows the landing
            # page instead.
            values[name] = unquote(value)
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,256}", values.get("hid", "")):
        raise ValueError("FAS request is missing a valid client token")
    _gateway_origin(values.get("gatewayaddress", ""), values.get("authdir", "/opennds_auth/"))
    return values


def _read_hosted_index():
    index = os.path.join(HOSTED_PORTAL, "index.html")
    try:
        with open(index, encoding="utf-8") as source:
            page = source.read(PORTAL_TEMPLATE_MAX_BYTES + 1)
    except (OSError, UnicodeError) as e:
        raise RuntimeError(f"could not read hosted portal index.html: {e}") from e
    if len(page.encode("utf-8")) > PORTAL_TEMPLATE_MAX_BYTES:
        raise RuntimeError("hosted portal index.html is too large")
    return page


def _connected_portal_page():
    # Portals that opt in with {{CONNECTED}} render their own connected state.
    try:
        page = _read_hosted_index()
    except RuntimeError:
        return None
    if "{{CONNECTED}}" not in page:
        return None
    for name in ("{{AUTH_ACTION}}", "{{TOKEN}}", "{{REDIR}}"):
        page = page.replace(name, "")
    return page.replace("{{CONNECTED}}", "1")


def _hosted_fas_page(values, landing=False):
    if not landing and values.get("status") == "authenticated":
        custom = _connected_portal_page()
        if custom:
            return custom, "", ""
    if landing:
        try:
            with open(os.path.join(HOSTED_PORTAL, "connected.html"), encoding="utf-8") as src:
                return src.read(PORTAL_TEMPLATE_MAX_BYTES), "", ""
        except (OSError, UnicodeError):
            pass
        return ("<!doctype html><html lang=\"en\"><meta charset=\"utf-8\">"
                "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
                "<title>Connected</title><body><main><h1>You're connected</h1>"
                "<p>You can close this page and continue browsing.</p></main></body></html>"), "", ""
    if values.get("status") == "authenticated":
        return ("<!doctype html><html lang=\"en\"><meta charset=\"utf-8\">"
                "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
                "<title>Already connected</title><body><main><h1>Already connected</h1>"
                "<p>This device already has internet access.</p></main></body></html>"), "", ""
    gateway_origin, auth_action = _gateway_origin(
        values["gatewayaddress"], values.get("authdir", "/opennds_auth/"))
    encoded = request.args.get("fas", "").replace(" ", "+")
    redir = FAS_BASE_URL + "/fas?" + urlencode({"fas": encoded, "landing": "1"})
    # The manager completes the *new* session with its saved profile. The
    # opaque FAS request is verified against openNDS at continuation time.
    auth_action = FAS_BASE_URL + "/fas/continue"
    token = encoded
    form = (
        f'<form method="get" action="{html.escape(auth_action, quote=True)}">'
        f'<input type="hidden" name="tok" value="{token}">'
        f'<input type="hidden" name="redir" value="{html.escape(redir, quote=True)}">'
        '<button type="submit">Continue to the internet</button></form>'
    )
    page = _read_hosted_index()
    placeholder = "{{CONTINUE_FORM}}"
    auto_mode = _client_mode(values) != "portal"
    page = page.replace("{{CONNECTED}}", "1" if auto_mode else "0")
    custom_values = {"{{AUTH_ACTION}}": auth_action, "{{TOKEN}}": token, "{{REDIR}}": redir}
    if any(name in page for name in custom_values):
        for name, value in custom_values.items():
            page = page.replace(name, html.escape(value, quote=True))
        page = page.replace(placeholder, form)
    elif placeholder in page:
        page = page.replace(placeholder, form)
    elif re.search(r"</body\s*>", page, flags=re.IGNORECASE):
        page = re.sub(r"</body\s*>", form + "</body>", page, count=1, flags=re.IGNORECASE)
    else:
        page += form
    return page, gateway_origin, encoded


def _auto_auth_fas_redirect(values):
    """Complete secure FAS authentication without rendering the portal page."""
    response = redirect(FAS_BASE_URL + "/fas/continue?" + urlencode({
        "tok": request.args.get("fas", "").replace(" ", "+")}), code=302)
    response.headers["Cache-Control"] = "no-store"
    return response


def _fas_response(page, gateway_origin=""):
    response = make_response(page)
    response.mimetype = "text/html"
    allowed_form_origin = gateway_origin or "http://192.168.1.1"
    response.headers["Content-Security-Policy"] = (
        "sandbox allow-forms allow-scripts; default-src 'self'; style-src 'self' 'unsafe-inline'; "
        f"img-src 'self' data: {allowed_form_origin}; font-src 'self'; script-src 'self' 'unsafe-inline'; connect-src 'none'; "
        f"object-src 'none'; base-uri 'none'; form-action {allowed_form_origin} {FAS_BASE_URL}"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Cache-Control"] = "no-store"
    return response


@app.route("/fas")
def hosted_fas():
    if request.args.get("landing") == "1":
        page, _, _ = _hosted_fas_page({}, landing=True)
        return _fas_response(page)
    if request.args.get("status") == "authenticated":
        page, _, _ = _hosted_fas_page({"status": "authenticated"})
        return _fas_response(page)
    try:
        fields = _decode_fas_query(request.args.get("fas", ""))
        if _client_mode(fields) == "auto_auth":
            return _auto_auth_fas_redirect(fields)
        page, gateway_origin, _ = _hosted_fas_page(fields)
    except (RuntimeError, ValueError) as e:
        return Response(str(e), status=400, mimetype="text/plain")
    return _fas_response(page, gateway_origin)


@app.route("/fas/continue")
def hosted_fas_continue():
    """Verify the FAS return hash before authenticating a new session only."""
    try:
        fields = _decode_fas_query(request.args.get("tok", ""))
        rhid = hashlib.sha256((fields["hid"] + _fas_key()).encode("ascii")).hexdigest()
        with _auth_control_lock:
            rc, raw = ndsctl("json " + rhid)
            if rc != 0:
                return Response("Login request expired or is invalid. Reopen the portal.", status=403)
            record = _loads_nds_json(raw)
            candidates = (record.get("clients") or {}).values() if "clients" in record else [record]
            client = next((c for c in candidates if isinstance(c, dict) and
                           str(c.get("mac", "")).lower() == fields.get("clientmac", "").lower()), None)
            if not client or not MAC_RE.fullmatch(str(client.get("mac", ""))):
                return Response("Invalid client login request.", status=403)
            if fields.get("clientip") != client.get("ip"):
                return Response("Invalid client login request.", status=403)
            mac = client["mac"].lower()
            if mac in _load_blocked():
                return Response("This client is blocked.", status=403)
            if _client_mode(client) == "unmanaged":
                return Response("This network is not managed by openNDS. Ask the administrator to scan the LAN settings.", status=409)
            if client.get("state") == "Preauthenticated":
                effective = _effective(mac, _load_limits())
                # Let a naturally ended session detach/drain an old queue
                # before the Continue action starts the next session.
                _refresh_punishment()
                rc, text = _ndsctl_auth_with_limits(rhid, effective)
                if rc != 0 or not re.search(r"\bauthenticated\b", text, re.IGNORECASE):
                    return Response("Login could not complete. Please retry.", status=503)
                _auth_attempts[mac] = {"sample_at": int(time.time()), "completed_at": time.monotonic()}
                applied = _load_json(APPLIED_FILE, {})
                applied[mac] = _sig(effective)
                _save_json(APPLIED_FILE, applied)
                refresh = _load_session_refresh()
                if mac in refresh:
                    del refresh[mac]
                    _save_json(SESSION_REFRESH_FILE, refresh)
            elif client.get("state") != "Authenticated":
                return Response("The client is not ready to log in.", status=409)
        destination = FAS_BASE_URL + "/fas?landing=1"
        if _client_mode(client) == "auto_auth":
            origin = fields.get("originurl", "")
            parsed = urlsplit(origin)
            if parsed.scheme in {"http", "https"} and parsed.netloc and not parsed.username and not parsed.password and len(origin) <= 4096:
                destination = origin
        response = redirect(destination, code=302)
        response.headers["Cache-Control"] = "no-store"
        return response
    except (RuntimeError, ValueError, StopIteration):
        return Response("Invalid or expired FAS request.", status=403)


@app.route("/portal-content/<path:name>")
def hosted_portal_content(name):
    path = portal_path(name)
    if not path or not os.path.isfile(path):
        return "not found", 404
    try:
        with open(path, "rb") as source:
            content = source.read()
    except OSError:
        return "not found", 404
    response = Response(content, mimetype=mimetypes.guess_type(path)[0] or "application/octet-stream")
    response.headers["Content-Security-Policy"] = "sandbox; default-src 'none'; style-src 'unsafe-inline'; img-src data:"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Cache-Control"] = "public, max-age=300"
    return response


def _router_fas_status():
    command = (
        "printf 'enabled=%s\\n' \"$(uci -q get opennds.@opennds[0].enabled || true)\"; "
        "printf 'fasremoteip=%s\\n' \"$(uci -q get opennds.@opennds[0].fasremoteip || true)\"; "
        "printf 'fasport=%s\\n' \"$(uci -q get opennds.@opennds[0].fasport || true)\"; "
        "printf 'faspath=%s\\n' \"$(uci -q get opennds.@opennds[0].faspath || true)\"; "
        "printf 'fas_secure_enabled=%s\\n' \"$(uci -q get opennds.@opennds[0].fas_secure_enabled || true)\"; "
        "printf 'themespec_path=%s\\n' \"$(uci -q get opennds.@opennds[0].themespec_path || true)\"; "
        "if [ -n \"$(uci -q get opennds.@opennds[0].faskey)\" ]; then echo faskey_set=yes; "
        "else echo faskey_set=no; fi; "
        f"if [ -d {shlex.quote(PORTAL)} ] && "
        f"[ -z \"$(ls -A {shlex.quote(PORTAL)} 2>/dev/null)\" ]; "
        "then echo portal_empty=yes; else echo portal_empty=no; fi; "
        f"if ls -d {shlex.quote(PORTAL + '.manager-backup-')}* >/dev/null 2>&1; "
        "then echo portal_archived=yes; else echo portal_archived=no; fi"
    )
    rc, out, err = ssh(command)
    if rc != 0:
        return None, err or "could not read openNDS FAS settings"
    values = {}
    for line in out.decode(errors="replace").splitlines():
        name, separator, value = line.partition("=")
        if separator:
            values[name] = value
    return values, ""


@app.route("/api/portal/fas", methods=["GET", "POST"])
@requires_auth
def hosted_fas_config():
    try:
        address, port = _fas_host_settings()
    except ValueError as e:
        return jsonify(ok=False, output=str(e)), 400
    if request.method == "GET":
        status, error = _router_fas_status()
        if status is None:
            return jsonify(ok=False, output=error, url=FAS_BASE_URL), 502
        ready = (status.get("enabled") == "1" and status.get("fasremoteip") == address
                 and status.get("fasport") == str(port) and status.get("faspath") == "/fas"
                 and status.get("fas_secure_enabled") == "1" and not status.get("themespec_path"))
        manager_mode = _load_mode()["mode"]
        mode_ready = manager_mode == "portal"
        return jsonify(ok=True, url=FAS_BASE_URL, router_ready=ready and mode_ready,
                       manager_mode=manager_mode,
                       router_portal_disabled=not status.get("themespec_path"),
                       router_portal_empty=status.get("portal_empty") == "yes",
                       old_portal_archived=status.get("portal_archived") == "yes",
                       output="external FAS ready" if ready and mode_ready else "external FAS is not fully configured")
    if not os.path.isfile(os.path.join(HOSTED_PORTAL, "index.html")):
        return jsonify(ok=False, output="upload a local portal containing index.html first"), 409
    try:
        key = _fas_key()
    except (OSError, RuntimeError) as e:
        return jsonify(ok=False, output=f"could not prepare the FAS secret: {e}"), 500
    settings = {
        "enabled": "1",
        "fasremoteip": address,
        "fasport": str(port),
        "faspath": "/fas",
        "fas_secure_enabled": "1",
        "faskey": key,
    }
    commands = ["set -e", f"cp -p {shlex.quote(CONF)} {shlex.quote(CONF + '.bak')}"]
    for name, value in settings.items():
        commands.append(f"uci set opennds.@opennds[0].{name}={shlex.quote(value)}")
    commands.extend([
        "uci -q delete opennds.@opennds[0].fasremotefqdn || true",
        "uci -q delete opennds.@opennds[0].themespec_path || true",
        "uci commit opennds",
        "/etc/init.d/opennds restart",
    ])
    _change_mode("portal")
    rc, out, err = ssh("; ".join(commands), timeout=45)
    if rc != 0:
        return jsonify(ok=False, output=(out.decode(errors="replace") + err).strip()
                       or "openNDS FAS configuration failed; manager mode is now captive portal and router backup is /etc/config/opennds.bak"), 502
    log.info("configured openNDS FAS to use the manager-hosted portal at %s", FAS_BASE_URL)
    return jsonify(ok=True, url=FAS_BASE_URL,
                   output="manager switched to captive-portal mode; openNDS now uses the manager-hosted portal; router config backup: /etc/config/opennds.bak")


@app.route("/api/portal/router/archive", methods=["POST"])
@requires_auth
def archive_router_portal():
    try:
        address, port = _fas_host_settings()
    except ValueError as e:
        return jsonify(ok=False, output=str(e)), 400
    if PORTAL != "/etc/opennds/htdocs":
        return jsonify(ok=False, output="router portal archival only supports /etc/opennds/htdocs"), 409
    status, error = _router_fas_status()
    if status is None:
        return jsonify(ok=False, output=error), 502
    ready = (status.get("enabled") == "1" and status.get("fasremoteip") == address
             and status.get("fasport") == str(port) and status.get("faspath") == "/fas"
             and status.get("fas_secure_enabled") == "1" and not status.get("themespec_path")
             and _load_mode()["mode"] == "portal")
    if not ready:
        return jsonify(ok=False, output="configure and verify the manager-hosted FAS before archiving router portal files"), 409
    remote = shlex.quote(PORTAL)
    backup_prefix = shlex.quote(PORTAL + ".manager-backup-")
    command = (f"set -e; if [ -d {remote} ]; then stamp=$(date +%Y%m%d%H%M%S); "
               f"backup={backup_prefix}\"$stamp\"; mv {remote} \"$backup\"; "
               f"mkdir -p {remote}; chmod 755 {remote}; echo \"router portal files archived to $backup\"; "
               "else echo \"router portal directory already absent\"; fi")
    rc, out, err = ssh(command)
    if rc != 0:
        return jsonify(ok=False, output=(out.decode(errors="replace") + err).strip()
                       or "could not archive the router portal directory"), 502
    return jsonify(ok=True, output=out.decode(errors="replace").strip()
                   or "router portal files archived; openNDS continues to run using the external FAS")


@app.route("/fas-preview")
@requires_auth
def hosted_fas_preview():
    fake = {"hid": "preview-token", "gatewayaddress": "192.168.1.1"}
    try:
        page, origin, _ = _hosted_fas_page(fake)
    except (RuntimeError, ValueError) as e:
        return Response(str(e), status=500, mimetype="text/plain")
    return _fas_response(page, origin)


@app.route("/api/portal/types", methods=["GET", "POST"])
@requires_auth
def portal_types():
    if request.method == "GET":
        types = [{"id": key, "name": name} for key, (name, _) in PORTAL_TYPES.items()]
        return jsonify(ok=True, types=types, current=_current_portal_type())
    choice = (request.get_json(force=True, silent=True) or {}).get("type")
    if choice not in PORTAL_TYPES:
        return jsonify(ok=False, output="unknown portal type"), 400
    try:
        template = _directory_template(PORTAL_TYPES[choice][1])
        _install_portal_template(template, choice)
    except (RuntimeError, OSError) as e:
        return jsonify(ok=False, output=str(e)), 500
    return jsonify(ok=True, current=choice,
                   output=f"now hosting the {PORTAL_TYPES[choice][0]} portal (previous version: {HOSTED_PORTAL}.bak)")


@app.route("/api/portal/template/<kind>")
@requires_auth
def portal_template_download(kind):
    if kind not in {"current", "default"}:
        return jsonify(ok=False, output="unknown template"), 404
    try:
        with _portal_lock:
            template = _current_portal_template() if kind == "current" else _default_portal_template()
    except (RuntimeError, OSError) as e:
        return jsonify(ok=False, output=str(e)), 502
    filename = f"opennds-portal-{kind}.zip"
    return Response(template, mimetype="application/zip",
                    headers={"Content-Disposition": f'attachment; filename="{filename}"'})


@app.route("/api/portal/template", methods=["POST"])
@requires_auth
def portal_template_upload():
    uploaded = request.files.get("template")
    if not uploaded:
        return jsonify(ok=False, output="choose a ZIP template"), 400
    try:
        template, files = _uploaded_portal_template(uploaded.read(PORTAL_TEMPLATE_UPLOAD_MAX_BYTES + 1))
    except (RuntimeError, ValueError) as e:
        return jsonify(ok=False, output=str(e) or "invalid ZIP template"), 400
    if "index.html" not in _template_names(template):
        return jsonify(ok=False, output="portal template must contain an index.html"), 400
    try:
        _install_portal_template(template)
    except RuntimeError as e:
        return jsonify(ok=False, output=str(e)), 500
    log.info("installed %d hosted portal template files", files)
    output = f"hosted {files} portal files locally (previous version: {HOSTED_PORTAL}.bak)"
    return jsonify(ok=True, output=output)


@app.route("/api/portal/template/folder", methods=["POST"])
@requires_auth
def portal_folder_upload():
    try:
        template, files, notes = _folder_portal_template(request.files.getlist("files"))
    except (RuntimeError, ValueError) as e:
        return jsonify(ok=False, output=str(e) or "invalid portal folder"), 400
    if "index.html" not in _template_names(template):
        return jsonify(ok=False, output="portal folder must contain an index.html"), 400
    try:
        _install_portal_template(template)
    except RuntimeError as e:
        return jsonify(ok=False, output=str(e)), 500
    log.info("installed %d hosted portal folder files", files)
    output = f"hosted {files} portal file{'s' if files != 1 else ''} locally (previous version: {HOSTED_PORTAL}.bak)"
    if notes:
        output += "; " + "; ".join(notes)
    return jsonify(ok=True, output=output)


@app.route("/api/portal")
@requires_auth
def portal_list():
    files = []
    for root, _, names in os.walk(HOSTED_PORTAL):
        for name in names:
            path = os.path.join(root, name)
            if os.path.isfile(path) and not os.path.islink(path):
                files.append(os.path.relpath(path, HOSTED_PORTAL).replace(os.sep, "/"))
    return jsonify(ok=True, files=sorted(files), output=f"hosted locally at {HOSTED_PORTAL}")


@app.route("/api/portal/file", methods=["GET", "PUT", "DELETE"])
@requires_auth
def portal_file():
    p = portal_path(request.args.get("name", ""))
    if not p:
        return jsonify(ok=False, output="invalid path"), 400
    if request.method == "GET":
        try:
            with open(p, encoding="utf-8") as source:
                return jsonify(ok=True, content=source.read(), output="")
        except (OSError, UnicodeError) as e:
            return jsonify(ok=False, output=f"could not read local portal file: {e}"), 404
    if request.method == "DELETE":
        try:
            os.remove(p)
        except OSError as e:
            return jsonify(ok=False, output=f"could not delete local portal file: {e}"), 500
        return jsonify(ok=True, output="deleted local portal file")
    content = request.get_json(force=True).get("content", "")
    if not isinstance(content, str):
        return jsonify(ok=False, output="file content must be text"), 400
    try:
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8") as target:
            target.write(content)
    except OSError as e:
        return jsonify(ok=False, output=f"could not save local portal file: {e}"), 500
    return jsonify(ok=True, output="saved local portal file")


@app.route("/api/portal/upload", methods=["POST"])
@requires_auth
def portal_upload():
    f = request.files.get("file")
    p = portal_path(request.form.get("name") or (f.filename if f else ""))
    if not f or not p:
        return jsonify(ok=False, output="invalid upload"), 400
    try:
        os.makedirs(os.path.dirname(p), exist_ok=True)
        f.save(p)
    except OSError as e:
        return jsonify(ok=False, output=f"could not save local portal upload: {e}"), 500
    return jsonify(ok=True, output="uploaded file to the local portal")


@app.route("/portal-preview/<path:name>")
@requires_auth
def portal_preview(name):
    p = portal_path(name)
    if not p:
        return "not found", 404
    try:
        with open(p, "rb") as source:
            content = source.read()
    except OSError:
        return "not found", 404
    r = Response(content, mimetype=mimetypes.guess_type(p)[0] or "application/octet-stream")
    r.headers["Content-Security-Policy"] = "sandbox; default-src 'none'; style-src 'unsafe-inline'; img-src data:; form-action 'none'"
    return r


@app.route("/portal-design-preview")
@requires_auth
def portal_design_preview():
    html_text, _, _ = _hosted_fas_page({"hid": "preview-token", "gatewayaddress": "192.168.1.1"})
    return _fas_response(html_text, "http://192.168.1.1")


MODE_FILE = os.environ.get("MODE_FILE", "/data/mode.json")
AUTOTRUST_INTERVAL = float(os.environ.get("AUTOTRUST_INTERVAL", "3"))
MODES = {"portal", "auto_trust", "auto_auth"}
LIMITS_FILE = os.environ.get("LIMITS_FILE", "/data/limits.json")
APPLIED_FILE = os.environ.get("APPLIED_FILE", "/data/applied.json")
SESSION_REFRESH_FILE = os.environ.get("SESSION_REFRESH_FILE", "/data/session-refresh.json")
THROTTLE_FILE = os.environ.get("THROTTLE_FILE", "/data/limit-throttle.json")
# Order matches `ndsctl auth mac timeout up down upquota downquota`; values are the max allowed.
LIMIT_KEYS = {"timeout": 525600, "up": 10_000_000, "down": 10_000_000,
              "upq": 10**10, "downq": 10**10}
LATENCY_KEY = "latency_ms"
LATENCY_MAX = PUNISH_DELAY_MAX
THROTTLE_DEFAULTS = {"trigger_secs": 3, "final_rate": 0, "reset_secs": 30}
THROTTLE_RANGES = {"trigger_secs": (1, 300),
                   "final_rate": (0, PUNISH_CAP_MAX),
                   "reset_secs": (1, 86400)}
THROTTLE_AVERAGE_SAMPLES = 3
LIMIT_PROFILE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _-]{0,31}$")
DEFAULT_LIMIT_PROFILES = {
    "Open": {"timeout": "", "up": "", "down": "", "upq": "", "downq": "", LATENCY_KEY: 0},
    "Standard": {"timeout": 480, "up": 16384, "down": 65536, "upq": "", "downq": "", LATENCY_KEY: 0},
    "Guest": {"timeout": 120, "up": 4096, "down": 16384, "upq": "", "downq": "", LATENCY_KEY: 0},
}
BLANK_SIG = "|" * (len(LIMIT_KEYS) - 1)


def _load_json(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def _save_json(path, obj):
    _write_json(path, json.dumps(obj))


def _write_json(path, encoded):
    """Replace a complete snapshot atomically; keep the prior file on failure."""
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    temporary = None
    try:
        previous = os.stat(path)
    except FileNotFoundError:
        previous = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", dir=directory, prefix=".state-", delete=False) as f:
            temporary = f.name
            f.write(encoded)
            f.flush()
            if previous is not None:
                os.fchmod(f.fileno(), stat.S_IMODE(previous.st_mode))
                if os.geteuid() == 0:
                    os.fchown(f.fileno(), previous.st_uid, previous.st_gid)
        os.replace(temporary, path)
    finally:
        if temporary and os.path.exists(temporary):
            os.unlink(temporary)


def _load_wan_usage():
    raw = _load_json(WAN_USAGE_FILE, {})
    if not isinstance(raw, dict):
        raw = {}
    devices, flows, rates = {}, {}, {}

    def counters(value):
        if not isinstance(value, dict):
            return None
        try:
            download, upload = int(value.get("download", 0)), int(value.get("upload", 0))
        except (TypeError, ValueError):
            return None
        return {"download": download, "upload": upload} if download >= 0 and upload >= 0 else None

    for mac, values in (raw.get("devices") or {}).items():
        if not isinstance(mac, str) or not MAC_RE.match(mac) or not isinstance(values, dict):
            continue
        today = counters(values.get("today")) or {"download": 0, "upload": 0}
        # Earlier versions retained only an all-time total. It cannot be
        # accurately split into calendar months, so begin its month total
        # with the current daily value rather than mislabeling all history.
        month = counters(values.get("month")) or dict(today)
        devices[mac.lower()] = {"today": today, "month": month}
    for key, values in (raw.get("flows") or {}).items():
        if not isinstance(key, str) or not isinstance(values, dict):
            continue
        mac = str(values.get("mac", "")).lower()
        try:
            download, upload = int(values.get("download", 0)), int(values.get("upload", 0))
        except (TypeError, ValueError):
            continue
        if MAC_RE.match(mac) and download >= 0 and upload >= 0:
            flows[key] = {"mac": mac, "download": download, "upload": upload}
    for mac, values in (raw.get("rates") or {}).items():
        if not isinstance(mac, str) or not MAC_RE.match(mac) or not isinstance(values, dict):
            continue
        try:
            download, upload = float(values["download"]), float(values["upload"])
        except (KeyError, TypeError, ValueError):
            continue
        if download >= 0 and upload >= 0:
            rates[mac.lower()] = {"download": download, "upload": upload}
    try:
        sample_at = int(raw.get("sample_at", 0))
    except (TypeError, ValueError):
        sample_at = 0
    day = raw.get("day") if isinstance(raw.get("day"), str) else ""
    month = raw.get("month") if isinstance(raw.get("month"), str) else ""
    if not re.fullmatch(r"\d{4}-\d{2}", month):
        month = day[:7] if re.fullmatch(r"\d{4}-\d{2}-\d{2}", day) else ""
    boot_id = raw.get("boot_id") if isinstance(raw.get("boot_id"), str) else ""
    if not re.fullmatch(r"[0-9a-fA-F-]{8,64}", boot_id):
        boot_id = ""
    sampler_id = raw.get("sampler_id") if isinstance(raw.get("sampler_id"), str) else ""
    if not re.fullmatch(r"[0-9a-f]{32}", sampler_id):
        sampler_id = ""
    interface_last = raw.get("interface_last") if isinstance(raw.get("interface_last"), dict) else {}
    try:
        interface_last = {"rx": int(interface_last["rx"]), "tx": int(interface_last["tx"])}
    except (KeyError, TypeError, ValueError):
        interface_last = {}
    if any(value < 0 for value in interface_last.values()):
        interface_last = {}
    try:
        version = int(raw.get("version", 0))
    except (TypeError, ValueError):
        version = 0
    interface_days = {}
    raw_interface_days = raw.get("interface_days")
    for iface, values in (raw_interface_days.items() if isinstance(raw_interface_days, dict) else []):
        clean = counters(values)
        if isinstance(iface, str) and _IFACE_RE.fullmatch(iface) and clean:
            interface_days[iface] = clean
    try:
        interface_tracking_since = max(0, int(raw.get("interface_tracking_since", 0)))
    except (ValueError, TypeError):
        interface_tracking_since = 0
    return {"version": version, "day": day, "month": month, "sample_at": max(0, sample_at),
            "interface_days": interface_days, "interface_tracking_since": interface_tracking_since,
            "devices": devices, "flows": flows, "rates": rates, "boot_id": boot_id.lower(),
            "sampler_id": sampler_id, "interface_last": interface_last,
            "overview": raw.get("overview") if isinstance(raw.get("overview"), dict) else {}}


def _load_client_wan_history():
    raw = _load_json(CLIENT_WAN_HISTORY_FILE, {})
    raw = raw if isinstance(raw, dict) else {}
    clients = raw.get("clients") if isinstance(raw.get("clients"), dict) else {}
    clean = {}
    for mac, entries in clients.items():
        if not isinstance(mac, str) or not MAC_RE.match(mac) or not isinstance(entries, list):
            continue
        points = []
        for point in entries:
            if not isinstance(point, dict):
                continue
            try:
                at, download, upload = int(point["at"]), float(point["download"]), float(point["upload"])
            except (KeyError, TypeError, ValueError):
                continue
            if at > 0 and download >= 0 and upload >= 0:
                points.append({"at": at, "download": download, "upload": upload})
        if points:
            clean[mac.lower()] = points[-(CLIENT_WAN_HISTORY_SECS // CLIENT_WAN_HISTORY_BUCKET_SECS):]
    try:
        updated_at = max(0, int(raw.get("updated_at", 0)))
    except (TypeError, ValueError):
        updated_at = 0
    return {"updated_at": updated_at, "clients": clean}


def _client_wan_history_state():
    global _client_wan_history_data
    if _client_wan_history_data is None:
        _client_wan_history_data = _load_client_wan_history()
    return _client_wan_history_data


def _record_client_wan_history(active_macs, rates, at):
    """Keep one compact per-minute rate point per active client for 24 hours."""
    data = _client_wan_history_state()
    cutoff = at - CLIENT_WAN_HISTORY_SECS
    bucket_at = at - (at % CLIENT_WAN_HISTORY_BUCKET_SECS)
    changed = False
    for mac in active_macs:
        rate = rates.get(mac)
        if not isinstance(rate, dict):
            continue
        try:
            point = {"at": bucket_at, "download": float(rate["download"]), "upload": float(rate["upload"])}
        except (KeyError, TypeError, ValueError):
            continue
        entries = data["clients"].setdefault(mac, [])
        if entries and entries[-1].get("at") == bucket_at:
            entries[-1] = point
        else:
            entries.append(point)
            changed = True
        data["clients"][mac] = [entry for entry in entries if entry["at"] >= cutoff]
    for mac, entries in list(data["clients"].items()):
        kept = [entry for entry in entries if entry["at"] >= cutoff]
        if kept:
            data["clients"][mac] = kept
        else:
            data["clients"].pop(mac, None)
            changed = True
    if changed:
        data["updated_at"] = at
        return json.dumps(data)
    return None


def _record_client_wan_live_history(active_macs, rates, at):
    """Keep the latest hour at the same one-second resolution as Overview."""
    cutoff = at - (CLIENT_WAN_LIVE_HISTORY_SECS - 1)
    for mac in active_macs:
        rate = rates.get(mac, {})
        try:
            point = {"at": at, "download": float(rate["download"]), "upload": float(rate["upload"])}
        except (KeyError, TypeError, ValueError):
            point = {"at": at, "download": None, "upload": None}
        entries = _client_wan_live_history.setdefault(mac, [])
        if entries and entries[-1].get("at") == at:
            entries[-1] = point
        else:
            entries.append(point)
        _client_wan_live_history[mac] = [entry for entry in entries if entry["at"] >= cutoff]
    for mac, entries in list(_client_wan_live_history.items()):
        kept = [entry for entry in entries if entry["at"] >= cutoff]
        if kept:
            _client_wan_live_history[mac] = kept
        else:
            _client_wan_live_history.pop(mac, None)


def _wan_usage_inputs(clients, now):
    """Map current openNDS IPv4 clients to MACs and select active devices."""
    ip_to_mac, active_macs = {}, set()
    for client in clients:
        if not isinstance(client, dict):
            continue
        mac, ip = str(client.get("mac", "")).lower(), str(client.get("ip", ""))
        try:
            is_ipv4 = ipaddress.ip_address(ip).version == 4
            online = now - int(client.get("last_active", 0)) < ONLINE_SECS
        except (TypeError, ValueError):
            is_ipv4 = online = False
        if MAC_RE.match(mac) and is_ipv4:
            ip_to_mac[ip] = mac
            if online:
                active_macs.add(mac)
    return ip_to_mac, active_macs


def _conntrack_read_command(ip_to_mac):
    """Filter on the router so local DNS/management flows never cross SSH.

    Both callers set wan_ips from the same interface used for accounting.
    The full original/reply records are retained for the existing parser.
    """
    addresses = []
    for value in ip_to_mac or {}:
        try:
            addresses.append(str(ipaddress.IPv4Address(value)))
        except (ipaddress.AddressValueError, TypeError):
            continue
    if not addresses:
        return "true"
    program = """BEGIN {
        split(clients, parts, " "); for (i in parts) client_ips[parts[i]] = 1;
        split(wan, parts, /[[:space:]]+/); for (i in parts) wan_addresses[parts[i]] = 1;
    }
    $1 == "ipv4" {
        source = ""; destination = ""; destinations = 0;
        for (i = 1; i <= NF; i++) {
            if ($i ~ /^src=/ && source == "") source = substr($i, 5);
            if ($i ~ /^dst=/ && ++destinations == 2) destination = substr($i, 5);
        }
        if (source in client_ips && destination in wan_addresses) print;
    }"""
    return (f"awk -v clients={shlex.quote(' '.join(sorted(set(addresses))))} "
            f'-v wan="$wan_ips" {shlex.quote(program)} '
            "/proc/net/nf_conntrack 2>/dev/null || true")


def _read_wan_flows(ip_to_mac, raw=None):
    """Read NATed IPv4 flows, whose reply destination is the WAN address."""
    if ip_to_mac is None or (not ip_to_mac and raw is None):
        return None
    if raw is None:
        interface = shlex.quote(WAN_IFACE)
        rc, raw, _ = ssh(
            "echo @@SAMPLE_AT; date +%s; "
            "echo @@BOOT_ID; cat /proc/sys/kernel/random/boot_id 2>/dev/null || true; "
            f"wan_ips=\"$(ip -4 -o addr show dev {interface} scope global "
            "| awk '{print $4}' | cut -d/ -f1)\"; echo @@WAN_IPS; printf '%s\\n' \"$wan_ips\"; "
            f"echo @@WAN_COUNTERS; cat /sys/class/net/{interface}/statistics/rx_bytes; "
            f"cat /sys/class/net/{interface}/statistics/tx_bytes; "
            "echo @@CONNTRACK; " + _conntrack_read_command(ip_to_mac), telemetry=True)
        if rc != 0:
            return None
    lines = raw.decode(errors="replace").splitlines()
    try:
        conntrack_marker = lines.index("@@CONNTRACK")
    except ValueError:
        return None
    boot_marker = lines.index("@@BOOT_ID") if "@@BOOT_ID" in lines else None
    sample_marker = lines.index("@@SAMPLE_AT") if "@@SAMPLE_AT" in lines else None
    sample_at = 0
    if sample_marker is not None and sample_marker + 1 < len(lines):
        try:
            sample_at = int(lines[sample_marker + 1])
        except ValueError:
            pass
    boot_id = ""
    if boot_marker is not None and boot_marker + 1 < len(lines):
        candidate = lines[boot_marker + 1].strip()
        if re.fullmatch(r"[0-9a-fA-F-]{8,64}", candidate):
            boot_id = candidate.lower()
    wan_marker = lines.index("@@WAN_IPS") if "@@WAN_IPS" in lines else None
    counter_marker = lines.index("@@WAN_COUNTERS") if "@@WAN_COUNTERS" in lines else None
    wan_end = counter_marker if counter_marker is not None else conntrack_marker
    wan_lines = lines[wan_marker + 1:wan_end] if wan_marker is not None else lines[:wan_end]
    wan_ips = set()
    for value in wan_lines:
        try:
            if ipaddress.ip_address(value).version == 4:
                wan_ips.add(value)
        except ValueError:
            pass
    if not wan_ips:
        return None
    interface_counters = {}
    if counter_marker is not None:
        try:
            interface_counters = dict(zip(
                ("rx", "tx"),
                (int(value) for value in lines[counter_marker + 1:conntrack_marker])))
        except ValueError:
            interface_counters = {}
    if set(interface_counters) != {"rx", "tx"} or min(interface_counters.values()) < 0:
        interface_counters = {}
    flows = {}
    for line in lines[conntrack_marker + 1:]:
        tuples = list(CONNTRACK_TUPLE_RE.finditer(line))
        if len(tuples) < 2:
            continue
        original, reply = tuples[0], tuples[1]
        mac = ip_to_mac.get(original["src"])
        if not mac or reply["dst"] not in wan_ips:
            continue
        ports = CONNTRACK_PORTS_RE.search(original["fields"])
        port_key = ":".join(ports.groups()) if ports else "-"
        protocol = line.split()[2] if len(line.split()) > 2 else "?"
        key = "|".join((protocol, original["src"], original["dst"], port_key, reply["src"], reply["dst"]))
        flows[key] = {"mac": mac, "upload": int(original["bytes"]), "download": int(reply["bytes"])}
    return sample_at, boot_id, interface_counters, flows


def _wan_usage_snapshot(ip_to_mac, active_macs, at, raw=None):
    """Accumulate active-client WAN bytes and rates from connection-tracking deltas."""
    global _wan_usage_live, _wan_usage_data
    sampled = _read_wan_flows(ip_to_mac, raw)
    if sampled is not None and sampled[0]:
        at = sampled[0]
    # Attribute new deltas at collection time. Moving/deleting a MAC later
    # must never move or erase bytes already charged to another interface.
    mac_interfaces = {}
    for ip, mac in (ip_to_mac or {}).items():
        network = _client_network({"ip": ip})
        if network and network.get("role") == "LAN":
            mac_interfaces[mac] = network["device"]
    hidden_ips = _infrastructure_client_ips()
    overview_macs = {mac for ip, mac in (ip_to_mac or {}).items() if ip not in hidden_ips} & active_macs
    with _wan_usage_lock:
        if _wan_usage_data is None:
            _wan_usage_data = _load_wan_usage()
        state = _wan_usage_data
        interface_days = state.setdefault("interface_days", {})
        if sampled is not None and not state.get("interface_tracking_since"):
            state["interface_tracking_since"] = at
        history_encoded = None
        # Earlier collectors could have concurrent readers of conntrack and
        # therefore accumulated the same flow more than once. Their totals
        # cannot be repaired per device, so restart them from this verified
        # conntrack/interface baseline once rather than present bad history.
        legacy_state = state["version"] < WAN_USAGE_SCHEMA_VERSION
        if legacy_state and sampled is not None:
            state.update(version=WAN_USAGE_SCHEMA_VERSION, devices={}, flows={}, rates={},
                         sample_at=0, boot_id="", sampler_id="", interface_last={})
        devices = state["devices"]
        for mac in active_macs:
            devices.setdefault(mac, {"today": {"download": 0, "upload": 0},
                                     "month": {"download": 0, "upload": 0}})
        stamp = _traffic_time(at)
        day, month = stamp.strftime("%Y-%m-%d"), stamp.strftime("%Y-%m")
        previous_at = state["sample_at"]
        day_changed = bool(state["day"] and state["day"] != day)
        month_changed = bool(state["month"] and state["month"] != month)
        if day_changed:
            interface_days.clear()
            for values in devices.values():
                values["today"] = {"download": 0, "upload": 0}
        if month_changed:
            for values in devices.values():
                values["month"] = {"download": 0, "upload": 0}
        state["day"] = day
        state["month"] = month
        deltas = {}
        baseline_needed = True
        if sampled is not None:
            _, boot_id, interface_counters, flows = sampled
            elapsed = at - previous_at
            # Conntrack counters are only trustworthy as deltas while sampling
            # remains continuous on the same router boot. After a manager or
            # router restart, a gap, or a day rollover, retain the saved
            # totals but establish a fresh baseline so old flow bytes are not
            # counted again in the new interval/day.
            baseline_needed = (not previous_at or elapsed < 0 or
                               elapsed >= WAN_USAGE_MAX_GAP or day_changed or month_changed or
                               (bool(boot_id) and boot_id != state["boot_id"]) or
                               state["sampler_id"] != WAN_USAGE_SAMPLER_ID)
            if baseline_needed:
                state["flows"] = flows
                state["rates"] = {}
                state["sample_at"] = at
                state["boot_id"] = boot_id
                state["sampler_id"] = WAN_USAGE_SAMPLER_ID
                state["interface_last"] = interface_counters
            else:
                current, deltas = {}, {}
                for key, flow in flows.items():
                    previous = state["flows"].get(key, {})
                    mac = flow["mac"]
                    current[key] = flow
                    # Keep an offline client's flow baseline fresh, but never
                    # add its WAN traffic until openNDS reports it online.
                    if mac not in active_macs:
                        continue
                    totals = devices.setdefault(mac, {"today": {"download": 0, "upload": 0},
                                                      "month": {"download": 0, "upload": 0}})
                    device_delta = deltas.setdefault(mac, {"download": 0, "upload": 0})
                    for direction in ("download", "upload"):
                        old = previous.get(direction, 0) if previous.get("mac") == mac else 0
                        delta = flow[direction] - old if flow[direction] >= old else flow[direction]
                        totals["today"][direction] += delta
                        totals["month"][direction] += delta
                        device_delta[direction] += delta
                # Conntrack describes individual flows while the WAN counter
                # describes the same interval as it crosses the interface.
                # It normally leaves some room for packet overhead and other
                # router traffic. If it ever exceeds that physical interval,
                # proportionally cap attribution rather than over-counting a
                # reused or malformed conntrack record.
                previous_interface = state.get("interface_last", {})
                try:
                    interface_delta = {
                        "download": interface_counters["rx"] - previous_interface["rx"],
                        "upload": interface_counters["tx"] - previous_interface["tx"],
                    }
                except (KeyError, TypeError, ValueError):
                    interface_delta = {}
                if set(interface_delta) == {"download", "upload"} and \
                        all(value >= 0 for value in interface_delta.values()):
                    for direction in ("download", "upload"):
                        attributed = sum(delta[direction] for delta in deltas.values())
                        allowed = interface_delta[direction]
                        if attributed > allowed:
                            for mac, delta in deltas.items():
                                original = delta[direction]
                                capped = original * allowed // attributed
                                correction = original - capped
                                delta[direction] = capped
                                devices[mac]["today"][direction] -= correction
                                devices[mac]["month"][direction] -= correction
                for mac, delta in deltas.items():
                    iface = mac_interfaces.get(mac)
                    if iface:
                        totals = interface_days.setdefault(iface, {"download": 0, "upload": 0})
                        for direction in ("download", "upload"):
                            totals[direction] += delta[direction]
                if previous_at and 0 < elapsed <= 10:
                    state["rates"] = {mac: {direction: delta[direction] / elapsed
                                             for direction in ("download", "upload")}
                                      for mac, delta in deltas.items()}
                    for mac in active_macs:
                        state["rates"].setdefault(mac, {"download": 0.0, "upload": 0.0})
                elif elapsed > 10:
                    state["rates"] = {}
                state["flows"] = current
                state["sample_at"] = at
                state["boot_id"] = boot_id
                state["sampler_id"] = WAN_USAGE_SAMPLER_ID
                state["interface_last"] = interface_counters
            history_encoded = _record_client_wan_history(active_macs, state["rates"], at)
            _record_client_wan_live_history(active_macs, state["rates"], at)
        else:
            # An unavailable collector/flow sample is a gap, not an idle LAN.
            # Do not charge the intervening bytes when sampling recovers.
            state["sampler_id"] = ""
            state["rates"] = {}
        _record_client_traffic(state, overview_macs, at, deltas,
                               sampled is not None, not baseline_needed and at > previous_at)
        state["devices"] = devices
        encoded = json.dumps(state)
        result = {}
        for mac, totals in devices.items():
            rate = state["rates"].get(mac, {})
            result[mac] = {"today_download": totals["today"]["download"],
                           "today_upload": totals["today"]["upload"],
                           "month_download": totals["month"]["download"],
                           "month_upload": totals["month"]["upload"],
                           "download_rate": rate.get("download"),
                           "upload_rate": rate.get("upload")}
        _wan_usage_live = {mac: dict(values) for mac, values in result.items()}
    _write_json(WAN_USAGE_FILE, encoded)
    if history_encoded is not None:
        _write_json(CLIENT_WAN_HISTORY_FILE, history_encoded)
    return result


def _live_wan_usage():
    with _wan_usage_lock:
        return {mac: dict(values) for mac, values in _wan_usage_live.items()}


def _client_wan_history(mac):
    """Return local history without contacting the router."""
    with _wan_usage_lock:
        data = _client_wan_history_state()
        live = list(_client_wan_live_history.get(mac, []))
        minute = list(data["clients"].get(mac, []))
        if live:
            first_live = live[0]["at"]
            minute = [entry for entry in minute if entry["at"] < first_live]
        return {"updated_at": max(data["updated_at"], live[-1]["at"] if live else 0),
                "history": minute + live,
                "recent_start_at": live[0]["at"] if live else 0,
                "recent_resolution": "seconds" if len(live) > 1 else "minutes"}


def _history_response(payload):
    """A timestamp cursor includes mutable boundary points and detects restarts."""
    raw = request.args.get("since")
    try:
        since = int(raw) if raw is not None else None
        if since is not None and since < 0:
            raise ValueError
    except ValueError:
        from werkzeug.exceptions import BadRequest
        raise BadRequest("since must be a non-negative timestamp")
    points = payload["history"]
    first = points[0]["at"] if points else 0
    last = points[-1]["at"] if points else 0
    generation = request.args.get("generation")
    reset = (since is None or not points or since < first or since > last or
             (generation is not None and generation != HISTORY_GENERATION))
    recent = payload.get("recent_start_at", 0)
    if not reset:
        points = [point for point in points if point["at"] >= since or
                  (recent and recent - 60 <= point["at"] < recent)]
    return {**payload, "history": points, "reset": reset,
            "history_start_at": first, "cursor": last, "generation": HISTORY_GENERATION}


def _with_live_wan_usage(payload):
    """Overlay one-second WAN values without mutating the client snapshot."""
    usage = _live_wan_usage()
    data = payload.get("data")
    clients = data.get("clients") if isinstance(data, dict) else None
    if not usage or not isinstance(clients, dict):
        return payload
    updated = {}
    for key, client in clients.items():
        if not isinstance(client, dict):
            updated[key] = client
            continue
        values = usage.get(str(client.get("mac", "")).lower())
        updated[key] = {**client, **({
            "wan_today_download_bytes": values["today_download"],
            "wan_today_upload_bytes": values["today_upload"],
            "wan_month_download_bytes": values["month_download"],
            "wan_month_upload_bytes": values["month_upload"],
            "wan_download_rate": values["download_rate"],
            "wan_upload_rate": values["upload_rate"],
        } if values else {})}
    return {**payload, "data": {**data, "clients": updated}}


def _clean_sqm_conditional_gb(value):
    try:
        amount = Decimal(str(value))
    except (InvalidOperation, ValueError):
        raise ValueError("threshold_gb")
    if not amount.is_finite() or not Decimal("0") < amount <= SQM_CONDITIONAL_GB_MAX:
        raise ValueError("threshold_gb")
    text = format(amount, "f")
    return text.rstrip("0").rstrip(".") if "." in text else text


def _clean_sqm_conditional(data):
    if not isinstance(data, dict):
        data = {}
    try:
        threshold_gb = _clean_sqm_conditional_gb(data.get("threshold_gb", "1"))
    except ValueError:
        threshold_gb = "1"
    rates = {}
    for key, default in (("download", 8192), ("upload", 4096)):
        try:
            rate = int(data.get(key, default))
        except (TypeError, ValueError):
            rate = default
        rates[key] = rate if 0 <= rate <= PUNISH_CAP_MAX else default
    baseline = {}
    raw_baseline = data.get("baseline")
    if isinstance(raw_baseline, dict):
        for key in ("download", "upload"):
            try:
                rate = int(raw_baseline[key])
            except (KeyError, TypeError, ValueError):
                continue
            if 0 <= rate <= PUNISH_CAP_MAX:
                baseline[key] = rate
    error = data.get("error", "")
    forced_date = data.get("forced_date", "")
    if not isinstance(forced_date, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", forced_date):
        forced_date = ""
    baselines = {}
    for scope, values in (data.get("baselines") or {}).items() if isinstance(data.get("baselines"), dict) else []:
        if scope in ("lan", "wan", "aggregate") and isinstance(values, dict) and set(values) == {"download", "upload"}:
            try:
                clean = {key: int(value) for key, value in values.items()}
                if all(0 <= value <= PUNISH_CAP_MAX for value in clean.values()):
                    baselines[scope] = clean
            except (ValueError, TypeError):
                pass
    placement = data.get("placement", "lan" if data.get("active") or baseline else "")
    return {"enabled": data.get("enabled") is True, "threshold_gb": threshold_gb, **rates,
            "active": data.get("active") is True, "baseline": baseline,
            "placement": placement if placement in ("lan", "wan", "aggregate") else "", "baselines": baselines,
            "forced_date": forced_date, "error": error if isinstance(error, str) else ""}


def _sqm_daily_interfaces():
    rows = _network_state().get("networks", [])
    interfaces = {row["device"]: row["name"] for row in rows
                  if row.get("role") == "LAN" and row.get("device") and row.get("subnets")}
    if not interfaces and not _network_state().get("initialized"):
        interfaces[_primary_lan_device()] = "LAN"
    return interfaces


def _sqm_rule_interfaces():
    """Daily rule targets; keep WAN out of per-LAN policy placement."""
    return {**_sqm_daily_interfaces(), WAN_IFACE: "WAN (all traffic)"}


def _today_sqm_rule_usage(interface):
    return (_today_wan_traffic_total() if interface == WAN_IFACE
            else _today_interface_wan_total(interface))


def _load_sqm_conditional_store():
    raw = _load_json(SQM_CONDITIONAL_FILE, {})
    raw = raw if isinstance(raw, dict) else {}
    if raw.get("version") == 2:
        rules = raw.get("rules", {})
        return {"version": 2, "rules": {iface: _clean_sqm_conditional(policy)
                for iface, policy in (rules.items() if isinstance(rules, dict) else [])
                if isinstance(iface, str) and _IFACE_RE.fullmatch(iface)}}
    # The old shared rule belongs only to the native LAN after migration.
    return {"version": 2, "rules": {_primary_lan_device(): _clean_sqm_conditional(raw)}}


def _load_sqm_conditional(interface=None):
    return _load_sqm_conditional_store()["rules"].get(interface or _primary_lan_device(),
                                                   _clean_sqm_conditional({}))


def _save_sqm_conditional(policy, interface=None):
    store = _load_sqm_conditional_store()
    store["rules"][interface or _primary_lan_device()] = policy
    _save_json(SQM_CONDITIONAL_FILE, store)


def _sqm_baseline_enabled(interface, queues):
    matches = [queue for queue in queues if queue.get("interface") == interface]
    return len(matches) == 1 and matches[0].get("enabled") == "1"


def _turn_off_sqm_daily(interface, clear_baseline=False):
    policy = _load_sqm_conditional(interface)
    previous = copy.deepcopy(policy)
    policy.update(enabled=False, active=False, forced_date="", error="")
    if clear_baseline:
        policy.update(baseline={}, baselines={}, placement="")
    if policy != previous:
        _save_sqm_conditional(policy, interface)
    return policy


def _today_interface_wan_total(interface):
    day = _traffic_time(time.time()).strftime("%Y-%m-%d")
    with _wan_usage_lock:
        state = _wan_usage_data if _wan_usage_data is not None else _load_wan_usage()
        totals = state.get("interface_days", {}).get(interface, {}) if state.get("day") == day else {}
        return day, max(0, int(totals.get("download", 0)) + int(totals.get("upload", 0)))


def _sqm_conditional_response(interface):
    store = _load_sqm_conditional_store()
    interfaces = _sqm_rule_interfaces()
    # Missing saved targets stay visible and never switch to another queue.
    names = sorted(set(interfaces) | set(store["rules"]),
                   key=lambda iface: (iface != _primary_lan_device(), iface))
    rules = [_sqm_conditional_for_ui(store["rules"].get(iface, _clean_sqm_conditional({})), iface)
             for iface in names]
    selected = next((rule for rule in rules if rule["interface"] == interface), None)
    selected = selected or _sqm_conditional_for_ui(_clean_sqm_conditional({}), interface)
    return {**selected, "rules": rules, "selected_interface": interface}


def _today_wan_traffic_total():
    """The SQM threshold is all traffic crossing the WAN interface."""
    with _wan_traffic_lock:
        data = _wan_traffic_state()
        day = _traffic_time(time.time()).strftime("%Y-%m-%d")
        totals = data["days"].get(day, {})
        try:
            total = int(totals.get("download", 0)) + int(totals.get("upload", 0))
        except (AttributeError, TypeError, ValueError):
            total = 0
    return day, max(0, total)


def _sqm_conditional_for_ui(policy, interface=None):
    interface = interface or _primary_lan_device()
    day, today_bytes = _today_sqm_rule_usage(interface)
    if interface == WAN_IFACE:
        with _wan_traffic_lock:
            tracking_since = _wan_traffic_state()["started_at"]
    else:
        with _wan_usage_lock:
            state = _wan_usage_data if _wan_usage_data is not None else _load_wan_usage()
            tracking_since = state.get("interface_tracking_since", 0)
    return {"interface": interface, "network": _sqm_rule_interfaces().get(interface, "Unavailable"),
            "available": interface in _sqm_rule_interfaces(), "tracking_since": tracking_since,
            "usage_scope": "all_wan" if interface == WAN_IFACE else "interface_wan_ipv4",
            "enabled": policy["enabled"], "threshold_gb": policy["threshold_gb"],
            "download": _kbits_to_kbytes(policy["download"]),
            "upload": _kbits_to_kbytes(policy["upload"]), "active": policy["active"],
            "forced_today": policy.get("forced_date") == day,
            "error": policy["error"], "today_date": day, "today_bytes": today_bytes,
            "wan_interface": WAN_IFACE, "threshold_unit": "GB", "rate_unit": "KB/s"}


def _get_sqm_rates():
    rc, out, err = ssh(_primary_sqm_command("set -e; uci -q get sqm.@queue[0].enabled; "
                       "uci -q get sqm.@queue[0].download; uci -q get sqm.@queue[0].upload"))
    lines = out.decode(errors="replace").splitlines()
    if rc != 0 or len(lines) != 3:
        return None, err or "could not read SQM rates"
    if lines[0].strip() != "1":
        return None, "SQM is disabled"
    try:
        rates = {"download": int(lines[1]), "upload": int(lines[2])}
    except ValueError:
        return None, "SQM rates are invalid"
    if any(not 0 <= rate <= PUNISH_CAP_MAX for rate in rates.values()):
        return None, "SQM rates are invalid"
    return rates, ""


def _restart_sqm(settings=None, interface=None):
    """Apply a structural change or recover queues using the saved SQM config.

    Caller owns _punishment_tc_lock; retain MAC identities across the reset.
    """
    commands = ["cp /etc/config/sqm /etc/config/sqm.manager-bak"]
    if settings:
        commands += [f"uci set sqm.@queue[0].{key}={shlex.quote(str(value))}"
                     for key, value in settings.items()]
        commands.append("uci commit sqm")
    commands.append(_sqm_apply_script('"$sqm_primary_iface"', '$(uci -q get sqm.@queue[0].enabled)'))
    state = _punishment_tc_state(interface)
    # Also record failed attempts, avoiding repeated disruptive recovery loops.
    _save_punishment_tc_state({**state, "recovery_at": time.time()}, interface)
    rc, out, err = ssh(_primary_sqm_command("set -e; " + "; ".join(commands), interface), timeout=30)
    if rc != 0:
        error = (out.decode(errors="replace") + err).strip() or "SQM restart failed"
        _save_punishment_tc_state({**_punishment_tc_state(interface), "error": error}, interface)
        return False, error
    _save_punishment_tc_state({**_punishment_tc_state(interface), "active": False,
                              "interfaces": None, "pending": {}, "error": ""}, interface)
    return True, ""


def _set_sqm_rates(rates, interface=None):
    """Change compatible bandwidth in place; restart SQM when necessary."""
    try:
        ingress, egress = int(rates["download"]), int(rates["upload"])
        if not 0 <= ingress <= PUNISH_CAP_MAX or not 0 <= egress <= PUNISH_CAP_MAX:
            return False, "SQM rates are invalid"
    except (KeyError, TypeError, ValueError):
        return False, "SQM rates are invalid"
    with _punishment_tc_lock:
        if not ingress or not egress:
            return _restart_sqm({"download": ingress, "upload": egress}, interface)
        interfaces, error = _punishment_interfaces(interface) if interface else _punishment_interfaces()
        if not interfaces:
            return _restart_sqm({"download": ingress, "upload": egress}, interface)
        wan_state = _wan_qos_state()
        if wan_state.get("installed") and interfaces == wan_state.get("interfaces"):
            try:
                wan_layouts = wan_shaping.inspect(ssh, interfaces)
                if all(layout["qdiscs"].get("root", {}).get("handle") == wan_shaping.MAJOR
                       for layout in wan_layouts.values()):
                    # The caller immediately reconciles the shared hierarchy.
                    # Keep classes/connection marks while changing its rates.
                    command = _primary_sqm_command(
                        f"set -e; uci set sqm.@queue[0].download={ingress}; "
                        f"uci set sqm.@queue[0].upload={egress}; uci commit sqm", interface)
                    rc, out, error = ssh(command)
                    return rc == 0, error if rc else ""
            except (ValueError, KeyError, TypeError):
                pass
        layouts, error = _inspect_managed_queues(interfaces, allow_cake=True)
        if layouts is None:
            return _restart_sqm({"download": ingress, "upload": egress}, interface)
        lan = interface != WAN_IFACE if interface else interfaces["download"] == _primary_lan_device()
        targets = {"download": egress if lan else ingress, "upload": ingress if lan else egress}
        commands = []
        state = _punishment_tc_state(interface)
        try:
            for direction, layout in layouts.items():
                dev, rate = shlex.quote(interfaces[direction]), targets[direction] * 1000
                root = layout["qdiscs"]["root"]
                if root["kind"] == "cake":
                    commands.append(f"tc qdisc change dev {dev} root handle {root['handle']}: cake bandwidth {rate}bit")
                    continue
                # Explicit caps remain caps; unlimited/latency-only classes follow the aggregate rate.
                for classid in ("1:1", "1:10"):
                    commands.append(f"tc class change dev {dev} classid {classid} htb rate {rate}bit ceil {rate}bit")
                leaf = layout["qdiscs"]["1:10"]
                commands.append(f"tc qdisc change dev {dev} parent 1:10 handle {leaf['handle']}: cake bandwidth {rate}bit")
                profiles = json.loads(state.get("signature", "{}" )).get("clients", {})
                for mac, binding in state.get("bindings", {}).items():
                    profile = profiles.get(mac)
                    if not profile or profile.get("download_cap" if direction == "download" else "upload_cap"):
                        continue
                    classid = "1:" + binding["minor"]
                    if classid not in layout["classes"]:
                        continue
                    commands.append(f"tc class change dev {dev} classid {classid} htb rate {rate}bit ceil {rate}bit")
                    child = layout["qdiscs"].get(classid)
                    if child and child["kind"] == "cake":
                        commands.append(f"tc qdisc change dev {dev} parent {classid} handle {child['handle']}: cake bandwidth {rate}bit")
            commands += [f"uci set sqm.@queue[0].download={ingress}",
                         f"uci set sqm.@queue[0].upload={egress}", "uci commit sqm"]
        except (ValueError, KeyError, TypeError) as error:
            return _restart_sqm({"download": ingress, "upload": egress}, interface)
        rc, out, err = ssh(_primary_sqm_command("set -e; " + "; ".join(commands), interface), timeout=30)
        if rc != 0:
            return _restart_sqm({"download": ingress, "upload": egress}, interface)
    return True, ""


def _set_sqm_conditional_baseline(rates, interface=None):
    """Preserve manual SQM edits as the normal rates to restore after the rule."""
    with _sqm_conditional_lock:
        policy = _load_sqm_conditional(interface)
        if policy["active"] or policy["baseline"]:
            if policy.get("placement") == "wan":
                policy.setdefault("baselines", {})["lan"] = dict(rates)
            else:
                policy["baseline"] = dict(rates)
            _save_sqm_conditional(policy, interface)


def _daily_sqm_queue(interface):
    if interface not in _sqm_rule_interfaces():
        return None, "Daily interface unavailable: " + interface
    queues, error = _read_sqm_queues()
    if error:
        return None, error
    matches = [queue for queue in queues if queue.get("interface") == interface]
    if len(matches) > 1:
        return None, "Expected one SQM queue for " + interface
    if interface == WAN_IFACE:
        if not matches or matches[0].get("enabled") != "1" or matches[0].get("qdisc") != "cake":
            return None, "Shared WAN Daily requires an enabled CAKE queue on " + interface
        return matches[0], ""
    if not matches or matches[0].get("enabled") != "1":
        routes, error = _qos_placements(queues)
        route = routes.get(interface, {})
        if route.get("placement") == "wan":
            return {**route["queue"], "qos_placement": "wan"}, ""
        if not matches:
            return None, "Expected one SQM queue for " + interface
        return None, "SQM is disabled on " + interface
    return matches[0], ""


def _daily_sqm_get_rates(interface):
    queue, error = _daily_sqm_queue(interface)
    if not queue:
        return None, error
    if queue.get("qos_placement") == "wan":
        return _wan_qos_state().get("daily_rates", {}).get(interface, {"download": 0, "upload": 0}), ""
    try:
        rates = {key: int(queue[key]) for key in ("download", "upload")}
        if any(not 0 <= rate <= PUNISH_CAP_MAX for rate in rates.values()):
            raise ValueError()
        return rates, ""
    except (KeyError, ValueError, TypeError):
        return None, "Invalid SQM rates on " + interface


def _daily_sqm_set_rates(interface, rates):
    _invalidate_sqm_cache()
    queue, error = _daily_sqm_queue(interface)
    if not queue:
        return False, error
    if queue.get("qos_placement") == "wan":
        return _refresh_punishment()
    if interface == WAN_IFACE:
        ok, error = _set_sqm_rates(rates, interface)
        # A managed WAN root changes in the existing shared hierarchy owner.
        return _refresh_punishment() if ok else (False, error)
    if interface == _primary_lan_device():
        return _set_sqm_rates(rates, interface)
    if queue.get("qdisc") == "cake":
        return _set_sqm_rates(rates, interface)
    settings = {"interface": interface, "enabled": "1", **rates}
    with _punishment_tc_lock:
        return _save_extra_sqm(queue, settings)


def _reconcile_sqm_conditional(force=False, interface=None):
    global _last_sqm_conditional_check
    now = time.monotonic()
    with _sqm_settings_lock, _sqm_conditional_lock:
        if not force and now - _last_sqm_conditional_check < SQM_CONDITIONAL_INTERVAL:
            return True, ""
        if interface is None:
            _last_sqm_conditional_check = now
        store = _load_sqm_conditional_store()
        raw = _load_json(SQM_CONDITIONAL_FILE, {})
        if not isinstance(raw, dict) or raw.get("version") != 2:
            _save_json(SQM_CONDITIONAL_FILE, store)
        interfaces = [interface] if interface else list(store["rules"])
        errors, messages = [], []
        for iface in interfaces:
            policy = _load_sqm_conditional(iface)
            try:
                ok, message = _reconcile_sqm_interface(iface, policy)
            except (subprocess.TimeoutExpired, OSError) as error:
                message = "SQM operation timed out" if isinstance(error, subprocess.TimeoutExpired) else str(error)
                policy["error"] = message
                _save_sqm_conditional(policy, iface)
                ok = False
            if not ok:
                errors.append(iface + ": " + message)
            elif message:
                messages.append(iface + ": " + message)
        return not errors, "; ".join(errors or messages)


def _reconcile_sqm_interface(interface, policy):
    if policy["enabled"] or policy["active"] or policy["baseline"]:
        queues, error = _read_sqm_queues()
        if error:
            policy["error"] = error
            _save_sqm_conditional(policy, interface)
            return False, error
        if not _sqm_baseline_enabled(interface, queues):
            matches = [queue for queue in queues if queue.get("interface") == interface]
            if len(matches) > 1:
                policy["error"] = "Duplicate SQM queues for " + interface
                _save_sqm_conditional(policy, interface)
                return False, policy["error"]
            # Keep a restore point for a queue disabled outside this manager.
            _turn_off_sqm_daily(interface)
            return True, "Baseline off; Daily off"
    today, today_bytes = _today_sqm_rule_usage(interface)
    threshold_bytes = int(Decimal(policy["threshold_gb"]) * (1024 ** 3))
    forced_today = policy.get("forced_date") == today and policy["enabled"]
    should_apply = forced_today or (policy["enabled"] and today_bytes >= threshold_bytes)
    target = {"download": policy["download"], "upload": policy["upload"]}
    if should_apply or policy["active"] or policy["baseline"]:
        current, error = _daily_sqm_get_rates(interface)
        if current is None:
            policy["error"] = error
            _save_sqm_conditional(policy, interface)
            return False, error
        routes, _ = _qos_placements()
        scope = ("aggregate" if interface == WAN_IFACE else
                 "wan" if routes.get(interface, {}).get("placement") == "wan" else "lan")
        if policy.get("placement") and policy["placement"] != scope:
            if policy["baseline"]:
                policy.setdefault("baselines", {})[policy["placement"]] = policy["baseline"]
            normal = {"download": 0, "upload": 0} if scope == "wan" else current
            policy["baseline"] = policy.get("baselines", {}).get(scope, normal)
            policy["active"] = False
        policy["placement"] = scope
        if should_apply:
            if not policy["active"] and not policy["baseline"]:
                # Another LAN's shared-WAN refresh may already have created
                # this rule's classes. Normal WAN LAN-parent rates are open.
                policy["baseline"] = {"download": 0, "upload": 0} if scope == "wan" else current
            desired = target
        else:
            desired = policy["baseline"]
            if set(desired) != {"download", "upload"}:
                policy["error"] = "could not restore the normal SQM rates"
                _save_sqm_conditional(policy, interface)
                return False, policy["error"]
        # Persist the restore point before router writes, including partial failures.
        _save_sqm_conditional(policy, interface)
        if current != desired or policy.get("error"):
            ok, error = _daily_sqm_set_rates(interface, desired)
            if not ok:
                policy["error"] = error
                _save_sqm_conditional(policy, interface)
                return False, error
        policy.update(active=should_apply, error="")
        if not should_apply:
            policy.update(baseline={}, forced_date="")
            policy.get("baselines", {}).pop(scope, None)
        _save_sqm_conditional(policy, interface)
        return True, "daily rule active" if should_apply else "normal SQM rates restored"
    if policy.get("error") or (policy.get("forced_date") and not forced_today):
        policy.update(error="", forced_date="")
        _save_sqm_conditional(policy, interface)
    return True, "daily rule waiting" if policy["enabled"] else "daily rule disabled"


def _clean_loss_pct(value):
    try:
        loss = Decimal(str(value))
    except (InvalidOperation, ValueError):
        raise ValueError("loss_pct")
    if not loss.is_finite() or not Decimal("0") <= loss <= PUNISH_LOSS_MAX:
        raise ValueError("loss_pct")
    text = format(loss, "f")
    return text.rstrip("0").rstrip(".") if "." in text else text


def _load_punishment_policy():
    data = _load_json(PUNISH_FILE, None)
    # Migrate the short-lived earlier latency-policy format without keeping its auto-punish behavior.
    legacy = not isinstance(data, dict)
    if legacy:
        data = _load_json(os.environ.get("LATENCY_FILE", "/data/latency.json"), {})
    if not isinstance(data, dict):
        data = {}
    try:
        delay = int(data.get("delay_ms", data.get("threshold_ms", 100)))
    except (TypeError, ValueError):
        delay = 100
    if not 1 <= delay <= PUNISH_DELAY_MAX:
        delay = 100
    caps = {}
    for key, default in (("download", 1024), ("upload", 512)):
        try:
            cap = int(data.get(key, default))
        except (TypeError, ValueError):
            cap = default
        caps[key] = cap if 1 <= cap <= PUNISH_CAP_MAX else default
    try:
        loss_pct = _clean_loss_pct(data.get("loss_pct", "0"))
    except ValueError:
        loss_pct = "0"
    stored_punished = data.get("punished", [])
    if not isinstance(stored_punished, list):
        stored_punished = []
    punished = sorted({mac.lower() for mac in stored_punished
                       if isinstance(mac, str) and MAC_RE.match(mac)})
    seen = data.get("auto_seen")
    seen = sorted({mac.lower() for mac in seen if isinstance(mac, str) and MAC_RE.fullmatch(mac)}) if isinstance(seen, list) else None
    return {"delay_ms": delay, **caps, "loss_pct": loss_pct, "punished": punished,
            "auto_punish_new": not legacy and data.get("auto_punish_new") is True,
            "auto_seen": seen}


def _save_punishment_policy(policy):
    _save_json(PUNISH_FILE, policy)


def _punishment_policy_snapshot():
    with _punishment_lock:
        return _load_punishment_policy()


def _punishment_online_clients(clients):
    """Match the Clients online window, excluding infrastructure/unmanaged IPs."""
    hidden, now, online = _infrastructure_client_ips(), int(time.time()), {}
    for client in clients:
        mac = str(client.get("mac", "")).lower()
        try:
            active = now - int(client.get("last_active") or 0) <= ONLINE_SECS
            valid_ip = ipaddress.ip_address(client.get("ip", "")).version == 4
        except (TypeError, ValueError):
            continue
        if (active and valid_ip and MAC_RE.fullmatch(mac) and client.get("ip") not in hidden
                and client.get("state") in ("Authenticated", "Preauthenticated")
                and _client_tc_interface(client)):
            online[mac] = client
    return online


def _punishment_history_macs(policy):
    """Seed first-connection memory from existing and retired client records."""
    history = _load_seen()
    known = set(history) if isinstance(history, dict) else set()
    known.update(_load_deleted())
    known.update(policy["punished"])
    # Migrate the previous connection-based tracker without treating its users
    # as first-time devices. Read-only policy GETs never persist this migration.
    old = _load_json(PUNISH_FILE, {})
    if isinstance(old, dict) and isinstance(old.get("auto_online"), list):
        known.update(mac for mac in old["auto_online"] if isinstance(mac, str))
    return {mac.lower() for mac in known if isinstance(mac, str) and MAC_RE.fullmatch(mac)}


def _auto_punish_connections(clients, blocked, trusted):
    # Resolve network identities before taking the policy lock. The existing
    # controller supplies a fresh snapshot; no new SSH read/worker is needed.
    online = _punishment_online_clients(clients)
    eligible = {mac for mac, client in online.items()
                if mac not in blocked and mac not in trusted and _client_mode(client) != "auto_trust"}
    with _punishment_lock:
        policy = _load_punishment_policy()
        previous = policy["auto_seen"]
        known = set(previous) if previous is not None else _punishment_history_macs(policy)
        added = eligible - known if policy["auto_punish_new"] and previous is not None else set()
        current = sorted(known | set(online))
        if added or previous != current:
            policy["punished"] = sorted(set(policy["punished"]) | added)
            policy["auto_seen"] = current
            _save_punishment_policy(policy)
        return policy


def _punishment_tc_state(interface=None):
    state = _load_json(PUNISH_TC_FILE, {})
    state = state if isinstance(state, dict) else {}
    if interface and interface != _primary_lan_device():
        return state.get("networks", {}).get(interface, {})
    return state


def _save_punishment_tc_state(state, interface=None):
    """Retain the native queue's legacy identities and isolate other LANs."""
    root = _punishment_tc_state()
    if interface and interface != _primary_lan_device():
        root = {**root, "version": 3, "networks": {**root.get("networks", {}), interface: state}}
    else:
        root = {**state, "version": 3, "networks": root.get("networks", {})}
    _save_json(PUNISH_TC_FILE, root)


def _managed_tc_active(state):
    return bool(state.get("active") or any(s.get("active") for s in state.get("networks", {}).values()))


def _client_tc_interface(client):
    row = _client_network(client)
    if row:
        device = row.get("device", "")
        if (row.get("eligible") and row.get("role") == "LAN" and
                row.get("mode") != "unmanaged" and _IFACE_RE.fullmatch(device)):
            return device
        return None
    if not _network_state().get("initialized") and not _client_is_extra_network(client):
        return _primary_lan_device()
    return None


def _punishment_for_ui(policy):
    tc = _punishment_tc_state()
    errors = ([f"{_primary_lan_device()}: {tc['error']}"] if tc.get("error") else [])
    errors += [f"{iface}: {s['error']}" for iface, s in tc.get("networks", {}).items() if s.get("error")]
    return {"delay_ms": policy["delay_ms"], "loss_pct": policy["loss_pct"],
            "auto_punish_new": policy.get("auto_punish_new", False),
            "download": _kbits_to_kbytes(policy["download"]),
            "upload": _kbits_to_kbytes(policy["upload"]), "punished": len(policy["punished"]),
            "rate_unit": "KB/s", "tc_active": _managed_tc_active(tc),
            "tc_error": "; ".join(errors)}


def _punishment_interfaces(interface=None):
    """Return the configured SQM egress device and its ingress IFB device."""
    if interface and interface not in _sqm_daily_interfaces() and interface != WAN_IFACE:
        return None, "LAN interface unavailable: " + interface
    command = "uci -q get sqm.@queue[0].interface"
    if interface:
        command += "; uci -q get sqm.@queue[0].enabled; uci -q get sqm.@queue[0].qdisc; "
        command += f"tc filter show dev {shlex.quote(interface)} parent ffff:"
    rc, out, err = ssh(_primary_sqm_command(command, interface))
    if rc != 0:
        return None, err or "punishment requires an active SQM queue"
    lines = out.decode(errors="replace").splitlines()
    if interface and (len(lines) < 3 or lines[:3] != [interface, "1", "cake"]):
        return None, "Client queues require enabled CAKE SQM on " + interface
    sqm_interface = (lines[0].strip() if lines else "") or TRAFFIC_IFACE
    if not _IFACE_RE.match(sqm_interface):
        return None, "SQM interface is invalid"
    redirects = set(re.findall(r"Redirect to device ([A-Za-z0-9_.-]+)\)", "\n".join(lines[3:]))) if interface else set()
    if interface and len(redirects) != 1:
        return None, "SQM ingress IFB unavailable or ambiguous on " + interface
    ifb = next(iter(redirects)) if interface else PUNISH_IFB or f"ifb4{sqm_interface}"
    if interface and not ifb.startswith("ifb"):
        return None, "SQM ingress redirect is not an IFB on " + interface
    if not _IFACE_RE.match(ifb):
        return None, "SQM ingress IFB name is invalid"
    # With SQM on the managed LAN bridge, downloads leave the bridge and
    # uploads are redirected to its IFB. With SQM on a WAN device, the
    # directions are reversed. An explicit PUNISH_IFB override is supported
    # for routers that use a non-standard IFB name.
    if (interface and interface != WAN_IFACE) or sqm_interface == _primary_lan_device():
        return {"download": sqm_interface, "upload": ifb}, ""
    return {"download": ifb, "upload": sqm_interface}, ""


def _cake_rate(options):
    match = re.search(r"\bbandwidth\s+([0-9.]+[KMG]?bit)\b", options, re.IGNORECASE)
    return match.group(1) if match else None


def _cake_with_rate(options, rate):
    return re.sub(r"\bbandwidth\s+\S+", f"bandwidth {rate}kbit", options,
                  count=1, flags=re.IGNORECASE)


def _limit_rate(value):
    """Return a configured hard rate cap in kbit/s; zero and blank are open."""
    try:
        cap = int(value)
    except (TypeError, ValueError):
        return 0
    return cap if 0 < cap <= PUNISH_CAP_MAX else 0


def _lowest_cap(*caps):
    """Combine policy caps without allowing one policy to weaken another."""
    configured = [cap for cap in caps if cap]
    return min(configured) if configured else 0


def _throttle_enabled(throttle):
    return bool(_limit_rate(throttle.get("final_rate")))


def _throttle_rate_caps(clients, limits, excluded=()):
    """Return the active temporary overuse-throttle caps by WAN direction."""
    throttle = limits["default"].get("throttle", THROTTLE_DEFAULTS)
    if not _throttle_enabled(throttle):
        return {}
    signature = json.dumps(throttle, sort_keys=True)
    usage, now, caps, present = _live_wan_usage(), int(time.time()), {}, set()
    excluded = set(excluded)
    with _throttle_lock:
        state = _load_json(THROTTLE_FILE, {})
        changed = False
        if not isinstance(state, dict) or state.get("signature") != signature:
            state = {"signature": signature, "clients": {}}
            changed = True
        entries = state.get("clients") if isinstance(state.get("clients"), dict) else {}
        for client in clients:
            mac = str(client.get("mac", "")).lower()
            if not MAC_RE.match(mac) or client.get("state") != "Authenticated":
                continue
            present.add(mac)
            if mac in excluded or mac in limits["devices"]:
                if mac in entries:
                    del entries[mac]
                    changed = True
                continue
            effective = _effective(mac, limits)
            allowable = {"download": _limit_rate(effective.get("down", "")),
                         "upload": _limit_rate(effective.get("up", ""))}
            if not any(allowable.values()):
                continue
            if mac not in entries:
                entries[mac] = {}
                changed = True
            entry = entries[mac]
            for direction, cap in allowable.items():
                if not cap:
                    continue
                if direction not in entry:
                    entry[direction] = {"above_since": 0, "active": False, "below_since": 0,
                                        "recent_rates": [], "sampled_at": 0}
                    changed = True
                direction_state = entry[direction]
                rate = usage.get(mac, {}).get(f"{direction}_rate")
                try:
                    rate = max(0.0, float(rate))
                except (TypeError, ValueError):
                    rate = 0.0
                # A CAKE-shaped client rarely reaches an exact cap.  95% is
                # close enough to mean "maxed" without missing real use.
                trigger_bytes = cap * 1000 / 8 * 0.95
                final_rate = _limit_rate(throttle["final_rate"])
                if direction_state.get("active"):
                    # Keep the final cap while it is being maxed. Use a short
                    # rolling average so a one-sample dip cannot start reset.
                    samples = direction_state.get("recent_rates")
                    if not isinstance(samples, list):
                        samples = []
                    last_sample = int(direction_state.get("sampled_at", 0) or 0)
                    if last_sample and now - last_sample > max(10, AUTOTRUST_INTERVAL * 3):
                        samples = []
                    samples = [max(0.0, float(value)) for value in samples[-(THROTTLE_AVERAGE_SAMPLES - 1):]
                               if isinstance(value, (int, float))]
                    samples.append(rate)
                    direction_state["recent_rates"] = samples
                    direction_state["sampled_at"] = now
                    average_rate = sum(samples) / len(samples)
                    final_bytes = final_rate * 1000 / 8 * 0.90
                    if len(samples) >= THROTTLE_AVERAGE_SAMPLES and average_rate < final_bytes:
                        below_since = int(direction_state.get("below_since", 0)) or now
                        direction_state["below_since"] = below_since
                        if now - below_since >= throttle["reset_secs"]:
                            direction_state.update(active=False, above_since=0, below_since=0,
                                                   recent_rates=[], sampled_at=0)
                        else:
                            caps.setdefault(mac, {})[direction] = final_rate
                        changed = True
                    else:
                        if direction_state.get("below_since"):
                            direction_state["below_since"] = 0
                        changed = True
                        caps.setdefault(mac, {})[direction] = final_rate
                    continue
                if rate > trigger_bytes:
                    above_since = int(direction_state.get("above_since", 0)) or now
                    direction_state["above_since"] = above_since
                    if now - above_since >= throttle["trigger_secs"]:
                        direction_state.update(above_since=0, active=True, below_since=0,
                                               recent_rates=[], sampled_at=0)
                        caps.setdefault(mac, {})[direction] = final_rate
                    changed = True
                elif direction_state.get("above_since"):
                    direction_state["above_since"] = 0
                    changed = True
        for mac in list(entries):
            if mac not in present:
                del entries[mac]
                changed = True
        state["clients"] = entries
        if changed:
            _save_json(THROTTLE_FILE, state)
    return caps


def _throttle_status(mac, limits, excluded=()):
    """Return currently active overuse-throttle directions for the client list."""
    if (mac in set(excluded) or mac in limits["devices"] or
            not _throttle_enabled(limits["default"].get("throttle", {}))):
        return {"download": False, "upload": False, "until": 0}
    signature = json.dumps(limits["default"]["throttle"], sort_keys=True)
    with _throttle_lock:
        state = _load_json(THROTTLE_FILE, {})
    if not isinstance(state, dict) or state.get("signature") != signature:
        return {"download": False, "upload": False, "until": 0}
    entry = (state.get("clients") or {}).get(mac, {})
    if not isinstance(entry, dict):
        return {"download": False, "upload": False, "until": 0}
    now = int(time.time())
    active = {direction: bool((entry.get(direction) or {}).get("active"))
              for direction in ("download", "upload")}
    return {"download": active["download"], "upload": active["upload"], "until": 0}


def _managed_tc_clients(clients, policy, limits, blocked, trusted, throttle_caps=None):
    """Return clients needing a hard Limits cap, latency, or punishment."""
    desired = {}
    punished = set(policy["punished"])
    throttle_caps = throttle_caps or {}
    for client in clients:
        mac = str(client.get("mac", "")).lower()
        ip = str(client.get("ip", ""))
        try:
            valid_ip = ipaddress.ip_address(ip).version == 4
        except ValueError:
            valid_ip = False
        # Include a client while it is at the captive-portal stage too.  This
        # installs its normal CAKE class before an auto-auth session begins.
        if (mac in blocked or mac in trusted or not MAC_RE.fullmatch(mac) or not valid_ip or not _client_tc_interface(client) or
                client.get("state") not in ("Authenticated", "Preauthenticated")):
            continue
        effective = _effective(mac, limits)
        latency = _limit_latency(effective.get(LATENCY_KEY, ""))
        limit_download = _limit_rate(throttle_caps.get(mac, {}).get(
            "download", effective.get("down", "")))
        limit_upload = _limit_rate(throttle_caps.get(mac, {}).get(
            "upload", effective.get("up", "")))
        manual = mac in punished
        download_cap = _lowest_cap(limit_download, policy["download"] if manual else 0)
        upload_cap = _lowest_cap(limit_upload, policy["upload"] if manual else 0)
        if manual or latency or download_cap or upload_cap:
            desired[mac] = {
                "ip": ip,
                "interface": _client_tc_interface(client),
                "download_cap": download_cap,
                "upload_cap": upload_cap,
                "delay_ms": latency + (policy["delay_ms"] if manual else 0),
                "loss_pct": policy["loss_pct"] if manual else "0",
                "session_active": client.get("state") == "Authenticated",
            }
    return desired


def _rate_bits(value):
    match = re.fullmatch(r"([0-9.]+)([KMG]?)bit", value, re.IGNORECASE)
    if not match:
        raise ValueError("unsupported queue bandwidth")
    return int(Decimal(match[1]) * {"": 1, "k": 1000, "m": 1000000, "g": 1000000000}[match[2].lower()])


def _parse_tc_layout(text):
    """Parse only the manager's known HTB/CAKE layout, including filter identity."""
    layout = {"qdiscs": {}, "classes": {}, "filters": []}
    current_qdisc = current_filter = None
    for line in text.splitlines():
        qdisc = re.match(r"^qdisc (\w+) ([0-9a-f]+): (.+)$", line)
        if qdisc:
            kind, handle, options = qdisc.groups()
            parent = re.search(r"\bparent (1:[0-9a-f]+)\b", options)
            key = parent[1] if parent else "root" if options.startswith("root") else None
            current_qdisc = {"kind": kind, "handle": handle, "options": options, "backlog": None}
            if key:
                layout["qdiscs"][key] = current_qdisc
            continue
        backlog = re.search(r"\bbacklog \S+ (\d+)p\b", line)
        if backlog and current_qdisc is not None and current_qdisc["backlog"] is None:
            current_qdisc["backlog"] = int(backlog[1])
        cls = re.match(r"^class htb (1:[0-9a-f]+) .*\brate (\S+) ceil (\S+)", line)
        if cls:
            layout["classes"][cls[1]] = {"rate": _rate_bits(cls[2]), "ceil": _rate_bits(cls[3])}
        if line.startswith("filter "):
            current_filter = None
            filt = re.search(r"\bpref (\d+) u32 .*\bfh ([0-9a-f:]+) .*\bflowid (1:[0-9a-f]+)\b", line)
            if filt:
                current_filter = {"priority": int(filt[1]), "handle": filt[2], "classid": filt[3]}
                layout["filters"].append(current_filter)
        match = re.match(r"\s+match ([0-9a-f]{8})/ffffffff at (12|16)$", line)
        if match and current_filter is not None:
            current_filter.update(ip=str(ipaddress.IPv4Address(int(match[1], 16))),
                                  direction="src" if match[2] == "12" else "dst")
    return layout


def _inspect_managed_queues(interfaces, allow_cake=False):
    commands = []
    for direction, interface in interfaces.items():
        if not _IFACE_RE.fullmatch(interface):
            return None, "invalid SQM interface"
        dev = shlex.quote(interface)
        commands += [f"echo @@TC_{direction}", f"tc -s qdisc show dev {dev}",
                     f"tc class show dev {dev}", f"tc filter show dev {dev} parent 1:"]
    rc, raw, err = ssh("set -e; " + "; ".join(commands))
    if rc != 0:
        return None, err.strip() or "could not inspect SQM queues"
    sections = re.split(r"^@@TC_(download|upload)\s*$", raw.decode(errors="replace"), flags=re.MULTILINE)
    try:
        layouts = {sections[i]: _parse_tc_layout(sections[i + 1]) for i in range(1, len(sections), 2)}
        if set(layouts) != {"download", "upload"}:
            raise ValueError("missing queue inspection")
        for layout in layouts.values():
            root, default = layout["qdiscs"].get("root", {}), layout["qdiscs"].get("1:10", {})
            if allow_cake and root.get("kind") == "cake":
                continue
            if (root.get("kind") != "htb" or root.get("handle") != "1" or
                    not re.search(r"\bdefault (?:0x)?10\b", root.get("options", "")) or
                    default.get("kind") != "cake" or
                    not {"1:1", "1:10"}.issubset(layout["classes"])):
                raise ValueError("existing SQM layout needs a root change; left unchanged")
        return layouts, ""
    except ValueError as error:
        return None, str(error)


def _adopt_tc_bindings(state, layouts, desired):
    """Keep existing handles, using saved legacy identities and verified filters."""
    bindings = copy.deepcopy(state.get("bindings", {}))
    for mac, binding in bindings.items():
        if (not MAC_RE.fullmatch(mac) or not re.fullmatch(r"[0-9a-f]{1,4}", binding.get("minor", "")) or
                int(binding["minor"], 16) <= 0x10 or
                not isinstance(binding.get("priority"), int) or not 100 <= binding["priority"] < 32767):
            raise ValueError("invalid saved queue identity; queues left unchanged")
    try:
        previous = json.loads(state.get("signature", "{}" )).get("clients", {})
    except (ValueError, AttributeError):
        previous = {}
    candidates = {**desired, **previous}
    for mac, profile in candidates.items():
        if mac in bindings:
            continue
        pairs = []
        for direction, match_direction in (("download", "dst"), ("upload", "src")):
            found = [f for f in layouts[direction]["filters"]
                     if f.get("ip") == profile["ip"] and f.get("direction") == match_direction]
            if len(found) != 1:
                break
            pairs.append(found[0])
        if len(pairs) == 2 and pairs[0]["classid"] == pairs[1]["classid"]:
            bindings[mac] = {"minor": pairs[0]["classid"].split(":")[1],
                             "priority": pairs[0]["priority"]}
    known = {"1:" + b["minor"] for b in bindings.values()}
    if len(known) != len(bindings):
        raise ValueError("ambiguous managed class identities; queues left unchanged")
    for layout in layouts.values():
        if set(layout["classes"]) - {"1:1", "1:10"} - known:
            raise ValueError("unidentified client classes; queues left unchanged")
        if any(f["classid"] not in known or "ip" not in f for f in layout["filters"]):
            raise ValueError("unidentified filters; queues left unchanged")
    # Reserve all existing IDs forever for their MAC, including retired classes.
    used_ids = {int(b["minor"], 16) for b in bindings.values()}
    used_priorities = {b["priority"] for b in bindings.values()}
    for mac in sorted(desired):
        if mac not in bindings:
            minor = next((n for n in range(0x100, 0xfffe) if n not in used_ids), None)
            priority = next((n for n in range(100, 32767) if n not in used_priorities), None)
            if minor is None or priority is None:
                raise ValueError("managed queue identities exhausted")
            bindings[mac] = {"minor": format(minor, "x"), "priority": priority}
            used_ids.add(minor)
            used_priorities.add(priority)
    return bindings


def _tc_client_update(interface, layout, binding, profile, direction):
    """Apply one client leaf, replacing its queue type immediately if needed."""
    dev, minor = shlex.quote(interface), binding["minor"]
    classid, priority = "1:" + minor, binding["priority"]
    leaf = layout["qdiscs"].get(classid)
    default = layout["qdiscs"]["1:10"]
    options = re.sub(r"^parent 1:10(?: refcnt \d+)? ", "", default["options"])
    if not re.fullmatch(r"[A-Za-z0-9._:/ -]+", options) or not _cake_rate(options):
        raise ValueError("unsupported CAKE parameters; queue left unchanged")
    total = layout["classes"]["1:1"]["rate"]
    cap = profile["download_cap" if direction == "dst" else "upload_cap"]
    rate = cap * 1000 if cap else total
    delay = profile["delay_ms"] if direction == "dst" else 0
    loss = profile["loss_pct"] if direction == "dst" else "0"
    kind = "netem" if delay or Decimal(loss) else "cake"
    filters = [f for f in layout["filters"] if f["classid"] == classid]
    if len(filters) > 1:
        raise ValueError("duplicate client filters; queue left unchanged")
    commands = []
    if leaf and leaf["kind"] != kind:
        commands.append(f"tc qdisc delete dev {dev} parent {classid} handle {leaf['handle']}:")
        leaf = None
    cls = layout["classes"].get(classid)
    if cls is None:
        commands.append(f"tc class add dev {dev} parent 1:1 classid {classid} htb rate {rate}bit ceil {rate}bit")
    elif cls != {"rate": rate, "ceil": rate}:
        commands.append(f"tc class change dev {dev} parent 1:1 classid {classid} htb rate {rate}bit ceil {rate}bit")
    if kind == "cake":
        parameters = _cake_with_rate(options, rate // 1000)
        if leaf is None:
            commands.append(f"tc qdisc add dev {dev} parent {classid} handle {minor}: cake {parameters}")
        elif _rate_bits(_cake_rate(leaf["options"]) or "0bit") != rate:
            commands.append(f"tc qdisc change dev {dev} parent {classid} handle {leaf['handle']}: cake bandwidth {rate}bit")
    else:
        parameters = f"delay {delay}ms loss {loss}%"
        if leaf is None:
            commands.append(f"tc qdisc add dev {dev} parent {classid} handle {minor}: netem {parameters}")
        else:
            old_delay = re.search(r"\bdelay ([0-9.]+)(ms|us|s)\b", leaf["options"])
            old_loss = re.search(r"\bloss ([0-9.]+)%", leaf["options"])
            delay_ms = (Decimal(old_delay[1]) * {"ms": 1, "us": Decimal(".001"), "s": 1000}[old_delay[2]]
                        if old_delay else 0)
            if delay_ms != delay or Decimal(old_loss[1] if old_loss else "0") != Decimal(loss):
                commands.append(f"tc qdisc change dev {dev} parent {classid} handle {leaf['handle']}: netem {parameters}")
    if filters:
        filt = filters[0]
        if filt["priority"] != priority or filt.get("direction") != direction:
            raise ValueError("client filter identity changed; queue left unchanged")
        if filt.get("ip") != profile["ip"]:
            commands.append(f"tc filter change dev {dev} parent 1: protocol ip prio {priority} "
                            f"handle {filt['handle']} u32 match ip {direction} {profile['ip']}/32 flowid {classid}")
    else:
        commands.append(f"tc filter add dev {dev} parent 1: protocol ip prio {priority} "
                        f"u32 match ip {direction} {profile['ip']}/32 flowid {classid}")
    return commands, ""


def _recover_managed_sqm(interface, error):
    """Recover one configured CAKE queue, including a missing ingress IFB."""
    if interface and interface not in _sqm_daily_interfaces():
        return False, "LAN interface unavailable: " + interface
    command = "; ".join(f"uci -q get sqm.@queue[0].{key}"
                        for key in ("enabled", "qdisc", "download", "upload"))
    rc, raw, err = ssh(_primary_sqm_command(command, interface))
    values = raw.decode(errors="replace").splitlines()
    if (rc != 0 or len(values) != 4 or values[:2] != ["1", "cake"] or
            not all(_limit_rate(value) for value in values[2:])):
        return False, err.strip() or "Client queues require enabled CAKE SQM with positive rates in both directions"
    if time.time() - _punishment_tc_state(interface).get("recovery_at", 0) < 60:
        return False, error or "SQM recovery will retry shortly"
    return _restart_sqm(interface=interface)


def _prepare_managed_queues(interfaces, interface=None):
    """Convert SQM's CAKE roots to the client hierarchy after apply/reboot."""
    layouts, error = _inspect_managed_queues(interfaces, allow_cake=True)
    if layouts is None:
        ok, error = _recover_managed_sqm(interface, error)
        if not ok:
            return None, error
        layouts, error = _inspect_managed_queues(interfaces, allow_cake=True)
        if layouts is None:
            return None, error
    commands = []
    try:
        for direction, layout in layouts.items():
            root = layout["qdiscs"]["root"]
            if root["kind"] != "cake":
                continue
            options = re.sub(r"^root(?: refcnt \d+)? ", "", root["options"])
            if not re.fullmatch(r"[A-Za-z0-9._:/ -]+", options):
                raise ValueError("unsupported CAKE parameters")
            bandwidth = _cake_rate(options)
            if not bandwidth:
                raise ValueError("client queues require positive SQM rates in both directions")
            rate = _rate_bits(bandwidth)
            if rate <= 0:
                raise ValueError("client queues require positive SQM rates in both directions")
            dev = shlex.quote(interfaces[direction])
            commands += [f"tc qdisc replace dev {dev} root handle 1: htb default 10",
                         f"tc class add dev {dev} parent 1: classid 1:1 htb rate {rate}bit ceil {rate}bit",
                         f"tc class add dev {dev} parent 1:1 classid 1:10 htb rate {rate}bit ceil {rate}bit",
                         f"tc qdisc add dev {dev} parent 1:10 handle 10: cake {options}"]
    except (ValueError, KeyError, TypeError) as exc:
        return None, str(exc)
    if commands:
        rc, out, err = ssh("set -e; " + "; ".join(commands), timeout=30)
        if rc != 0:
            return None, (out.decode(errors="replace") + err).strip() or "client hierarchy update failed"
        return _inspect_managed_queues(interfaces)
    return layouts, ""


def _apply_punishment_qdisc(policy, desired, interface=None):
    """Reconcile leaves and rebuild SQM roots when their layout needs it."""
    state = _punishment_tc_state(interface)
    interfaces, error = _punishment_interfaces(interface) if interface else _punishment_interfaces()
    layouts = None
    if not interfaces and desired:
        ok, error = _recover_managed_sqm(interface, error)
        if ok:
            interfaces, error = _punishment_interfaces(interface) if interface else _punishment_interfaces()
    if interfaces:
        layouts, error = _prepare_managed_queues(interfaces, interface)
    state = _punishment_tc_state(interface)
    if layouts is None:
        _save_punishment_tc_state({**state, "error": error,
                                  "pending": {mac: error for mac in desired}}, interface)
        return False, error
    try:
        bindings = _adopt_tc_bindings(state, layouts, desired)
        commands, pending = [], {}
        for mac, binding in bindings.items():
            classid = "1:" + binding["minor"]
            if mac in desired:
                per_client, draining = [], []
                for direction, match in (("download", "dst"), ("upload", "src")):
                    updates, message = _tc_client_update(interfaces[direction], layouts[direction],
                                                        binding, desired[mac], match)
                    if message:
                        pending[mac] = message
                        draining += updates
                    per_client += updates
                # A deferred type switch must not leave half of a client's policy applied.
                if mac not in pending:
                    commands += per_client
                else:
                    commands += draining
            else:
                for direction, layout in layouts.items():
                    dev = shlex.quote(interfaces[direction])
                    filters = [f for f in layout["filters"] if f["classid"] == classid]
                    for filt in filters:
                        commands.append(f"tc filter delete dev {dev} parent 1: protocol ip "
                                        f"prio {filt['priority']} handle {filt['handle']} u32")
                    leaf = layout["qdiscs"].get(classid)
                    # Drain during a subsequent inspection, after detaching filters.
                    if not filters and leaf and leaf["backlog"] == 0:
                        commands += [f"tc qdisc delete dev {dev} parent {classid} handle {leaf['handle']}:",
                                     f"tc class delete dev {dev} classid {classid}"]
                    elif not filters and not leaf and classid in layout["classes"]:
                        commands.append(f"tc class delete dev {dev} classid {classid}")
        next_state = {**state, "active": True, "version": 3, "interfaces": interfaces,
                      "bindings": bindings, "pending": pending, "error": ""}
        # Persist ownership before executing so partial additions remain recoverable.
        if next_state != state:
            _save_punishment_tc_state(next_state, interface)
        if commands:
            rc, out, err = ssh("set -e; " + "; ".join(commands), timeout=30)
            if rc != 0:
                error = (out.decode(errors="replace") + err).strip() or "queue update incomplete"
                _save_punishment_tc_state({**next_state, "error": error}, interface)
                return False, error
        verified = layouts
        if commands:
            verified, error = _inspect_managed_queues(interfaces)
            if verified is None:
                raise ValueError(error or "Client queue verification failed")
        for mac, profile in desired.items():
            for direction, match in (("download", "dst"), ("upload", "src")):
                updates, message = _tc_client_update(interfaces[direction], verified[direction], bindings[mac], profile, match)
                if updates or message:
                    pending[mac] = message or "Client queue verification pending"
        try:
            previous = json.loads(state.get("signature", "{}" )).get("clients", {})
        except (ValueError, AttributeError):
            previous = {}
        applied_clients = {mac: previous.get(mac, {}) if mac in pending else profile
                           for mac, profile in desired.items()}
        next_state.update(clients=sorted(desired), verified_at=time.time() if not pending else 0, signature=json.dumps(
            {"clients": applied_clients, "interfaces": interfaces}, sort_keys=True))
        if next_state != state:
            _save_punishment_tc_state(next_state, interface)
        return True, ("saved; some queue changes remain pending" if pending else "managed queues active")
    except (ValueError, KeyError, TypeError) as exc:
        error = str(exc)
        _save_punishment_tc_state({**state, "error": error,
                                  "pending": {mac: error for mac in desired}}, interface)
        return False, error


def _qos_placements(queues=None):
    if queues is None:
        queues, error = _read_sqm_queues()
        if error:
            return {}, error
    try:
        return wan_shaping.placements(queues, _sqm_daily_interfaces(), WAN_IFACE), ""
    except (TypeError, ValueError):
        return {}, "Invalid saved SQM rates"


def _wan_qos_state():
    state = _load_json(WAN_QOS_FILE, {})
    return state if isinstance(state, dict) else {}


def _wan_daily_targets(networks):
    targets = {}
    for iface in networks:
        policy = _load_sqm_conditional(iface)
        day, used = _today_interface_wan_total(iface)
        reached = used >= int(Decimal(policy["threshold_gb"]) * 1024 ** 3)
        active = policy["enabled"] and (policy.get("forced_date") == day or reached)
        targets[iface] = {key: policy[key] if active else 0 for key in ("download", "upload")}
    return targets


def _wan_qos_clients(clients, networks):
    result, ips = {}, set()
    for client in clients:
        mac = str(client.get("mac", "")).lower()
        lan = _client_tc_interface(client)
        if lan not in networks or not MAC_RE.fullmatch(mac):
            continue
        try:
            ip = str(ipaddress.IPv4Address(client.get("ip", "")))
        except (ValueError, ipaddress.AddressValueError):
            continue
        if (lan, ip) in ips:
            raise ValueError("Ambiguous client IPv4 identity on " + lan)
        ips.add((lan, ip))
        result[mac] = {"interface": lan, "ip": ip}
    return result


def _wan_qos_cleanup():
    state = _wan_qos_state()
    if not state.get("active") and not state.get("installed"):
        return True, ""
    dev = state.get("wan", WAN_IFACE)
    if not _IFACE_RE.fullmatch(dev):
        return False, "Invalid saved WAN device"
    # Inspect ownership before deleting anything; never suppress a failed delete.
    read = (f"tc filter show dev {shlex.quote(dev)} parent ffff:; echo @@NFT; "
            f"nft list table inet {wan_shaping.TABLE} 2>/dev/null || :")
    try:
        rc, out, error = ssh(read)
        if rc:
            raise ValueError(error or "WAN cleanup inspection failed")
        ingress, nft = out.decode(errors="replace").split("@@NFT\n", 1)
        owned = wan_shaping.ingress_handle(ingress)
        if nft.strip() and not re.search(r'comment "manager-[a-f0-9]+"', nft):
            raise ValueError("WAN classification table ownership conflict")
        commands = []
        if nft.strip():
            commands.append(f"nft delete table inet {wan_shaping.TABLE}")
        if owned:
            # Ownership validation allows no other nodes at this priority.
            # Remove its hash table too, so reinstallation can allocate cleanly.
            commands.append(f"tc filter delete dev {shlex.quote(dev)} parent ffff: protocol ip pref 1")
        if commands:
            rc, out, error = ssh("set -e; " + "; ".join(commands))
            if rc:
                raise ValueError(error or "WAN classification cleanup failed")
        rc, out, error = ssh(read)
        remaining_ingress, remaining_nft = out.decode(errors="replace").split("@@NFT\n", 1)
        if rc or remaining_nft.strip() or wan_shaping.ingress_status(remaining_ingress):
            raise ValueError(error or "WAN cleanup verification pending")
    except (ValueError, subprocess.TimeoutExpired, OSError) as exc:
        error = str(exc)
        _save_json(WAN_QOS_FILE, {**state, "active": False, "verified_at": 0, "error": error})
        return False, error
    # An enabled WAN queue must return to ordinary SQM when all policies move
    # to LAN. Disabled queues have already been removed by the scoped Apply.
    queues, error = _read_sqm_queues()
    if error:
        return False, error
    if any(q.get("interface") == dev and q.get("enabled") == "1" for q in queues):
        ok, error = _restart_sqm(interface=dev)
        if not ok:
            return False, error
    _save_json(WAN_QOS_FILE, {**state, "active": False, "installed": False,
                            "verified_at": 0, "error": "", "clients": {}})
    return True, "WAN policies moved to LAN"


def _apply_wan_qos(queue, networks, clients, desired):
    """One owner for all client/LAN classes on the selected WAN queue."""
    state = _wan_qos_state()
    try:
        wan = queue["interface"]
        if wan != WAN_IFACE or not _IFACE_RE.fullmatch(wan):
            raise ValueError("WAN shaping requires the configured WAN accounting device")
        bound = _wan_qos_clients(clients, networks)
        state = wan_shaping.identities(state, networks, bound)
        state.update(wan=wan, clients=bound, networks=sorted(networks), installed=True,
                     active=False, verified_at=0)
        _save_json(WAN_QOS_FILE, state)
        rc, output, error = ssh(
            f"tc filter show dev {shlex.quote(wan)} parent ffff:; "
            "echo @@OFFLOAD; uci -q get firewall.@defaults[0].flow_offloading || :; "
            "uci -q get firewall.@defaults[0].flow_offloading_hw || :; "
            "echo @@CTINFO; test -d /sys/module/act_ctinfo && echo loaded; "
            f"echo @@NFT; nft list table inet {wan_shaping.TABLE} 2>/dev/null || :")
        if rc:
            raise ValueError(error or "WAN classifier inspection failed")
        text = output.decode(errors="replace")
        ingress, rest = text.split("@@OFFLOAD\n", 1)
        offload, rest = rest.split("@@CTINFO\n", 1)
        dependency, nft = rest.split("@@NFT\n", 1)
        if "1" in offload.splitlines():
            raise ValueError("WAN policy shaping requires software/hardware flow offloading disabled in OpenWrt")
        if nft.strip() and not re.search(r'comment "manager-[a-f0-9]+"', nft):
            raise ValueError("WAN classification table ownership conflict")
        redirects = set(re.findall(r"Redirect to device ([A-Za-z0-9_.-]+)\)", ingress))
        if len(redirects) != 1 or not next(iter(redirects)).startswith("ifb"):
            # SQM apply/reboot can temporarily lose the ingress redirect.
            if time.time() - state.get("recovery_at", 0) < 60:
                raise ValueError("WAN ingress IFB unavailable; recovery will retry")
            state["recovery_at"] = time.time()
            _save_json(WAN_QOS_FILE, state)
            ok, error = _restart_sqm(interface=wan)
            if not ok:
                raise ValueError(error)
            raise ValueError("WAN SQM recovered; client classes will apply on the next control pass")
        ifb = next(iter(redirects))
        if not _IFACE_RE.fullmatch(ifb):
            raise ValueError("Invalid WAN ingress IFB")
        if "loaded" not in dependency:
            if time.time() - state.get("dependency_attempt_at", 0) < 60:
                raise ValueError("WAN conntrack marking unavailable; dependency setup will retry")
            state["dependency_attempt_at"] = time.time()
            _save_json(WAN_QOS_FILE, state)
            rc, out, err = ssh("modprobe act_ctinfo 2>/dev/null || { "
                "apk add kmod-sched-ctinfo > /tmp/opennds-qos-install.log 2>&1 && modprobe act_ctinfo; }",
                timeout=60)
            if rc:
                raise ValueError("WAN classification requires kmod-sched-ctinfo: " + (err.strip() or "automatic installation failed"))
        owned_ingress = wan_shaping.ingress_status(ingress)
        interfaces = {"download": ifb, "upload": wan}
        totals = {key: int(queue[key]) * 1000 for key in ("download", "upload")}
        daily_rates = _wan_daily_targets(networks)
        specs = wan_shaping.nodes(networks, bound, desired, daily_rates, state, totals)
        layouts = wan_shaping.inspect(ssh, interfaces)
        try:
            commands = wan_shaping.plan(interfaces, layouts, specs)
        except ValueError as exc:
            if "ownership conflict" in str(exc):
                raise
            if time.time() - state.get("recovery_at", 0) < 60:
                raise
            state["recovery_at"] = time.time()
            _save_json(WAN_QOS_FILE, state)
            ok, error = _restart_sqm(interface=wan)
            if not ok:
                raise ValueError(error)
            layouts = wan_shaping.inspect(ssh, interfaces)
            commands = wan_shaping.plan(interfaces, layouts, specs)
        if commands:
            rc, output, error = ssh("set -e; " + "; ".join(commands), timeout=30)
            if rc:
                raise ValueError((output.decode(errors="replace") + error).strip() or "WAN classes incomplete")
        rules, digest = wan_shaping.nft_rules(wan, networks, bound, state)
        if "manager-" + digest not in nft:
            rc, output, error = ssh("nft -f -", data=rules.encode())
            if rc:
                raise ValueError((output.decode(errors="replace") + error).strip() or "WAN connection marks incomplete")
        if not owned_ingress:
            rc, output, error = ssh(wan_shaping.ingress_command(wan))
            if rc:
                raise ValueError((output.decode(errors="replace") + error).strip() or "WAN ingress mark restore failed")
        # A successful command exit alone is not an Active status.
        verified = wan_shaping.inspect(ssh, interfaces) if commands else layouts
        if wan_shaping.plan(interfaces, verified, specs):
            raise ValueError("WAN queue verification pending")
        rc, output, error = ssh(f"tc filter show dev {shlex.quote(wan)} parent ffff:; "
                               f"echo @@NFT; nft list table inet {wan_shaping.TABLE}")
        if rc:
            raise ValueError(error or "WAN classification verification failed")
        check_ingress, check_nft = output.decode(errors="replace").split("@@NFT\n", 1)
        if not wan_shaping.ingress_status(check_ingress) or "manager-" + digest not in check_nft:
            raise ValueError("WAN connection-mark verification pending")
        state.update(active=True, error="", verified_at=time.time(), interfaces=interfaces, daily_rates=daily_rates,
                     managed_clients=sorted(desired), signature=digest)
        _save_json(WAN_QOS_FILE, state)
        return True, "WAN client and LAN policies verified"
    except (ValueError, KeyError, TypeError, subprocess.TimeoutExpired, OSError) as exc:
        error = "WAN queue operation timed out" if isinstance(exc, subprocess.TimeoutExpired) else str(exc)
        _save_json(WAN_QOS_FILE, {**state, "active": False, "verified_at": 0, "error": error})
        return False, error


def _publish_qos_status(queues, routes, desired, error=""):
    now, rows = time.time(), []
    wan = _wan_qos_state()
    root = _punishment_tc_state()
    for iface, name in _sqm_daily_interfaces().items():
        route = routes.get(iface, {})
        scope = route.get("placement", "unavailable")
        saved = wan if scope == "wan" else root if iface == _primary_lan_device() else root.get("networks", {}).get(iface, {})
        count = sum(p.get("interface") == iface for p in desired.values())
        message = error or route.get("error") or saved.get("error", "")
        verified = saved.get("verified_at", 0)
        pending = saved.get("pending", {})
        daily = _load_sqm_conditional(iface)
        daily_active = (any(wan.get("daily_rates", {}).get(iface, {}).values())
                        if scope == "wan" else daily.get("active", False))
        message = message or daily.get("error", "")
        if scope == "lan" and not count and not message:
            try:
                interfaces, reason = _punishment_interfaces(iface)
                layouts, reason = _inspect_managed_queues(interfaces, allow_cake=True) if interfaces else (None, reason)
                if layouts is not None:
                    verified = now
                    pending = {}
                else:
                    message = reason
            except (subprocess.TimeoutExpired, OSError, ValueError) as exc:
                message = str(exc)
        off = route.get("error") == "No enabled LAN or WAN SQM queue" and not error
        if off:
            message = "SQM off" + ("; device caps, delay and Punish are inactive" if count else "")
        state = "off" if off else "error" if message else "pending" if pending or not verified or now - verified > 15 else "active" if count or daily_active else "ready"
        rows.append({"interface": iface, "network": name, "placement": scope,
                     "queue_interface": route.get("queue_interface", ""), "state": state,
                     "message": message or ("Queue verification pending" if state == "pending" else ""),
                     "clients": count, "daily_active": bool(daily_active), "verified_at": verified,
                     "traffic_scope": "IPv4 WAN traffic" if scope == "wan" else "LAN interface traffic"})
    queue_rows = []
    names = _load_sqm_names()
    networks = {row.get("device"): row.get("name", "")
                for row in _network_state().get("networks", [])}
    for queue in queues:
        iface = queue.get("interface", "")
        enabled = queue.get("enabled") == "1"
        daily = _load_sqm_conditional(iface)
        related = next((row for row in rows if row["interface"] == iface and row["placement"] == "lan"), None)
        state, message, verified = "off", "", 0
        if enabled:
            if iface == WAN_IFACE and (wan.get("installed") or any(row["placement"] == "wan" for row in rows)):
                verified = wan.get("verified_at", 0)
                message = error or wan.get("error", "") or daily.get("error", "")
                state = ("error" if message else "pending" if not wan.get("active") or not verified or now-verified > 15 else "active")
            elif related:
                state, message, verified = related["state"], related["message"], related["verified_at"]
            elif iface == WAN_IFACE:
                try:
                    interfaces, message = _punishment_interfaces(iface)
                    layouts, message = _inspect_managed_queues(interfaces, allow_cake=True) if interfaces else (None, message)
                    state, verified = ("active", now) if layouts is not None else ("error", 0)
                except (subprocess.TimeoutExpired, OSError, ValueError) as exc:
                    state, message = "error", str(exc)
            else:
                state, message = "unknown", "Queue not verified"
        queue_rows.append({**_sqm_for_ui(queue), "enabled": enabled,
                           "name": names.get(iface) or networks.get(iface) or iface,
                           "state": state, "message": message, "verified_at": verified,
                           "daily_active": enabled and bool(daily.get("active"))})
    with _qos_status_lock:
        global _qos_status_data
        _qos_status_data = {"checked_at": now, "networks": rows,
                            "queues": queue_rows, "error": error}


@app.route("/api/qos/status")
@requires_auth
def qos_status():
    # Settings polling reads only this cached runtime view; no SSH or drafts.
    with _qos_status_lock:
        data = copy.deepcopy(_qos_status_data)
    age = time.time() - data["checked_at"] if data["checked_at"] else None
    stale = age is None or age > max(15, AUTOTRUST_INTERVAL * 4)
    if stale:
        for row in data["networks"] + data.get("queues", []):
            row.update(state="unknown", message="Runtime check is stale")
    return jsonify(ok=True, stale=stale, age=age, **data)


def _reconcile_punishment(policy, limits, clients, blocked, trusted, interface=None):
    with _punishment_tc_lock:
        state = _punishment_tc_state()
        clients = list(clients)
        excluded = set(policy["punished"]) | set(trusted) | set(blocked)
        desired = _managed_tc_clients(clients, policy, limits, blocked, trusted,
                                      _throttle_rate_caps(clients, limits, excluded))
        groups = {}
        for mac, profile in desired.items():
            groups.setdefault(profile["interface"], {})[mac] = profile
        primary = _primary_lan_device()
        queues, topology_error = _read_sqm_queues()
        routes, route_error = _qos_placements(queues)
        topology_error = topology_error or route_error
        wan_lans = {iface for iface, route in routes.items() if route.get("placement") == "wan"}
        if topology_error:
            _publish_qos_status(queues, routes, desired, topology_error)
            return False, topology_error
        targets = set(groups) | {iface for iface, saved in state.get("networks", {}).items()
                                 if saved.get("active")}
        if state.get("active"):
            targets.add(primary)
        if interface is not None and interface != WAN_IFACE and interface not in wan_lans:
            targets &= {interface}
        errors, messages, cleanup_error = [], [], ""
        if wan_lans:
            rows = {r["device"]: r for r in _network_state().get("networks", [])
                    if r.get("device") in wan_lans}
            if wan_lans - set(rows):
                message = "WAN shaping requires discovered LAN subnets: " + ", ".join(sorted(wan_lans-set(rows)))
                errors.append(message)
                _save_json(WAN_QOS_FILE, {**_wan_qos_state(), "active": False,
                                        "verified_at": 0, "error": message})
            else:
                wan_desired = {mac: profile for mac, profile in desired.items() if profile["interface"] in wan_lans}
                ok, message = _apply_wan_qos(routes[next(iter(wan_lans))]["queue"], rows, clients, wan_desired)
                (messages if ok else errors).append(message)
        elif _wan_qos_state().get("installed"):
            ok, message = _wan_qos_cleanup()
            (messages if ok else errors).append(message)
            if not ok:
                cleanup_error = message
                _save_json(WAN_QOS_FILE, {**_wan_qos_state(), "active": False,
                                        "verified_at": 0, "error": message})
        for iface in sorted(targets, key=lambda name: (name != primary, name)):
            if iface in wan_lans:
                # A disabled/removed LAN queue no longer owns these clients.
                saved = _punishment_tc_state(iface)
                if saved.get("active") or saved.get("error"):
                    _save_punishment_tc_state({**saved, "active": False, "error": "", "pending": {},
                                              "verified_at": 0}, iface)
                continue
            if routes.get(iface, {}).get("error") == "No enabled LAN or WAN SQM queue":
                saved = _punishment_tc_state(iface)
                pending = {mac: "SQM off; enable LAN or WAN CAKE for device caps, delay and Punish."
                           for mac in groups.get(iface, {})}
                next_state = {**saved, "active": False, "error": "", "pending": pending, "verified_at": 0}
                if next_state != saved:
                    _save_punishment_tc_state(next_state, iface)
                continue
            try:
                if iface == primary:
                    ok, message = _apply_punishment_qdisc(policy, groups.get(iface, {}))
                else:
                    ok, message = _apply_punishment_qdisc(policy, groups.get(iface, {}), iface)
            except (subprocess.TimeoutExpired, OSError) as exc:
                message = "queue operation timed out" if isinstance(exc, subprocess.TimeoutExpired) else str(exc)
                saved = _punishment_tc_state(iface)
                _save_punishment_tc_state({**saved, "error": message,
                    "pending": {mac: message for mac in groups.get(iface, {})}}, iface)
                ok = False
            (messages if ok else errors).append(iface + ": " + message)
        _publish_qos_status(queues, routes, desired, cleanup_error)
        return not errors, "; ".join(errors or messages) or "no active managed clients"


def _refresh_punishment(interface=None):
    """Refresh the shared hard-cap hierarchy after a policy action."""
    policy = _punishment_policy_snapshot()
    rc, out = ndsctl("json")
    try:
        clients = (_loads_nds_json(out).get("clients") or {}).values()
    except ValueError:
        return False, out or f"ndsctl failed (rc={rc})"
    limits = _load_limits()
    state = _punishment_tc_state()
    has_tc_policy = any(
        _limit_latency(_effective(str(client.get("mac", "")).lower(), limits).get(LATENCY_KEY, "")) or
        _limit_rate(_effective(str(client.get("mac", "")).lower(), limits).get("down", "")) or
        _limit_rate(_effective(str(client.get("mac", "")).lower(), limits).get("up", ""))
        for client in clients)
    trusted = _trusted_macs() if policy["punished"] or _managed_tc_active(state) or has_tc_policy else set()
    if interface is not None:
        return _reconcile_punishment(policy, limits, clients, _load_blocked(), trusted, interface)
    return _reconcile_punishment(policy, limits, clients, _load_blocked(), trusted)


def _traffic_time(at):
    try:
        return datetime.fromtimestamp(at, ZoneInfo(TRAFFIC_TZ))
    except ZoneInfoNotFoundError:
        return datetime.fromtimestamp(at, timezone.utc)


def _load_traffic():
    data = _load_json(TRAFFIC_FILE, {})
    if not isinstance(data, dict):
        data = {}
    return {"started_at": int(data.get("started_at") or 0),
            "updated_at": int(data.get("updated_at") or 0),
            "last": data.get("last") if isinstance(data.get("last"), dict) else {},
            "live": data.get("live") if isinstance(data.get("live"), dict) else {},
            "history_unit": data.get("history_unit"),
            "history": data.get("history") if data.get("history_unit") == "bytes_per_second"
            and isinstance(data.get("history"), list) else [],
            "days": data.get("days") if isinstance(data.get("days"), dict) else {},
            "months": data.get("months") if isinstance(data.get("months"), dict) else {}}


def _traffic_state():
    global _traffic_data
    if _traffic_data is None:
        _traffic_data = _load_traffic()
    return _traffic_data


def _load_wan_traffic():
    data = _load_json(WAN_TRAFFIC_FILE, {})
    if not isinstance(data, dict):
        data = {}
    days = data.get("days") if isinstance(data.get("days"), dict) else {}
    months = data.get("months") if isinstance(data.get("months"), dict) else {}
    counter_source = data.get("counter_source")
    if counter_source not in ("interface", "persistent"):
        counter_source = "interface"

    return {"started_at": int(data.get("started_at") or 0),
            "updated_at": int(data.get("updated_at") or 0),
            "last": data.get("last") if isinstance(data.get("last"), dict) else {},
            "live_last": data.get("live_last") if isinstance(data.get("live_last"), dict) else {},
            "counter_source": counter_source,
            "live": data.get("live") if isinstance(data.get("live"), dict) else {},
            "history_unit": data.get("history_unit"),
            "history": data.get("history") if data.get("history_unit") == "bytes_per_second"
            and isinstance(data.get("history"), list) else [],
            "history_24h": data.get("history_24h") if data.get("history_unit") == "bytes_per_second"
            and isinstance(data.get("history_24h"), list) else [],
            "days": days, "months": months}


def _wan_traffic_state():
    global _wan_traffic_data
    if _wan_traffic_data is None:
        _wan_traffic_data = _load_wan_traffic()
    return _wan_traffic_data


def _traffic_bucket(data, at):
    for bucket in data["history"]:
        if bucket.get("at") == at:
            return bucket
    bucket = {"at": at}
    data["history"].append(bucket)
    return bucket


def _wan_traffic_history_bucket(data, at):
    """Return the current one-minute WAN-rate bucket for 24-hour display."""
    bucket_at = at - (at % WAN_TRAFFIC_HISTORY_BUCKET_SECS)
    history = data["history_24h"]
    if history and history[-1].get("at") == bucket_at:
        return history[-1]
    bucket = {"at": bucket_at}
    history.append(bucket)
    return bucket


def _add_traffic_usage(data, at, download, upload):
    stamp = _traffic_time(at)
    day, month = stamp.strftime("%Y-%m-%d"), stamp.strftime("%Y-%m")
    for collection, key in ((data["days"], day), (data["months"], month)):
        total = collection.setdefault(key, {"download": 0, "upload": 0})
        total["download"] += download
        total["upload"] += upload


def _add_wan_traffic_interval(data, start_at, end_at, download, upload):
    """Retain valid WAN counter deltas, splitting only across calendar boundaries."""
    elapsed = end_at - start_at
    if elapsed <= 0:
        return
    cursor, assigned_download, assigned_upload = start_at, 0, 0
    while cursor < end_at:
        stamp = _traffic_time(cursor)
        tomorrow = stamp.date() + timedelta(days=1)
        midnight = int(datetime(tomorrow.year, tomorrow.month, tomorrow.day,
                                tzinfo=stamp.tzinfo).timestamp())
        segment_end = min(end_at, midnight if midnight > cursor else end_at)
        segment_seconds = segment_end - cursor
        if segment_end == end_at:
            segment_download = download - assigned_download
            segment_upload = upload - assigned_upload
        else:
            segment_download = download * segment_seconds // elapsed
            segment_upload = upload * segment_seconds // elapsed
        _add_traffic_usage(data, cursor, segment_download, segment_upload)
        assigned_download += segment_download
        assigned_upload += segment_upload
        cursor = segment_end


def _prune_traffic(data, at):
    first_second = at - (TRAFFIC_HISTORY_SECS - 1)
    data["history"] = [bucket for bucket in data["history"]
                       if isinstance(bucket, dict) and bucket.get("at", 0) >= first_second]
    if "history_24h" in data:
        first_minute = at - (WAN_TRAFFIC_HISTORY_SECS - 1)
        data["history_24h"] = [bucket for bucket in data["history_24h"]
                               if isinstance(bucket, dict) and bucket.get("at", 0) >= first_minute]
    _prune_usage_periods(data, at)


def _prune_usage_periods(data, at):
    first_day = (_traffic_time(at).date() - timedelta(days=399)).isoformat()
    data["days"] = {day: total for day, total in data["days"].items() if day >= first_day}
    keep_months = sorted(data["months"])[-24:]
    data["months"] = {month: data["months"][month] for month in keep_months}


def _read_traffic_counters(include_flows=False, ip_to_mac=None):
    iface, wan_iface, counter_file = (shlex.quote(value) for value in
                                      (_primary_lan_device(), WAN_IFACE, WAN_COUNTER_REMOTE))
    command = (
        "sample_at=$(date +%s); "
        f"printf '%s\\n' \"$sample_at\"; cat /sys/class/net/{iface}/statistics/rx_bytes; "
        f"cat /sys/class/net/{iface}/statistics/tx_bytes; echo @@WAN; "
        f"wan_rx=$(cat /sys/class/net/{wan_iface}/statistics/rx_bytes); "
        f"wan_tx=$(cat /sys/class/net/{wan_iface}/statistics/tx_bytes); "
        "printf '%s\\n%s\\n' \"$wan_rx\" \"$wan_tx\"; "
        f"echo @@WAN_COUNTER; cat {counter_file} 2>/dev/null || true")
    if include_flows:
        if ip_to_mac is None:
            ip_to_mac, _ = _wan_sampling_inputs()
        command += (
            "; echo @@FLOW_SAMPLE; echo @@SAMPLE_AT; printf '%s\\n' \"$sample_at\"; "
            "echo @@BOOT_ID; cat /proc/sys/kernel/random/boot_id 2>/dev/null || true; "
            f"wan_ips=\"$(ip -4 -o addr show dev {wan_iface} scope global "
            "| awk '{print $4}' | cut -d/ -f1)\"; echo @@WAN_IPS; printf '%s\\n' \"$wan_ips\"; echo @@WAN_COUNTERS; "
            "printf '%s\\n%s\\n' \"$wan_rx\" \"$wan_tx\"; "
            "echo @@CONNTRACK; " + _conntrack_read_command(ip_to_mac))
    rc, out, _ = ssh(command, telemetry=True)
    if rc != 0:
        return None
    counter_raw, _, flow_raw = out.partition(b"@@FLOW_SAMPLE\n")
    lines = counter_raw.decode(errors="replace").splitlines()
    try:
        at, rx, tx = (int(line) for line in lines[:3])
    except (TypeError, ValueError):
        log.warning("invalid traffic counter response for %s", TRAFFIC_IFACE)
        return None
    wan_rx = wan_tx = None
    counter_marker = None
    try:
        wan_marker = lines.index("@@WAN")
        counter_marker = lines.index("@@WAN_COUNTER")
        wan_rx, wan_tx = (int(line) for line in lines[wan_marker + 1:counter_marker])
    except (TypeError, ValueError):
        log.warning("invalid WAN traffic counter response for %s", WAN_IFACE)
    wan_counter = {}
    try:
        if counter_marker is None:
            raise ValueError("WAN counter marker missing")
        for line in lines[counter_marker + 1:]:
            name, separator, value = line.partition("=")
            if separator:
                wan_counter[name] = value
        wan_counter = {key: int(wan_counter[key]) for key in ("total_rx", "total_tx")}
        if min(wan_counter.values()) < 0:
            wan_counter = {}
    except (KeyError, TypeError, ValueError):
        wan_counter = {}
    return {"at": at, "rx": rx, "tx": tx, "wan_rx": wan_rx, "wan_tx": wan_tx,
            "wan_counter": wan_counter, "flow_raw": flow_raw if include_flows else None}


def _connected_count(data, now):
    try:
        clients = (data.get("clients") or {}).values()
    except (AttributeError, TypeError, ValueError):
        return None
    hidden_ips = _infrastructure_client_ips()
    count = 0
    for client in clients:
        try:
            if client.get("ip") not in hidden_ips and now - int(client.get("last_active", 0)) < ONLINE_SECS:
                count += 1
        except (AttributeError, TypeError, ValueError):
            pass
    return count


def _sample_traffic(sample=None):
    if sample is None:
        sample = _read_traffic_counters()
    if not sample:
        return
    with _traffic_lock:
        data = _traffic_state()
        at = sample["at"]
        data["started_at"] = data["started_at"] or at
        data["history_unit"] = "bytes_per_second"
        previous = data["last"]
        try:
            elapsed = at - int(previous["at"])
            upload = sample["rx"] - int(previous["rx"])
            download = sample["tx"] - int(previous["tx"])
        except (KeyError, TypeError, ValueError):
            elapsed = upload = download = 0
        if 0 < elapsed <= max(TRAFFIC_INTERVAL * 3, 10) and upload >= 0 and download >= 0:
            bucket = _traffic_bucket(data, at)
            bucket["download"] = download / elapsed
            bucket["upload"] = upload / elapsed
            _add_traffic_usage(data, at, download, upload)
            data["live"] = {"download": download / elapsed, "upload": upload / elapsed}
        else:
            data["live"] = {"download": 0, "upload": 0}
        data["last"] = {key: value for key, value in sample.items() if key != "flow_raw"}
        data["updated_at"] = at
        _prune_traffic(data, at)
        encoded = json.dumps(data)
    _write_json(TRAFFIC_FILE, encoded)
    _sample_wan_traffic(sample)


def _sample_wan_traffic(sample):
    """Persist WAN deltas, using the router's reboot-persistent counter when available."""
    if sample.get("wan_rx") is None or sample.get("wan_tx") is None:
        return
    with _wan_traffic_lock:
        data = _wan_traffic_state()
        at = sample["at"]
        data["started_at"] = data["started_at"] or at
        data["history_unit"] = "bytes_per_second"
        persistent = sample.get("wan_counter") or {}
        if set(persistent) == {"total_rx", "total_tx"}:
            current_rx, current_tx = persistent["total_rx"], persistent["total_tx"]
            source = "persistent"
        else:
            current_rx, current_tx = sample["wan_rx"], sample["wan_tx"]
            source = "interface"
        previous = data["last"]
        try:
            elapsed = at - int(previous["at"])
            upload = current_tx - int(previous["tx"])
            download = current_rx - int(previous["rx"])
        except (KeyError, TypeError, ValueError):
            elapsed = upload = download = 0
        source_changed = data.get("counter_source") != source
        if source_changed:
            # The raw interface counters and the persistent cumulative
            # counters have different origins. Establish a safe baseline
            # instead of adding the two counter domains together.
            data["counter_source"] = source
            elapsed = upload = download = 0
        # Interface counters remain monotonic through an SSH delay. Retain
        # that traffic instead of silently losing it; if the interval crosses
        # midnight, split it proportionally between its calendar periods.
        # A negative delta is still an interface/router counter reset and is
        # deliberately excluded.
        valid_delta = elapsed > 0 and upload >= 0 and download >= 0
        if valid_delta:
            _add_wan_traffic_interval(data, int(previous.get("at", at)), at, download, upload)
        # The persistent counter is intentionally flushed less often than the
        # manager samples. Use the raw interface counters for realtime rates
        # and the history graph, while retaining the persistent counters above
        # for reboot-safe calendar totals.
        live_previous = data["live_last"]
        try:
            live_elapsed = at - int(live_previous["at"])
            live_upload = sample["wan_tx"] - int(live_previous["tx"])
            live_download = sample["wan_rx"] - int(live_previous["rx"])
        except (KeyError, TypeError, ValueError):
            live_elapsed = live_upload = live_download = 0
        live_valid = (0 < live_elapsed <= max(TRAFFIC_INTERVAL * 3, 10)
                      and live_upload >= 0 and live_download >= 0)
        if live_valid:
            bucket = _traffic_bucket(data, at)
            bucket["download"] = live_download / live_elapsed
            bucket["upload"] = live_upload / live_elapsed
            long_bucket = _wan_traffic_history_bucket(data, at)
            long_bucket["download"] = live_download / live_elapsed
            long_bucket["upload"] = live_upload / live_elapsed
            data["live"] = {"download": live_download / live_elapsed,
                             "upload": live_upload / live_elapsed}
        else:
            data["live"] = {"download": 0, "upload": 0}
        data["live_last"] = {"at": at, "rx": sample["wan_rx"], "tx": sample["wan_tx"]}
        data["last"] = {"at": at, "rx": current_rx, "tx": current_tx}
        data["updated_at"] = at
        _prune_traffic(data, at)
        encoded = json.dumps(data)
    _write_json(WAN_TRAFFIC_FILE, encoded)


def _traffic_history(data, end):
    recent_start = end - (TRAFFIC_HISTORY_SECS - 1)
    old = [bucket for bucket in data.get("history_24h", [])
           if isinstance(bucket, dict) and bucket.get("at", 0) < recent_start]
    recent = [bucket for bucket in data["history"]
              if isinstance(bucket, dict) and bucket.get("at", 0) >= recent_start]
    points = old + recent
    return [{"at": point.get("at"), "download": point.get("download"),
             "upload": point.get("upload")} for point in points]


def _traffic_overview(include_history=False):
    global _wan_usage_data
    with _wan_usage_lock:
        if _wan_usage_data is None:
            _wan_usage_data = _load_wan_usage()
        data = _client_traffic_state(_wan_usage_data)
        at = int(time.time())
        stale = (not data["updated_at"] or at - data["updated_at"] >= WAN_USAGE_MAX_GAP or
                 _wan_usage_data["sampler_id"] != WAN_USAGE_SAMPLER_ID)
        result = {"interface": WAN_IFACE, "updated_at": data["updated_at"],
                  "scope": "clients", "address_family": "IPv4", "stale": stale,
                  "tracking_since": data["started_at"],
                  "live": {"download": None, "upload": None} if stale else data["live"],
                  "today": data["days"].get(_traffic_time(at).strftime("%Y-%m-%d"),
                                             {"download": 0, "upload": 0}),
                  "month": data["months"].get(_traffic_time(at).strftime("%Y-%m"),
                                               {"download": 0, "upload": 0})}
        if include_history:
            result["history"] = _traffic_history(data, at)
            result["recent_start_at"] = at - (TRAFFIC_HISTORY_SECS - 1)
        return copy.deepcopy(result)


def _client_traffic_state(state):
    """Client-only Overview has its own baseline; never import raw WAN totals."""
    data = state.get("overview")
    if not isinstance(data, dict) or data.get("version") != 1:
        data = {"version": 1, "started_at": 0, "updated_at": 0,
                "live": {"download": None, "upload": None},
                "history_unit": "bytes_per_second", "history": [], "history_24h": [],
                "days": {}, "months": {}}
        state["overview"] = data
    return data


def _record_client_traffic(state, active_macs, at, deltas, available, continuous):
    """Record the same capped client deltas used by the individual WAN meters.

    Called under the usage lock; persistence is part of wan-usage.json and
    happens after releasing the lock. A fresh empty snapshot records real
    zeroes, whereas collector/conntrack failures and baselines leave gaps.
    """
    data = _client_traffic_state(state)
    if at <= data["updated_at"]:
        return
    data["started_at"] = data["started_at"] or at
    rates = {"download": None, "upload": None}
    if available and (continuous or not active_macs):
        # The accounting state has already published this sample. Its rates
        # use the actual router timestamp interval, not the browser clock.
        totals = {direction: sum(deltas.get(mac, {}).get(direction, 0) for mac in active_macs)
                  for direction in ("download", "upload")}
        rates = {direction: sum(state["rates"].get(mac, {}).get(direction, 0) for mac in active_macs)
                 for direction in ("download", "upload")}
        _add_traffic_usage(data, at, totals["download"], totals["upload"])
    data["live"] = rates
    _traffic_bucket(data, at).update(rates)
    _wan_traffic_history_bucket(data, at).update(rates)
    data["updated_at"] = at
    _prune_traffic(data, at)


def _client_snapshot_loop():
    time.sleep(0.5)
    while True:
        started = time.monotonic()
        try:
            _sync_networks_if_due()
            payload = _collect_clients_snapshot()
            if payload.get("ok") is True:
                with _clients_cache_lock:
                    global _clients_cache_data, _clients_cache_until
                    _clients_cache_data = payload
                    _clients_cache_until = 0.0
                _refresh_trusted_macs_if_due()
            else:
                log.warning("client snapshot unavailable: %s", payload.get("output", "unknown error"))
        except Exception:
            log.exception("client snapshot error")
        time.sleep(max(0, CLIENTS_SNAPSHOT_INTERVAL - (time.monotonic() - started)))


def _wan_sampling_inputs():
    """None means unavailable; an empty map means a confirmed empty client list."""
    with _clients_cache_lock:
        snapshot = _clients_cache_data
    if not isinstance(snapshot, dict) or snapshot.get("ok") is not True:
        return None, set()
    try:
        if time.time() - int(snapshot["sampled_at"]) > max(CLIENTS_SNAPSHOT_INTERVAL * 3, 10):
            return None, set()
    except (KeyError, TypeError, ValueError):
        return None, set()
    clients = snapshot.get("_live_clients")
    return _wan_usage_inputs(clients.values(), int(time.time())) if isinstance(clients, dict) else (None, set())


def _set_overview_clients(data, now):
    """Publish the collector's connected count without another ndsctl read."""
    global _overview_clients
    count = _connected_count(data, now)
    if count is not None:
        with _traffic_lock:
            _overview_clients = {"at": now, "count": count}


def _set_trusted_macs(macs):
    global _trusted_macs_cache, _trusted_macs_cache_at
    with _clients_cache_lock:
        _trusted_macs_cache = set(macs)
        _trusted_macs_cache_at = time.monotonic()


def _trusted_macs():
    """Return the periodically collected trust state without querying openNDS."""
    with _clients_cache_lock:
        return set(_trusted_macs_cache)


def _refresh_trusted_macs_if_due():
    """Refresh runtime trust state at a low cadence, outside the fast JSON path."""
    with _clients_cache_lock:
        due = time.monotonic() - _trusted_macs_cache_at >= NDS_STATUS_INTERVAL
    if not due:
        return
    rc, out, _ = ssh("ndsctl status")
    text = out.decode(errors="replace")
    if rc != 0 or "busy" in text.lower():
        return
    trusted_section = re.search(r"^Trusted MAC.*?^====", text, re.MULTILINE | re.DOTALL)
    lines = trusted_section.group(0).splitlines() if trusted_section else []
    _set_trusted_macs({line.strip().lower() for line in lines if MAC_RE.match(line.strip())})


def _traffic_loop():
    """One SSH owner for fast counters/conntrack, preserving each configured cadence."""
    next_traffic = next_usage = time.monotonic()
    while True:
        now = time.monotonic()
        traffic_due, usage_due = now >= next_traffic, now >= next_usage
        ip_to_mac, active_macs = _wan_sampling_inputs() if usage_due else ({}, set())
        sample = None
        try:
            if traffic_due or usage_due:
                sample = _read_traffic_counters(include_flows=usage_due, ip_to_mac=ip_to_mac)
        except Exception:
            log.exception("combined WAN read failed")
        if sample:
            if traffic_due:
                try:
                    _sample_traffic(sample)
                except Exception:
                    log.exception("traffic sampler error")
            if usage_due:
                try:
                    _wan_usage_snapshot(ip_to_mac, active_macs, sample["at"], raw=sample["flow_raw"])
                except Exception:
                    log.exception("client WAN usage sampler error")
        if traffic_due:
            next_traffic = max(next_traffic + TRAFFIC_INTERVAL, time.monotonic())
        if usage_due:
            next_usage = max(next_usage + WAN_USAGE_INTERVAL, time.monotonic())
        time.sleep(max(0.05, min(next_traffic, next_usage) - time.monotonic()))


@app.route("/api/overview")
@requires_auth
def overview():
    data = _traffic_overview()
    with _traffic_lock:
        data["connected"] = _overview_clients["count"] if _overview_clients else None
    return jsonify(ok=True, **data)


@app.route("/api/overview/history")
@requires_auth
def overview_history():
    return jsonify(ok=True, **_history_response(_traffic_overview(include_history=True)))


def _load_limits():
    d = _load_json(LIMITS_FILE, {})
    raw_default = d.get("default") if isinstance(d, dict) and isinstance(d.get("default"), dict) else {}
    raw_profiles = d.get("profiles") if isinstance(d, dict) else None
    profiles = {}
    if isinstance(raw_profiles, dict):
        for name, values in raw_profiles.items():
            if isinstance(name, str) and LIMIT_PROFILE_NAME_RE.fullmatch(name) and isinstance(values, dict):
                try:
                    profiles[name] = _clean_limits(values)
                except (TypeError, ValueError):
                    pass
    else:
        profiles = {name: dict(values) for name, values in DEFAULT_LIMIT_PROFILES.items()}
    default = dict(raw_default)
    # Deliberately do not migrate the former burst policy: the replacement is
    # a reducing overuse throttle, not an increase in speed.
    default.pop("burst", None)
    default["throttle"] = _clean_throttle(raw_default.get("throttle"))
    return {"default": default, "devices": d.get("devices") or {},
            "profiles": profiles}


def _clean_limits(d):
    out = {}
    for k, mx in LIMIT_KEYS.items():
        v = d.get(k, "")
        if v in ("", None):
            out[k] = ""
            continue
        v = _kbytes_to_kbits(v, mx) if k in RATE_KEYS else int(v)
        if not 0 <= v <= mx:
            raise ValueError(k)
        out[k] = v
    latency = d.get(LATENCY_KEY, "")
    if latency in ("", None):
        out[LATENCY_KEY] = ""
    else:
        if isinstance(latency, bool):
            raise ValueError(LATENCY_KEY)
        latency = int(latency)
        if not 0 <= latency <= LATENCY_MAX:
            raise ValueError(LATENCY_KEY)
        out[LATENCY_KEY] = latency
    return out


def _clean_throttle(value, from_ui=False):
    raw = value if isinstance(value, dict) else {}
    result = {}
    for key, default in THROTTLE_DEFAULTS.items():
        try:
            value = raw.get(key, default)
            number = (_kbytes_to_kbits(value, PUNISH_CAP_MAX)
                      if from_ui and key == "final_rate" else int(value))
        except (TypeError, ValueError):
            raise ValueError(f"throttle_{key}")
        minimum, maximum = THROTTLE_RANGES[key]
        if not minimum <= number <= maximum:
            raise ValueError(f"throttle_{key}")
        result[key] = number
    return result


def _limits_for_ui(lim):
    def profile(values):
        result = dict(values)
        for key in RATE_KEYS:
            if result.get(key) not in ("", None):
                result[key] = _kbits_to_kbytes(result[key])
        throttle = result.get("throttle")
        if isinstance(throttle, dict):
            result["throttle"] = dict(throttle)
            for key in ("final_rate",):
                result["throttle"][key] = _kbits_to_kbytes(result["throttle"][key])
        return result
    return {"default": profile(lim["default"]),
            "devices": {mac: profile(values) for mac, values in lim["devices"].items()},
            "profiles": {name: profile(values) for name, values in lim["profiles"].items()}}


def _effective(mac, lim):
    dev, dflt = lim["devices"].get(mac, {}), lim["default"]
    effective = {k: dev[k] if dev.get(k) not in ("", None) else dflt.get(k, "")
                 for k in LIMIT_KEYS}
    effective[LATENCY_KEY] = (dev.get(LATENCY_KEY) if dev.get(LATENCY_KEY) not in ("", None)
                              else dflt.get(LATENCY_KEY, ""))
    return effective


def _limit_latency(value):
    try:
        latency = int(value)
    except (TypeError, ValueError):
        return 0
    return latency if 0 <= latency <= LATENCY_MAX else 0


def _gateway_latency_ms(mac, limits, punishment_policy, punished, blocked, trusted):
    if blocked or trusted:
        return 0
    latency = _limit_latency(_effective(mac, limits).get(LATENCY_KEY, ""))
    return latency + (punishment_policy["delay_ms"] if punished else 0)


def _sig(eff):
    return "|".join(str(eff[k]) for k in LIMIT_KEYS)


def _opennds_effective(effective, limits):
    """Return the session profile openNDS should enforce.

    Overuse throttling only lowers the normal cap through CAKE, so the normal
    openNDS rate profile remains valid as a second enforcement layer.
    """
    return dict(effective)


def _ndsctl_auth_with_limits(mac, effective):
    """Authenticate a preauthenticated client with a complete ndsctl profile."""
    # ndsctl turns argv into comma-separated positional values. Quote blanks so
    # they survive the remote shell and retain their documented "use openNDS
    # global value" meaning; an explicit 0 remains unlimited for rates/quotas.
    values = [str(effective[k]) if effective[k] not in ("", None) else ""
              for k in LIMIT_KEYS]
    return ndsctl("auth " + mac + " " + " ".join(shlex.quote(value) for value in values) + " ''")


def _client_rate_quota_limits_match(client, effective):
    """Check the live openNDS values for every explicitly configured limit."""
    timeout = effective.get("timeout", "")
    if timeout not in ("", None):
        try:
            session_start = int(client.get("session_start"))
            session_end = int(client.get("session_end"))
            expected_seconds = int(timeout) * 60
        except (TypeError, ValueError):
            return False
        if expected_seconds == 0:
            if session_end != 0:
                return False
        elif session_end - session_start != expected_seconds:
            return False
    fields = {
        "up": "upload_rate_limit_threshold",
        "down": "download_rate_limit_threshold",
        "upq": "upload_quota",
        "downq": "download_quota",
    }
    for key, field in fields.items():
        expected = effective.get(key, "")
        if expected in ("", None):
            continue
        actual = client.get(field)
        # openNDS represents its unlimited value (0) as the string "null".
        if int(expected) == 0:
            if actual not in (None, "", "0", 0, "null"):
                return False
            continue
        try:
            if int(actual) != int(expected):
                return False
        except (TypeError, ValueError):
            return False
    return True


def _load_mode():
    try:
        with open(MODE_FILE) as f:
            d = json.load(f)
    except (OSError, ValueError):
        d = {}
    return {"mode": d.get("mode") if d.get("mode") in MODES else "portal",
            "auto_trusted": [m for m in d.get("auto_trusted", []) if MAC_RE.match(m)],
            "auto_authed": [m for m in d.get("auto_authed", []) if MAC_RE.match(m)],
            "network_resets": [m for m in d.get("network_resets", []) if MAC_RE.match(m)]}


def _client_network(client):
    try:
        address = ipaddress.ip_address(client.get("ip") or client.get("clientip", ""))
    except ValueError:
        return None
    rows = _network_state().get("networks", [])
    return next((row for row in rows if any(address in ipaddress.IPv4Network(n) for n in row["subnets"])), None)


def _is_portal_subnet(client):
    row = _client_network(client)
    if row:
        return row["mode"] == "portal"
    if _network_state().get("initialized"):
        return False
    try:
        address = ipaddress.ip_address(client.get("ip") or client.get("clientip", ""))
    except ValueError:
        return False
    return any(address in network for network in PORTAL_SUBNETS)


def _client_mode(client, primary=None):
    row = _client_network(client)
    if row:
        return row["mode"] if row["eligible"] else "unmanaged"
    if _network_state().get("initialized"):
        return "unmanaged"
    return "portal" if _is_portal_subnet(client) else (primary or _load_mode()["mode"])


def _client_is_extra_network(client):
    row = _client_network(client)
    return not row["primary"] if row else _is_portal_subnet(client)


def _primary_lan_device():
    return _network_state().get("primary_device") or TRAFFIC_IFACE


def _cached_client(mac):
    with _clients_cache_lock:
        clients = ((_clients_cache_data or {}).get("data") or {}).get("clients") or {}
        return next((dict(c) for c in clients.values()
                     if str(c.get("mac", "")).lower() == str(mac).lower()), {})


def _save_mode(d):
    _save_json(MODE_FILE, d)


def _live_clients_for_control():
    """Get current collector data for auto-auth without another ndsctl json."""
    with _clients_cache_lock:
        snapshot = _clients_cache_data
    if not isinstance(snapshot, dict) or snapshot.get("ok") is not True:
        return None
    try:
        age = time.time() - int(snapshot["sampled_at"])
    except (KeyError, TypeError, ValueError):
        return None
    if age > max(CLIENTS_SNAPSHOT_INTERVAL * 3, 10):
        return None
    clients = snapshot.get("_live_clients")
    return clients.values() if isinstance(clients, dict) else None


def _load_session_refresh():
    raw = _load_json(SESSION_REFRESH_FILE, {})
    if not isinstance(raw, dict):
        return {}
    return {mac: dict(record) for mac, record in raw.items()
            if MAC_RE.fullmatch(mac) and isinstance(record, dict) and
            record.get("stage") in ("logout", "login")}


def _queue_session_refresh(before, after):
    """Only explicit changes to saved session limits may restart an active session."""
    refresh = _load_session_refresh()
    # A stale snapshot may queue work, but the controller only acts after a
    # fresh collection. This preserves an explicit save during a router outage.
    with _clients_cache_lock:
        snapshot = _clients_cache_data or {}
        clients = (snapshot.get("_live_clients") or {}).values() if snapshot.get("ok") else ()
    excluded = _load_blocked() | _trusted_macs()
    primary_mode = _load_mode()["mode"]
    for client in clients:
        mac = str(client.get("mac", "")).lower()
        if (not MAC_RE.fullmatch(mac) or mac in excluded or
                _client_mode(client, primary_mode) == "auto_trust" or
                client.get("state") != "Authenticated"):
            continue
        if _sig(_effective(mac, before)) != _sig(_effective(mac, after)):
            refresh.setdefault(mac, {"stage": "logout",
                                     "session_start": str(client.get("session_start", ""))})
    _save_json(SESSION_REFRESH_FILE, refresh)
    return len(refresh)


def _session_pending(client, effective, trusted=False, applied=None, tc=None):
    fields = []
    mac = str(client.get("mac", "")).lower()
    if not trusted and client.get("state") == "Authenticated":
        fields = [key for key in LIMIT_KEYS if effective.get(key) not in ("", None)
                  and not _client_rate_quota_limits_match(client, {key: effective[key]})]
        previous = (applied if applied is not None else _load_json(APPLIED_FILE, {})).get(mac)
        if previous is not None and previous != _sig(effective):
            old = previous.split("|")
            fields = sorted(set(fields) | {key for key, value in zip(LIMIT_KEYS, old)
                                          if value != str(effective.get(key, ""))})
    tc = tc if tc is not None else _punishment_tc_state()
    interface = _client_tc_interface(client)
    with _qos_status_lock:
        runtime = next((row for row in _qos_status_data["networks"] if row["interface"] == interface), {})
    if interface and interface != _primary_lan_device():
        tc = tc.get("networks", {}).get(interface, {})
    if runtime.get("placement") == "wan":
        tc = _wan_qos_state()
    tc_message = (tc.get("pending", {}).get(mac, "") or tc.get("error", "")) if interface else ""
    tc_note = "" if interface else "Client interface unavailable or unmanaged; only openNDS session limits apply."
    refreshing = not trusted and mac in _load_session_refresh()
    return {"limits_pending": bool(fields) or refreshing, "limits_refreshing": refreshing, "limits_pending_fields": fields,
            "limits_pending_message": ("Updating session limits with automatic logout/login; failed logins are retried."
                                       if refreshing else
                                       "Session profile pending until next login; existing openNDS caps still apply."
                                       if fields else ""), "tc_pending_message": tc_message, "tc_note": tc_note}


def _control_once():
    with _auth_control_lock:
        _control_once_locked()


def _control_once_locked():
    state, lim, punishment_policy = _load_mode(), _load_limits(), _punishment_policy_snapshot()
    applied = _load_json(APPLIED_FILE, {})
    refresh = _load_session_refresh()
    clients = _live_clients_for_control()
    if clients is None:
        return
    clients = list(clients)
    with _clients_cache_lock:
        collection_started = (_clients_cache_data or {}).get("_collection_started_at", 0)
        sample_at = (_clients_cache_data or {}).get("sampled_at", 0)
    blocked, trusted = _load_blocked(), _trusted_macs()
    # Remember first connections while Off too; reconnecting later must never
    # turn a previously known device into a new one when the switch is enabled.
    punishment_policy = _auto_punish_connections(clients, blocked, trusted)
    ok, message = _reconcile_punishment(punishment_policy, lim, clients, blocked, trusted)
    if not ok:
        log.warning("managed queues pending: %s", message)
    mode_dirty = applied_dirty = False
    present = set()
    for client in clients:
        mac = str(client.get("mac", "")).lower()
        if not MAC_RE.match(mac):
            continue
        present.add(mac)
        client_mode = _client_mode(client, state["mode"])
        if mac in state["auto_trusted"] and client_mode != "auto_trust":
            rc, text = ndsctl(f"untrust {mac}")
            if rc != 0:
                continue
            trusted.discard(mac)
            _set_trusted_macs(trusted)
            state["auto_trusted"].remove(mac)
            mode_dirty = True
            if client_mode == "auto_auth" and client.get("state") == "Authenticated":
                refresh[mac] = {"stage": "logout", "session_start": str(client.get("session_start", ""))}
                _save_json(SESSION_REFRESH_FILE, refresh)
        if mac in state["network_resets"] or (client_mode in ("portal", "unmanaged") and mac in state["auto_authed"]):
            if mac not in trusted and client.get("state") == "Authenticated":
                rc, text = ndsctl(f"deauth {mac}")
                if rc != 0:
                    continue
                client = {**client, "state": "Preauthenticated"}
            if mac in state["network_resets"]:
                state["network_resets"].remove(mac)
            if mac in state["auto_authed"]:
                state["auto_authed"].remove(mac)
            refresh.pop(mac, None)
            _save_json(SESSION_REFRESH_FILE, refresh)
            mode_dirty = True
        if client_mode == "unmanaged":
            continue
        if mac in blocked or mac in trusted or client_mode == "auto_trust":
            if mac in refresh:
                del refresh[mac]
                _save_json(SESSION_REFRESH_FILE, refresh)
        if mac in blocked or mac in trusted:
            continue
        if client_mode == "auto_trust":
            rc, text = ndsctl(f"trust {mac}")
            if rc == 0:
                _set_trusted_macs(_trusted_macs() | {mac})
                if mac not in state["auto_trusted"]:
                    state["auto_trusted"].append(mac)
                    mode_dirty = True
            continue
        attempt = _auth_attempts.get(mac)
        if attempt and (sample_at <= attempt["sample_at"] or
                        collection_started <= attempt["completed_at"]):
            continue
        effective = _opennds_effective(_effective(mac, lim), lim)
        authenticated = client.get("state") == "Authenticated"
        if authenticated and mac not in refresh:
            _auth_attempts.pop(mac, None)
            continue
        if not authenticated and (client.get("state") != "Preauthenticated" or
                                   (client_mode != "auto_auth" and mac not in refresh)):
            continue
        # Recover a login that completed before a manager restart or returned
        # an ambiguous response, without logging the client out a second time.
        request = refresh.get(mac, {})
        new_session = (request.get("session_start") and
                       str(client.get("session_start", "")) != request["session_start"])
        if (authenticated and request.get("stage") == "login" and new_session and
                _client_rate_quota_limits_match(client, effective)):
            applied[mac] = _sig(effective)
            applied_dirty = True
            del refresh[mac]
            _save_json(SESSION_REFRESH_FILE, refresh)
            _auth_attempts.pop(mac, None)
            continue
        try:
            if authenticated:
                rc, text = ndsctl(f"deauth {mac}")
                log.info("limits logout %s rc=%s %s", mac, rc, text.strip()[:100])
                if rc != 0:
                    continue
                # Persist before login so retries survive a manager restart,
                # including in portal mode where ordinary auto-login is off.
                refresh[mac]["stage"] = "login"
                _save_json(SESSION_REFRESH_FILE, refresh)
            rc, text = _ndsctl_auth_with_limits(mac, effective)
        finally:
            _auth_attempts[mac] = {"sample_at": sample_at, "completed_at": time.monotonic()}
        log.info("%s %s rc=%s %s", "limits login" if mac in refresh else "auto-auth",
                 mac, rc, text.strip()[:100])
        if rc == 0 and re.search(r"\bauthenticated\b", text, re.IGNORECASE):
            applied[mac] = _sig(effective)
            applied_dirty = True
            if mac in refresh:
                del refresh[mac]
                _save_json(SESSION_REFRESH_FILE, refresh)
            if client_mode == "auto_auth" and mac not in state["auto_authed"]:
                state["auto_authed"].append(mac)
                mode_dirty = True
    for mac in set(_auth_attempts) - present:
        _auth_attempts.pop(mac, None)
    if mode_dirty:
        _save_mode(state)
    if applied_dirty:
        _save_json(APPLIED_FILE, applied)


def _auto_trust_loop():
    while True:
        try:
            _refresh_sqm_cache()
        except Exception:
            log.exception("SQM settings refresh error")
        try:
            _control_once()
        except Exception:
            log.exception("control loop error")
        try:
            _reconcile_sqm_conditional()
        except Exception:
            log.exception("daily SQM rule error")
        try:
            _refresh_sqm_cache()
        except Exception:
            log.exception("SQM settings refresh error")
        time.sleep(AUTOTRUST_INTERVAL)


@app.route("/api/mode", methods=["GET", "PUT"])
@requires_auth
def mode():
    if request.method == "GET":
        s = _load_mode()
        return jsonify(ok=True, mode=s["mode"], auto_trusted=len(s["auto_trusted"]),
                       auto_authed=len(s["auto_authed"]),
                       portal_subnets=[n for row in _network_state().get("networks", []) if row["mode"] == "portal" for n in row["subnets"]])
    new = request.get_json(force=True).get("mode")
    if new not in MODES:
        return jsonify(ok=False, output="invalid mode"), 400
    _change_mode(new)
    return jsonify(ok=True, mode=new, output=f"mode: {new}")


def _change_mode(new):
    network_state = _network_state()
    if network_state.get("initialized"):
        primary = next(r for r in network_state["networks"] if r["primary"])
        ok, output = _apply_network_modes({primary["name"]: new})
        if not ok:
            raise ValueError(output)
        return
    s = _load_mode()
    old = s["mode"]
    if old == "auto_trust" and new != "auto_trust":
        # revert only devices this mode trusted; manual trusts stay
        for mac in s["auto_trusted"]:
            ndsctl(f"untrust {mac}")
        s["auto_trusted"] = []
    if old == "auto_auth" and new != "auto_auth":
        if new == "portal":
            for mac in s["auto_authed"]:
                ndsctl(f"deauth {mac}")
        s["auto_authed"] = []
    s["mode"] = new
    _save_mode(s)
    log.info("mode set to %s", new)


@app.route("/api/limits", methods=["GET", "PUT"])
@requires_auth
def limits():
    lim = _load_limits()
    if request.method == "GET":
        return jsonify(ok=True, rate_unit="KB/s", **_limits_for_ui(lim))
    b = request.get_json(force=True)
    mac = (b.get("mac") or "").lower()
    if mac and not MAC_RE.match(mac):
        return jsonify(ok=False, output="invalid MAC"), 400
    try:
        clean = _clean_limits(b.get("limits") or {})
        throttle = _clean_throttle(b.get("throttle"), from_ui=True) if not mac else None
    except (TypeError, ValueError) as e:
        return jsonify(ok=False, output=f"invalid limit: {e}"), 400
    with _auth_control_lock:
        lim = _load_limits()
        before = copy.deepcopy(lim)
        if not mac:
            clean["throttle"] = throttle
            lim["default"] = clean
        elif b.get("clear") or all(v == "" for v in clean.values()):
            lim["devices"].pop(mac, None)
        else:
            lim["devices"][mac] = clean
        _save_json(LIMITS_FILE, lim)
        refreshing = _queue_session_refresh(before, lim)
    log.info("limits updated mac=%s %s", mac or "default", clean)
    return jsonify(ok=True, output="saved; active session changes apply by automatic logout/login; a brief interruption and session-counter reset are possible",
                   sessions_refreshing=refreshing,
                   rate_unit="KB/s", **_limits_for_ui(lim))


@app.route("/api/limits/profile", methods=["PUT", "DELETE"])
@requires_auth
def limit_profile():
    lim = _load_limits()
    if request.method == "DELETE":
        name = request.args.get("name", "")
        if not LIMIT_PROFILE_NAME_RE.fullmatch(name):
            return jsonify(ok=False, output="invalid profile name"), 400
        if name not in lim["profiles"]:
            return jsonify(ok=False, output="profile not found"), 404
        del lim["profiles"][name]
        _save_json(LIMITS_FILE, lim)
        return jsonify(ok=True, output="profile deleted", rate_unit="KB/s", **_limits_for_ui(lim))
    body = request.get_json(force=True)
    name = body.get("name", "") if isinstance(body, dict) else ""
    if not isinstance(name, str) or not LIMIT_PROFILE_NAME_RE.fullmatch(name):
        return jsonify(ok=False, output="profile name: 1-32 letters, numbers, spaces, _ or -"), 400
    try:
        lim["profiles"][name] = _clean_limits(body.get("limits") or {})
    except (TypeError, ValueError) as error:
        return jsonify(ok=False, output=f"invalid profile: {error}"), 400
    _save_json(LIMITS_FILE, lim)
    return jsonify(ok=True, output="profile saved", rate_unit="KB/s", **_limits_for_ui(lim))


@app.route("/api/punishment", methods=["GET", "PUT"])
@app.route("/api/latency", methods=["GET", "PUT"])  # compatibility with the previous UI URL
@requires_auth
def punishment_policy():
    if request.method == "GET":
        return jsonify(ok=True, **_punishment_for_ui(_punishment_policy_snapshot()))
    body = request.get_json(force=True)
    if not isinstance(body, dict):
        return jsonify(ok=False, output="policy must be an object"), 400
    # Serialize enabling and its baseline with the connection controller.
    with _auth_control_lock:
        # Snapshot before the policy lock; do not take network/cache locks inside it.
        baseline = None
        if body.get("auto_punish_new") is True:
            current = _live_clients_for_control()
            if current is not None:
                baseline = sorted(_punishment_online_clients(list(current)))
        with _punishment_lock:
            policy = _load_punishment_policy()
            try:
                delay = body.get("delay_ms", policy["delay_ms"])
                if isinstance(delay, bool):
                    raise ValueError("delay_ms")
                delay = int(delay)
                if not 1 <= delay <= PUNISH_DELAY_MAX:
                    raise ValueError("delay_ms")
                loss_pct = _clean_loss_pct(body.get("loss_pct", policy["loss_pct"]))
                download = _kbytes_to_kbits(body.get("download", _kbits_to_kbytes(policy["download"])),
                                             PUNISH_CAP_MAX)
                upload = _kbytes_to_kbits(body.get("upload", _kbits_to_kbytes(policy["upload"])),
                                           PUNISH_CAP_MAX)
                if not download or not upload:
                    raise ValueError("caps")
                automatic = body.get("auto_punish_new", policy["auto_punish_new"])
                if not isinstance(automatic, bool):
                    raise ValueError("auto_punish_new")
            except (TypeError, ValueError) as error:
                return jsonify(ok=False, output=f"invalid punishment policy: {error}"), 400
            policy.update(delay_ms=delay, loss_pct=loss_pct, download=download, upload=upload)
            if automatic != policy["auto_punish_new"]:
                policy["auto_punish_new"] = automatic
                if automatic and baseline is not None:
                    known = (set(policy["auto_seen"]) if policy["auto_seen"] is not None
                             else _punishment_history_macs(policy))
                    policy["auto_seen"] = sorted(known | set(baseline))
            _save_punishment_policy(policy)
    if set(body) == {"auto_punish_new"}:
        # This arms future connections; it must not reshape existing users or
        # submit unsaved form values merely because the toggle was clicked.
        return jsonify(ok=True, output="Auto-punish " + ("on" if automatic else "off"),
                       **_punishment_for_ui(policy))
    ok, message = _refresh_punishment()
    return jsonify(ok=ok, output=message,
                   **_punishment_for_ui(policy))


threading.Thread(target=_auto_trust_loop, daemon=True, name="auto-trust").start()
threading.Thread(target=_traffic_loop, daemon=True, name="traffic-sampler").start()
threading.Thread(target=_client_snapshot_loop, daemon=True, name="client-snapshot").start()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
