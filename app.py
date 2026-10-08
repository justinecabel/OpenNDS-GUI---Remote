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
DELETED_FILE = os.environ.get("DELETED_FILE", "/data/deleted.json")
ONLINE_SECS = int(os.environ.get("ONLINE_SECS", "300"))
BLOCK_FILE = os.environ.get("BLOCK_FILE", "/data/blocked.json")
TRAFFIC_FILE = os.environ.get("TRAFFIC_FILE", "/data/traffic.json")
TRAFFIC_IFACE = os.environ.get("TRAFFIC_IFACE", "br-lan")
WAN_IFACE = os.environ.get("WAN_IFACE", "eth0")
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
DOMAIN_RANK_FILE = os.environ.get("DOMAIN_RANK_FILE", "/data/domain-rank.json")
DOMAIN_LOG_FILE = os.environ.get("DOMAIN_LOG_FILE", "/tmp/opennds-dns-queries.log")
DOMAIN_REFRESH_INTERVAL = max(60.0, float(os.environ.get("DOMAIN_REFRESH_INTERVAL", "1800")))
DOMAIN_LOG_COLLECT_INTERVAL = 60.0
DOMAIN_WINDOW_SECS = 24 * 60 * 60
DOMAIN_WATCH_LIMIT = 50
DOMAIN_DETAIL_LIMIT = 30
DOMAIN_LOG_MAX_BYTES = 1024 * 1024
LAST_DNS_RETENTION_SECS = 7 * 24 * 60 * 60
LAST_DNS_LIMIT = 100
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
_history_lock = threading.Lock()
_traffic_lock = threading.Lock()
_wan_usage_lock = threading.Lock()
_wan_traffic_lock = threading.Lock()
_domain_rank_lock = threading.Lock()
_clients_cache_lock = threading.Lock()
_portal_lock = threading.Lock()
_punishment_lock = threading.Lock()
_punishment_tc_lock = threading.Lock()
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
_domain_refresh_at = 0.0
_domain_refresh_lock = threading.Lock()
_auth_attempts = {}
_auth_control_lock = threading.Lock()
HISTORY_GENERATION = secrets.token_hex(8)

MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
CONNTRACK_TUPLE_RE = re.compile(
    r"\bsrc=(?P<src>\S+)\s+dst=(?P<dst>\S+)(?P<fields>(?:(?!\bsrc=).)*?)\bbytes=(?P<bytes>\d+)")
CONNTRACK_PORTS_RE = re.compile(r"\bsport=(\d+)\s+dport=(\d+)")
DNS_QUERY_RE = re.compile(r"\bquery\[[^]]+\]\s+([^\s]+)\s+from\s+([^\s]+)", re.IGNORECASE)
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


def ssh(command: str, data: bytes | None = None, timeout=15):
    """Run a command on the OpenWrt VM; returns (returncode, stdout bytes, stderr str)."""
    with _ssh_lock:
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
    with _clients_cache_lock:
        snapshot = _clients_cache_data
    if snapshot is None:
        return jsonify(ok=True, data={"clients": {}}, sampled_at=0, stale=True,
                       output="collecting client snapshot")
    payload = dict(snapshot)
    # The collector keeps the unmodified openNDS records for the auto-control
    # loop. They are an implementation detail, not part of the public API.
    payload.pop("_live_clients", None)
    payload.pop("_collection_started_at", None)
    payload = _with_live_wan_usage(payload)
    try:
        payload["stale"] = int(time.time()) - int(payload.get("sampled_at", 0)) > \
            max(CLIENTS_SNAPSHOT_INTERVAL * 3, 10)
    except (TypeError, ValueError):
        payload["stale"] = True
    return jsonify(payload)


@app.route("/api/clients/<mac>/history")
@requires_auth
def client_wan_history(mac):
    mac = mac.lower()
    if not MAC_RE.match(mac):
        return jsonify(ok=False, output="invalid MAC"), 400
    return jsonify(ok=True, **_history_response(_client_wan_history(mac)))


@app.route("/api/clients/<mac>/dns")
@requires_auth
def client_dns_history(mac):
    mac = mac.lower()
    if not MAC_RE.match(mac):
        return jsonify(ok=False, output="invalid MAC"), 400
    # This endpoint is called only while the corresponding expanded client
    # dialog is open. Refresh first so the list can reflect new queries rather
    # than waiting for the normal one-minute background collection.
    _refresh_domain_ranking()
    return jsonify(ok=True, last_dns=_last_dns_client_snapshot().get(mac, []))


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


@app.route("/api/sqm", methods=["GET", "PUT"])
@requires_auth
def sqm():
    if request.method == "GET":
        rc, out, err = ssh("uci -q show sqm.@queue[0]")
        interfaces = _router_interfaces()
        interface_roles = _router_interface_roles(interfaces)
        if rc != 0:
            return jsonify(ok=True, configured=False, config={},
                           interfaces=interfaces, interface_roles=interface_roles,
                           output=err or "no SQM queue configured (is sqm-scripts installed?)")
        cfg = {}
        for line in out.decode(errors="replace").splitlines():
            m = re.match(r"^sqm\.[^.]+\.(\w+)='?(.*?)'?$", line)
            if m:
                cfg[m.group(1)] = m.group(2)
        for key in ("download", "upload"):
            try:
                cfg[key] = _kbits_to_kbytes(int(cfg[key]))
            except (KeyError, ValueError):
                pass
        if cfg.get("interface") and cfg["interface"] not in interfaces:
            interfaces.append(cfg["interface"])
            interfaces.sort()
        return jsonify(ok=True, configured=True, config=cfg, interfaces=interfaces,
                       interface_roles=interface_roles, rate_unit="KB/s")
    b = request.get_json(force=True)
    try:
        down = _kbytes_to_kbits(b["download"], 10_000_000)
        up = _kbytes_to_kbits(b["upload"], 10_000_000)
    except (KeyError, TypeError, ValueError):
        return jsonify(ok=False, output="download/upload must be valid KB/s values"), 400
    iface, qdisc, script = b.get("interface", ""), b.get("qdisc", "cake"), b.get("script", "piece_of_cake.qos")
    if not _IFACE_RE.match(iface) or qdisc not in _SQM_QDISC or script not in _SQM_SCRIPT:
        return jsonify(ok=False, output="invalid value"), 400
    enabled = "1" if b.get("enabled") else "0"
    rc, out, err = ssh("uci -q show sqm.@queue[0]")
    current = dict(re.findall(r"^sqm\.[^.]+\.(\w+)='([^']*)'", out.decode(errors="replace"), re.MULTILINE))
    if rc != 0 or any(current.get(key) != value for key, value in
                      {"enabled": enabled, "interface": iface, "qdisc": qdisc, "script": script}.items()):
        return jsonify(ok=False, pending=True,
                       output="SQM structural changes require maintenance; current queues were left unchanged"), 409
    ok, error = _set_sqm_rates({"download": down, "upload": up})
    if not ok:
        return jsonify(ok=False, pending=True, output=error), 409
    _set_sqm_conditional_baseline({"download": down, "upload": up})
    conditional_ok, conditional_message = _reconcile_sqm_conditional(force=True)
    message = "applied"
    if conditional_message:
        message += f"; {conditional_message}"
    return jsonify(ok=conditional_ok, output=message), (200 if conditional_ok else 502)


@app.route("/api/sqm/conditional", methods=["GET", "PUT"])
@requires_auth
def sqm_conditional():
    if request.method == "GET":
        return jsonify(ok=True, **_sqm_conditional_for_ui(_load_sqm_conditional()))
    body = request.get_json(force=True)
    if not isinstance(body, dict):
        return jsonify(ok=False, output="daily SQM rule must be an object"), 400
    with _sqm_conditional_lock:
        policy = _load_sqm_conditional()
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
        if force_today:
            enabled = True
            today, _ = _today_wan_traffic_total()
            policy["forced_date"] = today
        elif not enabled:
            policy["forced_date"] = ""
        policy.update(enabled=enabled, threshold_gb=threshold_gb, download=download, upload=upload,
                      error="")
        _save_sqm_conditional(policy)
    ok, message = _reconcile_sqm_conditional(force=True)
    return jsonify(ok=ok, output=message, **_sqm_conditional_for_ui(_load_sqm_conditional())), \
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
        with _punishment_lock:
            previous = _load_punishment_policy()
            policy = dict(previous)
            punished = set(policy["punished"])
            if act == "punish":
                punished.add(mac)
            else:
                punished.discard(mac)
            policy["punished"] = sorted(punished)
            _save_punishment_policy(policy)
        ok, detail = _refresh_punishment()
        if not ok:
            # Do not leave a client marked as punished when its qdisc could not
            # be installed. The previous policy remains the truthful state.
            with _punishment_lock:
                _save_punishment_policy(previous)
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
        if act == "deauth" and _load_mode()["mode"] == "auto_auth":
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
    auto_mode = _load_mode()["mode"] != "portal"
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
        if _load_mode()["mode"] == "auto_auth":
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
            mac = client["mac"].lower()
            if mac in _load_blocked():
                return Response("This client is blocked.", status=403)
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
        if _load_mode()["mode"] == "auto_auth":
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
    return {"version": version, "day": day, "month": month, "sample_at": max(0, sample_at),
            "devices": devices, "flows": flows, "rates": rates, "boot_id": boot_id.lower(),
            "sampler_id": sampler_id, "interface_last": interface_last}


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


def _read_wan_flows(ip_to_mac, raw=None):
    """Read NATed IPv4 flows, whose reply destination is the WAN address."""
    if not ip_to_mac:
        return None
    if raw is None:
        interface = shlex.quote(WAN_IFACE)
        rc, raw, _ = ssh(
            "echo @@SAMPLE_AT; date +%s; "
            "echo @@BOOT_ID; cat /proc/sys/kernel/random/boot_id 2>/dev/null || true; "
            f"echo @@WAN_IPS; ip -4 -o addr show dev {interface} scope global "
            "| awk '{print $4}' | cut -d/ -f1; "
            f"echo @@WAN_COUNTERS; cat /sys/class/net/{interface}/statistics/rx_bytes; "
            f"cat /sys/class/net/{interface}/statistics/tx_bytes; "
            "echo @@CONNTRACK; cat /proc/net/nf_conntrack 2>/dev/null || true")
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
    with _wan_usage_lock:
        if _wan_usage_data is None:
            _wan_usage_data = _load_wan_usage()
        state = _wan_usage_data
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
            for values in devices.values():
                values["today"] = {"download": 0, "upload": 0}
        if month_changed:
            for values in devices.values():
                values["month"] = {"download": 0, "upload": 0}
        state["day"] = day
        state["month"] = month
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


def _load_sqm_conditional():
    data = _load_json(SQM_CONDITIONAL_FILE, {})
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
    return {"enabled": data.get("enabled") is True, "threshold_gb": threshold_gb, **rates,
            "active": data.get("active") is True, "baseline": baseline,
            "forced_date": forced_date, "error": error if isinstance(error, str) else ""}


def _save_sqm_conditional(policy):
    _save_json(SQM_CONDITIONAL_FILE, policy)


def _today_wan_traffic_total():
    """The SQM threshold is all traffic crossing the WAN interface."""
    with _wan_traffic_lock:
        data = _wan_traffic_state()
        at = data["updated_at"] or int(time.time())
        day = _traffic_time(at).strftime("%Y-%m-%d")
        totals = data["days"].get(day, {})
        try:
            total = int(totals.get("download", 0)) + int(totals.get("upload", 0))
        except (AttributeError, TypeError, ValueError):
            total = 0
    return day, max(0, total)


def _sqm_conditional_for_ui(policy):
    day, today_bytes = _today_wan_traffic_total()
    return {"enabled": policy["enabled"], "threshold_gb": policy["threshold_gb"],
            "download": _kbits_to_kbytes(policy["download"]),
            "upload": _kbits_to_kbytes(policy["upload"]), "active": policy["active"],
            "forced_today": policy.get("forced_date") == day,
            "error": policy["error"], "today_date": day, "today_bytes": today_bytes,
            "wan_interface": WAN_IFACE, "threshold_unit": "GB", "rate_unit": "KB/s"}


def _get_sqm_rates():
    rc, out, err = ssh("set -e; uci -q get sqm.@queue[0].enabled; "
                       "uci -q get sqm.@queue[0].download; uci -q get sqm.@queue[0].upload")
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


def _set_sqm_rates(rates):
    """Persist and apply bandwidth only, without restarting SQM."""
    try:
        ingress, egress = int(rates["download"]), int(rates["upload"])
        if not 1 <= ingress <= PUNISH_CAP_MAX or not 1 <= egress <= PUNISH_CAP_MAX:
            return False, "live SQM changes require positive rates; queues left unchanged"
    except (KeyError, TypeError, ValueError):
        return False, "SQM rates are invalid"
    with _punishment_tc_lock:
        interfaces, error = _punishment_interfaces()
        if not interfaces:
            return False, error
        layouts, error = _inspect_managed_queues(interfaces, allow_cake=True)
        if layouts is None:
            return False, error
        lan = interfaces["download"] == TRAFFIC_IFACE
        targets = {"download": egress if lan else ingress, "upload": ingress if lan else egress}
        commands = []
        state = _punishment_tc_state()
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
            return False, str(error)
        rc, out, err = ssh("set -e; " + "; ".join(commands), timeout=30)
        if rc != 0:
            return False, (out.decode(errors="replace") + err).strip() or "live SQM update incomplete; no restart attempted"
    return True, ""


def _set_sqm_conditional_baseline(rates):
    """Preserve manual SQM edits as the normal rates to restore after the rule."""
    with _sqm_conditional_lock:
        policy = _load_sqm_conditional()
        if policy["active"]:
            policy["baseline"] = dict(rates)
            _save_sqm_conditional(policy)


def _reconcile_sqm_conditional(force=False):
    global _last_sqm_conditional_check
    now = time.monotonic()
    with _sqm_conditional_lock:
        if not force and now - _last_sqm_conditional_check < SQM_CONDITIONAL_INTERVAL:
            return True, ""
        _last_sqm_conditional_check = now
        policy = _load_sqm_conditional()
        today, today_bytes = _today_wan_traffic_total()
        threshold_bytes = int(Decimal(policy["threshold_gb"]) * (1024 ** 3))
        forced_today = policy.get("forced_date") == today
        should_apply = forced_today or (policy["enabled"] and today_bytes >= threshold_bytes)
        target = {"download": policy["download"], "upload": policy["upload"]}
        if should_apply:
            current, error = _get_sqm_rates()
            if current is None:
                policy["error"] = error
                _save_sqm_conditional(policy)
                return False, error
            if not policy["active"]:
                policy["baseline"] = current
            if current != target or policy.get("error"):
                ok, error = _set_sqm_rates(target)
                if not ok:
                    policy["error"] = error
                    _save_sqm_conditional(policy)
                    return False, error
            policy["active"] = True
            policy["error"] = ""
            _save_sqm_conditional(policy)
            return True, "daily SQM rule active"
        if policy["active"]:
            baseline = policy["baseline"]
            if set(baseline) != {"download", "upload"}:
                policy["error"] = "could not restore the normal SQM rates"
                _save_sqm_conditional(policy)
                return False, policy["error"]
            current, error = _get_sqm_rates()
            if current is None:
                policy["error"] = error
                _save_sqm_conditional(policy)
                return False, error
            if current != baseline or policy.get("error"):
                ok, error = _set_sqm_rates(baseline)
                if not ok:
                    policy["error"] = error
                    _save_sqm_conditional(policy)
                    return False, error
            policy["active"] = False
            policy["baseline"] = {}
            policy["forced_date"] = ""
            policy["error"] = ""
            _save_sqm_conditional(policy)
            return True, "normal SQM rates restored"
        return True, "daily SQM rule waiting" if policy["enabled"] else "daily SQM rule disabled"


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
    if not isinstance(data, dict):
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
    return {"delay_ms": delay, **caps, "loss_pct": loss_pct, "punished": punished}


def _save_punishment_policy(policy):
    _save_json(PUNISH_FILE, policy)


def _punishment_policy_snapshot():
    with _punishment_lock:
        return _load_punishment_policy()


def _punishment_tc_state():
    state = _load_json(PUNISH_TC_FILE, {})
    return state if isinstance(state, dict) else {}


def _punishment_for_ui(policy):
    tc = _punishment_tc_state()
    return {"delay_ms": policy["delay_ms"], "loss_pct": policy["loss_pct"],
            "download": _kbits_to_kbytes(policy["download"]),
            "upload": _kbits_to_kbytes(policy["upload"]), "punished": len(policy["punished"]),
            "rate_unit": "KB/s", "tc_active": bool(tc.get("active")),
            "tc_error": tc.get("error", "")}


def _punishment_interfaces():
    """Return the configured SQM egress device and its ingress IFB device."""
    rc, out, err = ssh("uci -q get sqm.@queue[0].interface")
    if rc != 0:
        return None, err or "punishment requires an active SQM queue"
    sqm_interface = out.decode(errors="replace").strip() or TRAFFIC_IFACE
    if not _IFACE_RE.match(sqm_interface):
        return None, "SQM interface is invalid"
    ifb = PUNISH_IFB or f"ifb4{sqm_interface}"
    if not _IFACE_RE.match(ifb):
        return None, "SQM ingress IFB name is invalid"
    # With SQM on the managed LAN bridge, downloads leave the bridge and
    # uploads are redirected to its IFB. With SQM on a WAN device, the
    # directions are reversed. An explicit PUNISH_IFB override is supported
    # for routers that use a non-standard IFB name.
    if sqm_interface == TRAFFIC_IFACE:
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
        if (mac in blocked or mac in trusted or not valid_ip or
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
    """Add/change one leaf without replacing a root or an existing queue type."""
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
        message = "Queue type change pending until the client queue can be drained."
        if profile.get("session_active", True) and filters:
            return [], message
        if filters:
            return [f"tc filter delete dev {dev} parent 1: protocol ip prio {f['priority']} "
                    f"handle {f['handle']} u32" for f in filters], message
        if leaf["backlog"] != 0:
            return [], message
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


def _apply_punishment_qdisc(policy, desired):
    """Reconcile leaves in the existing hierarchy; never restart SQM as recovery."""
    state = _punishment_tc_state()
    interfaces, error = _punishment_interfaces()
    layouts = None
    if interfaces:
        layouts, error = _inspect_managed_queues(interfaces)
    if layouts is None:
        _save_json(PUNISH_TC_FILE, {**state, "error": error,
                                  "pending": {mac: error for mac in desired}})
        return False, error
    try:
        if state.get("interfaces") not in (None, interfaces):
            raise ValueError("SQM interfaces changed; existing queues left unchanged")
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
        next_state = {**state, "active": True, "version": 2, "interfaces": interfaces,
                      "bindings": bindings, "pending": pending, "error": ""}
        # Persist ownership before executing so partial additions remain recoverable.
        if next_state != state:
            _save_json(PUNISH_TC_FILE, next_state)
        if commands:
            rc, out, err = ssh("set -e; " + "; ".join(commands), timeout=30)
            if rc != 0:
                error = (out.decode(errors="replace") + err).strip() or "queue update incomplete"
                _save_json(PUNISH_TC_FILE, {**next_state, "error": error})
                return False, error
        try:
            previous = json.loads(state.get("signature", "{}" )).get("clients", {})
        except (ValueError, AttributeError):
            previous = {}
        applied_clients = {mac: previous.get(mac, {}) if mac in pending else profile
                           for mac, profile in desired.items()}
        next_state.update(clients=sorted(desired), signature=json.dumps(
            {"clients": applied_clients, "interfaces": interfaces}, sort_keys=True))
        if next_state != state:
            _save_json(PUNISH_TC_FILE, next_state)
        return True, ("saved; some queue changes remain pending" if pending else "managed queues active")
    except (ValueError, KeyError, TypeError) as exc:
        error = str(exc)
        _save_json(PUNISH_TC_FILE, {**state, "error": error,
                                  "pending": {mac: error for mac in desired}})
        return False, error



def _reconcile_punishment(policy, limits, clients, blocked, trusted):
    with _punishment_tc_lock:
        state = _punishment_tc_state()
        clients = list(clients)
        excluded = set(policy["punished"]) | set(trusted)
        desired = _managed_tc_clients(clients, policy, limits, blocked, trusted,
                                      _throttle_rate_caps(clients, limits, excluded))
        if desired:
            return _apply_punishment_qdisc(policy, desired)
        if state.get("active"):
            return _apply_punishment_qdisc(policy, {})
        return True, "no active punished clients"


def _refresh_punishment():
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
    trusted = _trusted_macs() if policy["punished"] or state.get("active") or has_tc_policy else set()
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


def _read_traffic_counters(include_flows=False):
    iface, wan_iface, counter_file = (shlex.quote(value) for value in
                                      (TRAFFIC_IFACE, WAN_IFACE, WAN_COUNTER_REMOTE))
    command = (
        "sample_at=$(date +%s); "
        f"printf '%s\\n' \"$sample_at\"; cat /sys/class/net/{iface}/statistics/rx_bytes; "
        f"cat /sys/class/net/{iface}/statistics/tx_bytes; echo @@WAN; "
        f"wan_rx=$(cat /sys/class/net/{wan_iface}/statistics/rx_bytes); "
        f"wan_tx=$(cat /sys/class/net/{wan_iface}/statistics/tx_bytes); "
        "printf '%s\\n%s\\n' \"$wan_rx\" \"$wan_tx\"; "
        f"echo @@WAN_COUNTER; cat {counter_file} 2>/dev/null || true")
    if include_flows:
        command += (
            "; echo @@FLOW_SAMPLE; echo @@SAMPLE_AT; printf '%s\\n' \"$sample_at\"; "
            "echo @@BOOT_ID; cat /proc/sys/kernel/random/boot_id 2>/dev/null || true; "
            f"echo @@WAN_IPS; ip -4 -o addr show dev {wan_iface} scope global "
            "| awk '{print $4}' | cut -d/ -f1; echo @@WAN_COUNTERS; "
            "printf '%s\\n%s\\n' \"$wan_rx\" \"$wan_tx\"; "
            "echo @@CONNTRACK; cat /proc/net/nf_conntrack 2>/dev/null || true")
    rc, out, _ = ssh(command)
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
    count = 0
    for client in clients:
        try:
            if now - int(client.get("last_active", 0)) < ONLINE_SECS:
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
    with _wan_traffic_lock:
        data = _wan_traffic_state()
        at = data["updated_at"] or int(time.time())
        result = {"interface": WAN_IFACE, "updated_at": data["updated_at"],
                  "tracking_since": data["started_at"], "live": data["live"],
                  "today": data["days"].get(_traffic_time(at).strftime("%Y-%m-%d"),
                                             {"download": 0, "upload": 0}),
                  "month": data["months"].get(_traffic_time(at).strftime("%Y-%m"),
                                               {"download": 0, "upload": 0})}
        if include_history:
            result["history"] = _traffic_history(data, at)
            result["recent_start_at"] = at - (TRAFFIC_HISTORY_SECS - 1)
        return copy.deepcopy(result)


def _normalise_ranked_domain(value):
    if not isinstance(value, str):
        return None
    domain = value.strip().rstrip(".").lower()
    if not domain or len(domain) > 253 or "." not in domain or \
            domain in {"status.client", "localhost"} or domain.endswith((".lan", ".local", ".arpa")):
        return None
    labels = domain.split(".")
    if any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels):
        return None
    return domain


def _clean_domain_details(raw):
    clean = {}
    if not isinstance(raw, dict):
        return clean
    for root, value in raw.items():
        root = _normalise_ranked_domain(root)
        if not root or not isinstance(value, dict):
            continue
        try:
            total = max(0, int(value.get("total", 0)))
        except (TypeError, ValueError):
            continue
        subdomains, clients = {}, {}
        for name, count in (value.get("subdomains") or {}).items():
            name = _normalise_ranked_domain(name)
            try:
                count = int(count)
            except (TypeError, ValueError):
                continue
            if name and (name == root or name.endswith("." + root)) and count > 0:
                subdomains[name] = count
        for name, count in (value.get("clients") or {}).items():
            try:
                count = int(count)
            except (TypeError, ValueError):
                continue
            if isinstance(name, str) and name and len(name) <= 253 and count > 0:
                clients[name] = count
        if total > 0:
            clean[root] = {"total": total, "subdomains": subdomains, "clients": clients}
    return clean


def _load_domain_rank_state():
    raw = _load_json(DOMAIN_RANK_FILE, {})
    raw = raw if isinstance(raw, dict) else {}
    buckets = []
    for bucket in raw.get("buckets", []):
        if not isinstance(bucket, dict):
            continue
        try:
            at = int(bucket.get("at", 0))
        except (TypeError, ValueError):
            continue
        domains = _clean_domain_details(bucket.get("domains"))
        if at > 0 and domains:
            buckets.append({"at": at, "domains": domains})
    try:
        offset = max(0, int(raw.get("offset", 0)))
        refreshed_at = max(0, int(raw.get("refreshed_at", 0)))
        next_refresh_at = max(0, int(raw.get("next_refresh_at", 0)))
    except (TypeError, ValueError):
        offset = refreshed_at = next_refresh_at = 0
    raw_watched = raw.get("watched", [])
    raw_watched = raw_watched if isinstance(raw_watched, list) else []
    watched = sorted({normalised for domain in raw_watched
                      if (normalised := _normalise_ranked_domain(domain))})[:DOMAIN_WATCH_LIMIT]
    last_clients = {}
    for mac, values in (raw.get("last_clients") or {}).items():
        entries = []
        for value in values if isinstance(values, list) else []:
            domain = _normalise_ranked_domain(value.get("domain")) if isinstance(value, dict) else None
            try:
                at = int(value.get("at", 0)) if isinstance(value, dict) else 0
            except (TypeError, ValueError):
                at = 0
            if domain and at > 0:
                entries.append({"domain": domain, "at": at})
        if MAC_RE.match(str(mac)) and entries:
            last_clients[str(mac).lower()] = entries[-LAST_DNS_LIMIT:]
    return {"offset": offset, "refreshed_at": refreshed_at, "next_refresh_at": next_refresh_at,
            "buckets": buckets, "pending": _clean_domain_details(raw.get("pending")),
            "watched": watched, "logging_active": raw.get("logging_active", True) is True,
            "last_clients": last_clients,
            "error": raw.get("error", "") if isinstance(raw.get("error"), str) else ""}


def _ensure_domain_logging():
    """Inspect existing logging only; never reload DNS during collection/startup."""
    rc, out, err = ssh("uci -q get dhcp.@dnsmasq[0].logqueries; "
                       "uci -q get dhcp.@dnsmasq[0].logfacility")
    lines = out.decode(errors="replace").splitlines()
    if rc != 0 or len(lines) != 2 or lines[0].strip() != "1" or lines[1].strip() != DOMAIN_LOG_FILE:
        return False, "DNS logging is unavailable; existing dnsmasq configuration was left unchanged"
    return True, ""


def _read_domain_log(offset):
    offset = max(0, int(offset))
    log_file = shlex.quote(DOMAIN_LOG_FILE)
    command = (
        f"log={log_file}; [ -f \"$log\" ] || exit 1; "
        "now=$(date +%s); size=$(wc -c < \"$log\" 2>/dev/null || echo 0); "
        f"if [ \"$size\" -lt {offset} ]; then start=0; else start={offset}; fi; "
        "printf '%s\\n%s\\n' \"$now\" \"$size\"; "
        "if [ \"$size\" -gt \"$start\" ]; then head -c \"$size\" \"$log\" | tail -c +$((start + 1)); fi; "
        f"if [ \"$size\" -ge {DOMAIN_LOG_MAX_BYTES} ]; then : > \"$log\"; fi"
    )
    rc, out, err = ssh(command, timeout=30)
    if rc != 0:
        return None, None, f"could not read DNS query log: {err.strip() or 'router command failed'}"
    lines = out.decode(errors="replace").splitlines()
    try:
        at, size = int(lines[0]), max(0, int(lines[1]))
    except (IndexError, ValueError):
        return None, None, "invalid DNS query log response"
    return at, (0 if size >= DOMAIN_LOG_MAX_BYTES else size, "\n".join(lines[2:])), ""


def _dns_clients():
    rc, out, _ = ssh("cat /tmp/dhcp.leases 2>/dev/null || true")
    if rc != 0:
        return {}
    clients = {}
    for line in out.decode(errors="replace").splitlines():
        fields = line.split()
        if len(fields) >= 4:
            clients[fields[2]] = {"mac": fields[1].lower(),
                                  "hostname": fields[3] if fields[3] != "*" else fields[2]}
    return clients


def _domain_counts(log_text, clients, watched):
    counts = {}
    for line in log_text.splitlines():
        match = DNS_QUERY_RE.search(line)
        if not match:
            continue
        domain = _normalise_ranked_domain(match.group(1))
        try:
            source = ipaddress.ip_address(match.group(2))
        except ValueError:
            continue
        if not domain or not source.is_private or source.is_loopback:
            continue
        matches = [item for item in watched if domain == item or domain.endswith("." + item)]
        if not matches:
            continue
        watched_domain = max(matches, key=len)
        record = counts.setdefault(watched_domain, {"total": 0, "subdomains": {}, "clients": {}})
        record["total"] += 1
        record["subdomains"][domain] = record["subdomains"].get(domain, 0) + 1
        hostname = clients.get(str(source), {}).get("hostname", str(source))
        record["clients"][hostname] = record["clients"].get(hostname, 0) + 1
    return counts


def _last_dns_queries(log_text, clients, at):
    last = {}
    for line in log_text.splitlines():
        match = DNS_QUERY_RE.search(line)
        if not match:
            continue
        domain = _normalise_ranked_domain(match.group(1))
        client = clients.get(match.group(2))
        if domain and client and MAC_RE.match(client.get("mac", "")):
            last.setdefault(client["mac"], []).append({"domain": domain, "at": at})
    return last


def _merge_last_dns(target, updates):
    for mac, entries in updates.items():
        merged = list(target.get(mac, []))
        for entry in entries:
            merged = [old for old in merged if old["domain"] != entry["domain"]]
            merged.append(entry)
        target[mac] = merged[-LAST_DNS_LIMIT:]


def _merge_domain_details(target, source):
    for root, values in source.items():
        record = target.setdefault(root, {"total": 0, "subdomains": {}, "clients": {}})
        record["total"] += values["total"]
        for field in ("subdomains", "clients"):
            for name, count in values[field].items():
                record[field][name] = record[field].get(name, 0) + count


def _refresh_domain_ranking():
    global _domain_refresh_at
    with _domain_refresh_lock:
        now = time.monotonic()
        if _domain_refresh_at and now - _domain_refresh_at < 3:
            return
        _domain_refresh_at = now
        _collect_domain_ranking()


def _collect_domain_ranking():
    with _domain_rank_lock:
        state = _load_domain_rank_state()
        enabled, error = _ensure_domain_logging()
        if not enabled:
            state["error"] = error
            _save_json(DOMAIN_RANK_FILE, state)
            return
        at, result, error = _read_domain_log(state["offset"])
        if error:
            state["error"] = error
            _save_json(DOMAIN_RANK_FILE, state)
            return
        offset, log_text = result
        clients = _dns_clients()
        _merge_domain_details(state["pending"], _domain_counts(log_text, clients, state["watched"]))
        _merge_last_dns(state["last_clients"], _last_dns_queries(log_text, clients, at))
        state["last_clients"] = {mac: [item for item in items if item["at"] >= at - LAST_DNS_RETENTION_SECS]
                                 for mac, items in state["last_clients"].items()}
        state["last_clients"] = {mac: items for mac, items in state["last_clients"].items() if items}
        state["offset"], state["error"], state["logging_active"] = offset, "", True
        if not state["next_refresh_at"]:
            state["next_refresh_at"] = at + int(DOMAIN_REFRESH_INTERVAL)
        if at >= state["next_refresh_at"]:
            if state["pending"]:
                state["buckets"].append({"at": at, "domains": state["pending"]})
                state["pending"] = {}
            state["refreshed_at"] = at
            state["next_refresh_at"] = at + int(DOMAIN_REFRESH_INTERVAL)
        cutoff = at - DOMAIN_WINDOW_SECS
        state["buckets"] = [bucket for bucket in state["buckets"] if bucket["at"] >= cutoff]
        _save_json(DOMAIN_RANK_FILE, state)


def _domain_ranking_for_ui():
    with _domain_rank_lock:
        state = _load_domain_rank_state()
    totals = {}
    cutoff = int(time.time()) - DOMAIN_WINDOW_SECS
    for bucket in state["buckets"]:
        if bucket["at"] >= cutoff:
            _merge_domain_details(totals, bucket["domains"])
    _merge_domain_details(totals, state["pending"])
    rows = []
    for domain, values in sorted(totals.items(), key=lambda item: (-item[1]["total"], item[0])):
        rows.append({"domain": domain, "queries": values["total"],
                     "subdomains": [{"name": name, "queries": count} for name, count in
                                    sorted(values["subdomains"].items(), key=lambda item: (-item[1], item[0]))[:DOMAIN_DETAIL_LIMIT]],
                     "clients": [{"name": name, "queries": count} for name, count in
                                 sorted(values["clients"].items(), key=lambda item: (-item[1], item[0]))[:DOMAIN_DETAIL_LIMIT]]})
    return {"domains": rows, "watched": state["watched"],
            "refreshed_at": state["refreshed_at"], "error": state["error"]}


def _last_dns_client_snapshot():
    with _domain_rank_lock:
        state = _load_domain_rank_state()
    return {mac: list(entries) for mac, entries in state["last_clients"].items()}


def _domain_ranking_loop():
    while True:
        try:
            _refresh_domain_ranking()
        except Exception:
            log.exception("domain ranking error")
        time.sleep(DOMAIN_LOG_COLLECT_INTERVAL)


def _client_snapshot_loop():
    time.sleep(0.5)
    while True:
        started = time.monotonic()
        try:
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
    """Return the current map only when the collector has a fresh snapshot."""
    with _clients_cache_lock:
        snapshot = _clients_cache_data
    if not isinstance(snapshot, dict) or snapshot.get("ok") is not True:
        return {}, set()
    try:
        if time.time() - int(snapshot["sampled_at"]) > max(CLIENTS_SNAPSHOT_INTERVAL * 3, 10):
            return {}, set()
    except (KeyError, TypeError, ValueError):
        return {}, set()
    clients = snapshot.get("_live_clients")
    return _wan_usage_inputs(clients.values(), int(time.time())) if isinstance(clients, dict) else ({}, set())


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
            if traffic_due or ip_to_mac:
                sample = _read_traffic_counters(include_flows=bool(ip_to_mac))
        except Exception:
            log.exception("combined WAN read failed")
        if sample:
            if traffic_due:
                try:
                    _sample_traffic(sample)
                except Exception:
                    log.exception("traffic sampler error")
            if ip_to_mac:
                try:
                    _wan_usage_snapshot(ip_to_mac, active_macs, sample["at"], raw=sample["flow_raw"])
                except Exception:
                    log.exception("client WAN usage sampler error")
        if traffic_due:
            next_traffic = max(next_traffic + TRAFFIC_INTERVAL, time.monotonic())
        if usage_due:
            next_usage = max(next_usage + WAN_USAGE_INTERVAL, time.monotonic())
        try:
            _reconcile_sqm_conditional()
        except Exception:
            log.exception("daily SQM rule error")
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


@app.route("/api/domains")
@requires_auth
def domains():
    return jsonify(ok=True, **_domain_ranking_for_ui())


@app.route("/api/domains/watch", methods=["PUT"])
@requires_auth
def domain_watchlist():
    body = request.get_json(silent=True)
    values = body.get("domains") if isinstance(body, dict) else None
    if not isinstance(values, list) or len(values) > DOMAIN_WATCH_LIMIT:
        return jsonify(ok=False, output=f"domains must contain at most {DOMAIN_WATCH_LIMIT} domains"), 400
    watched = set()
    for value in values:
        domain = _normalise_ranked_domain(value)
        if not domain:
            return jsonify(ok=False, output="invalid domain"), 400
        watched.add(domain)
    with _domain_rank_lock:
        state = _load_domain_rank_state()
        state.update({"watched": sorted(watched), "buckets": [], "pending": {}, "offset": 0,
                      "refreshed_at": 0, "next_refresh_at": 0, "error": "",
                      "logging_active": True})
        _save_json(DOMAIN_RANK_FILE, state)
    _refresh_domain_ranking()
    return jsonify(ok=True, **_domain_ranking_for_ui())


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
            "auto_authed": [m for m in d.get("auto_authed", []) if MAC_RE.match(m)]}


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
    if _load_mode()["mode"] != "auto_trust":
        for client in clients:
            mac = str(client.get("mac", "")).lower()
            if (not MAC_RE.fullmatch(mac) or mac in excluded or
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
    tc_message = tc.get("pending", {}).get(mac, "") or tc.get("error", "")
    refreshing = not trusted and mac in _load_session_refresh()
    return {"limits_pending": bool(fields) or refreshing, "limits_refreshing": refreshing, "limits_pending_fields": fields,
            "limits_pending_message": ("Updating session limits with automatic logout/login; failed logins are retried."
                                       if refreshing else
                                       "Session profile pending until next login; existing openNDS caps still apply."
                                       if fields else ""), "tc_pending_message": tc_message}


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
    tc_active = bool(_punishment_tc_state().get("active"))
    has_tc_policy = any(any(_effective(str(c.get("mac", "")).lower(), lim).get(key)
                           for key in (LATENCY_KEY, "up", "down")) for c in clients)
    if punishment_policy["punished"] or has_tc_policy or tc_active:
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
        if mac in blocked or mac in trusted or state["mode"] == "auto_trust":
            if mac in refresh:
                del refresh[mac]
                _save_json(SESSION_REFRESH_FILE, refresh)
        if mac in blocked or mac in trusted:
            continue
        if state["mode"] == "auto_trust":
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
                                   (state["mode"] != "auto_auth" and mac not in refresh)):
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
            if state["mode"] == "auto_auth" and mac not in state["auto_authed"]:
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
            _control_once()
        except Exception:
            log.exception("control loop error")
        time.sleep(AUTOTRUST_INTERVAL)


@app.route("/api/mode", methods=["GET", "PUT"])
@requires_auth
def mode():
    if request.method == "GET":
        s = _load_mode()
        return jsonify(ok=True, mode=s["mode"], auto_trusted=len(s["auto_trusted"]),
                       auto_authed=len(s["auto_authed"]))
    new = request.get_json(force=True).get("mode")
    if new not in MODES:
        return jsonify(ok=False, output="invalid mode"), 400
    _change_mode(new)
    return jsonify(ok=True, mode=new, output=f"mode: {new}")


def _change_mode(new):
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
        except (TypeError, ValueError) as error:
            return jsonify(ok=False, output=f"invalid punishment policy: {error}"), 400
        policy.update(delay_ms=delay, loss_pct=loss_pct, download=download, upload=upload)
        _save_punishment_policy(policy)
    return jsonify(ok=True, output="saved; compatible queues update live; queue-type changes remain pending",
                   **_punishment_for_ui(policy))


threading.Thread(target=_auto_trust_loop, daemon=True, name="auto-trust").start()
threading.Thread(target=_traffic_loop, daemon=True, name="traffic-sampler").start()
threading.Thread(target=_client_snapshot_loop, daemon=True, name="client-snapshot").start()
threading.Thread(target=_domain_ranking_loop, daemon=True, name="domain-ranking").start()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
