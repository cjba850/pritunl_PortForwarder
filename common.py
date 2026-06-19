"""
common.py — shared helpers used by both app.py (web UI) and daemon.py
(iptables daemon). Keeping this in one place avoids the two processes
drifting out of sync on rule format, comment-tag format, or status format.
"""

import os
import json
import secrets
import hashlib
import ipaddress

RULES_FILE            = os.environ.get("RULES_FILE",            "/etc/pritunl-portfwd/rules.json")
STATUS_FILE            = os.environ.get("STATUS_FILE",            "/etc/pritunl-portfwd/status.json")
IMPORT_REQUESTS_FILE  = os.environ.get("IMPORT_REQUESTS_FILE",  "/etc/pritunl-portfwd/import_requests.json")
CAPTURE_REQUESTS_FILE = os.environ.get("CAPTURE_REQUESTS_FILE", "/etc/pritunl-portfwd/capture_requests.json")
CAPTURE_STATUS_FILE   = os.environ.get("CAPTURE_STATUS_FILE",   "/etc/pritunl-portfwd/capture_status.json")
CAPTURE_LOG_DIR       = os.environ.get("CAPTURE_LOG_DIR",       "/etc/pritunl-portfwd/captures")

VALID_ENDPOINT_TYPES = ("pritunl", "static", "ipsec")
VALID_PROTOS = ("tcp", "udp", "both")
VALID_DIRECTIONS = ("inbound", "outbound")
COMMENT_PREFIX = "pritunl-portfwd"
MAX_CAPTURE_SECONDS = int(os.environ.get("MAX_CAPTURE_SECONDS", "600"))  # safety auto-stop


# ---------------------------------------------------------------------------
# Rules file (the rule definitions the admin creates in the UI)
# ---------------------------------------------------------------------------

def load_rules():
    if not os.path.exists(RULES_FILE):
        return []
    try:
        with open(RULES_FILE) as f:
            return json.load(f)
    except Exception:
        return []


def save_rules(rules):
    os.makedirs(os.path.dirname(RULES_FILE), exist_ok=True)
    tmp = RULES_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(rules, f, indent=2)
    os.replace(tmp, RULES_FILE)


def gen_rule_id():
    return secrets.token_hex(6)


def comment_tag(rule_id, proto, ext_spec):
    """iptables comment used to identify rules this tool owns. ext_spec is
    the (possibly range) port spec string, e.g. '8443' or '8000-8010'."""
    return f"{COMMENT_PREFIX}:{rule_id}:{proto}:{ext_spec}"


def expand_protos(proto):
    return ["tcp", "udp"] if proto == "both" else [proto]


# ---------------------------------------------------------------------------
# Status file — written by daemon.py (root), read by app.py (unprivileged)
# ---------------------------------------------------------------------------

def load_status():
    if not os.path.exists(STATUS_FILE):
        return {}
    try:
        with open(STATUS_FILE) as f:
            return json.load(f)
    except Exception:
        return {}


def save_status(status):
    os.makedirs(os.path.dirname(STATUS_FILE), exist_ok=True)
    tmp = STATUS_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(status, f, indent=2)
    os.replace(tmp, STATUS_FILE)
    try:
        os.chmod(STATUS_FILE, 0o644)  # world-readable; contains no secrets
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Import requests — written by app.py (unprivileged, when the admin clicks
# "Import" on a discovered iptables rule), consumed by daemon.py (root,
# since adopting a rule requires deleting/re-tagging real iptables state).
# ---------------------------------------------------------------------------

def load_import_requests():
    if not os.path.exists(IMPORT_REQUESTS_FILE):
        return []
    try:
        with open(IMPORT_REQUESTS_FILE) as f:
            return json.load(f)
    except Exception:
        return []


def save_import_requests(requests_list):
    os.makedirs(os.path.dirname(IMPORT_REQUESTS_FILE), exist_ok=True)
    tmp = IMPORT_REQUESTS_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(requests_list, f, indent=2)
    os.replace(tmp, IMPORT_REQUESTS_FILE)


def rule_signature(raw_line):
    """Stable id for a raw (foreign) iptables rule line, used to refer to
    an import candidate across the UI -> request file -> daemon round trip
    without relying on fragile exact-text matching at every step."""
    return hashlib.sha1(raw_line.strip().encode()).hexdigest()[:12]


def gen_session_id():
    return secrets.token_hex(8)


# ---------------------------------------------------------------------------
# tcpdump capture requests/status — same privilege-separated pattern as
# import requests. The unprivileged web UI writes a request; the root
# daemon is the only thing that actually spawns tcpdump.
# ---------------------------------------------------------------------------

def load_capture_requests():
    if not os.path.exists(CAPTURE_REQUESTS_FILE):
        return []
    try:
        with open(CAPTURE_REQUESTS_FILE) as f:
            return json.load(f)
    except Exception:
        return []


def save_capture_requests(requests_list):
    os.makedirs(os.path.dirname(CAPTURE_REQUESTS_FILE), exist_ok=True)
    tmp = CAPTURE_REQUESTS_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(requests_list, f, indent=2)
    os.replace(tmp, CAPTURE_REQUESTS_FILE)


def load_capture_status():
    if not os.path.exists(CAPTURE_STATUS_FILE):
        return {}
    try:
        with open(CAPTURE_STATUS_FILE) as f:
            return json.load(f)
    except Exception:
        return {}


def save_capture_status(status):
    os.makedirs(os.path.dirname(CAPTURE_STATUS_FILE), exist_ok=True)
    tmp = CAPTURE_STATUS_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(status, f, indent=2)
    os.replace(tmp, CAPTURE_STATUS_FILE)
    try:
        os.chmod(CAPTURE_STATUS_FILE, 0o644)
    except Exception:
        pass


def capture_log_path(session_id):
    return os.path.join(CAPTURE_LOG_DIR, f"capture_{session_id}.log")


# ---------------------------------------------------------------------------
# Port spec parsing — a "spec" is either a single port (int, or a numeric
# string) or a range string "LOW-HIGH". This lets old rules.json entries
# (plain ints, from before range support existed) keep working unchanged.
# ---------------------------------------------------------------------------

def parse_port_spec(spec):
    """Returns (low, high) ints. Raises ValueError on anything invalid."""
    if isinstance(spec, int):
        return spec, spec
    s = str(spec).strip()
    if "-" in s:
        lo, hi = s.split("-", 1)
        lo, hi = int(lo.strip()), int(hi.strip())
    else:
        lo = hi = int(s)
    if lo > hi:
        raise ValueError(f"range start {lo} is greater than range end {hi}")
    return lo, hi


def format_port_spec(low, high):
    return str(low) if low == high else f"{low}-{high}"


def valid_port_spec(spec):
    try:
        lo, hi = parse_port_spec(spec)
        return 1 <= lo <= 65535 and 1 <= hi <= 65535
    except (ValueError, TypeError):
        return False


def ranges_compatible(ext_low, ext_high, int_low, int_high):
    """
    Whether an external port spec can be DNAT'd onto an internal port spec.
    Valid iptables DNAT range patterns:
      - single -> single        (the original, simple case)
      - range  -> single        (many-to-one: fan multiple external ports
                                  into one internal port)
      - single -> range         (one-to-many: iptables load-balances a
                                  single matched port across a destination
                                  range)
      - range  -> range (same size) (parallel, offset-preserving mapping)
    Anything else (two differently-sized ranges on both sides) isn't a
    single iptables rule iptables knows how to express.
    """
    ext_size = ext_high - ext_low + 1
    int_size = int_high - int_low + 1
    if ext_size == 1 or int_size == 1:
        return True
    return ext_size == int_size


def ranges_overlap(a_low, a_high, b_low, b_high):
    return not (a_high < b_low or b_high < a_low)


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def valid_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except (ValueError, TypeError):
        return False


def valid_port(value):
    """Legacy single-port validator, kept for anything not range-aware."""
    try:
        p = int(value)
        return 1 <= p <= 65535
    except (TypeError, ValueError):
        return False


# ---------------------------------------------------------------------------
# Local port scan — no root required. Used for an immediate "this port is
# already in use on this host" check. Reads /proc/net directly (rather than
# shelling out to `ss`) so it works identically for the unprivileged web UI
# process and the root daemon, and has no external dependency.
# ---------------------------------------------------------------------------

def get_local_listening_ports():
    """
    Returns {"tcp": {port, ...}, "udp": {port, ...}} for ports currently
    bound on this host by ANY process — not just our own rules. This is
    what catches "you're about to hijack traffic meant for sshd/another
    app on this same port" before a DNAT rule gets applied.
    """
    result = {"tcp": set(), "udp": set()}
    sources = {
        "tcp": ["/proc/net/tcp", "/proc/net/tcp6"],
        "udp": ["/proc/net/udp", "/proc/net/udp6"],
    }
    for proto, paths in sources.items():
        for path in paths:
            try:
                with open(path) as f:
                    lines = f.readlines()[1:]
            except (FileNotFoundError, PermissionError):
                continue
            for line in lines:
                fields = line.split()
                if len(fields) < 4:
                    continue
                local_addr = fields[1]
                state = fields[3]
                if proto == "tcp" and state != "0A":  # 0A = LISTEN
                    continue
                try:
                    port = int(local_addr.split(":")[-1], 16)
                except ValueError:
                    continue
                result[proto].add(port)
    return result
