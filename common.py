"""
common.py — shared helpers used by both app.py (web UI) and daemon.py
(iptables daemon). Keeping this in one place avoids the two processes
drifting out of sync on rule format, comment-tag format, or status format.
"""

import os
import json
import secrets
import ipaddress

RULES_FILE  = os.environ.get("RULES_FILE",  "/etc/pritunl-portfwd/rules.json")
STATUS_FILE = os.environ.get("STATUS_FILE", "/etc/pritunl-portfwd/status.json")

VALID_ENDPOINT_TYPES = ("pritunl", "static", "ipsec")
VALID_PROTOS = ("tcp", "udp", "both")
COMMENT_PREFIX = "pritunl-portfwd"


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


def comment_tag(rule_id, proto, ext_port):
    """iptables comment used to identify rules this tool owns and to
    distinguish multiple proto/port entries belonging to the same rule."""
    return f"{COMMENT_PREFIX}:{rule_id}:{proto}:{ext_port}"


def expand_protos(proto):
    return ["tcp", "udp"] if proto == "both" else [proto]


# ---------------------------------------------------------------------------
# Status file — written by daemon.py (root), read by app.py (unprivileged).
# This is how the unprivileged web process learns live state (which rules
# are actually applied, current target IPs, tunnel health, conflicts)
# without needing root itself to inspect iptables or strongSwan.
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
# Validation
# ---------------------------------------------------------------------------

def valid_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except (ValueError, TypeError):
        return False


def valid_port(value):
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
