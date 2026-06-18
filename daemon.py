#!/usr/bin/env python3
"""
pritunl-portfwd daemon

Polls Pritunl's MongoDB for connected VPN clients, checks StrongSwan/IPsec
tunnel state, and applies/removes iptables DNAT rules for three kinds of
forwarding targets:

  pritunl  - a Pritunl VPN user's current virtual IP. DYNAMIC: tracked via
             MongoDB; the rule is only applied while the user is connected,
             and is torn down (and re-applied under the new IP) if their
             virtual IP changes between sessions.

  static   - a fixed IP anywhere routable from this host (LAN, another
             VLAN, wherever). PERSISTENT: applied as soon as the rule
             exists, independent of any VPN session state.

  ipsec    - a fixed IP reachable through a named StrongSwan/IPsec
             connection. PERSISTENT like 'static' - the DNAT rule itself
             doesn't depend on the tunnel being up right now (exactly like
             a real firewall config wouldn't delete a forwarding rule just
             because the far end is briefly unreachable). Tunnel up/down
             state IS tracked separately and surfaced to the UI as a
             health indicator.

Before applying any rule, two conflict checks run and any match causes
that specific proto/port to be skipped (and reported, not silently
dropped):

  1. A local process on this host is already bound to the external port
     - the DNAT would otherwise hijack traffic meant for that service,
       since PREROUTING DNAT happens before local delivery.
  2. An existing iptables PREROUTING rule NOT owned by this tool already
     matches the same proto/port (e.g. something added manually, or by
     other tooling).
"""

import os
import re
import sys
import time
import signal
import logging
import subprocess
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import (
    load_rules, save_status,
    expand_protos, comment_tag, get_local_listening_ports,
    COMMENT_PREFIX,
)

# --------------------------------------------------------------------- #
# Config
# --------------------------------------------------------------------- #

MONGO_URI = os.environ.get("MONGO_URI", "mongodb://localhost:27017/")
MONGO_DB  = os.environ.get("MONGO_DB",  "pritunl")
POLL_SECS = int(os.environ.get("POLL_SECS", "10"))
IPSEC_POLL_EVERY = int(os.environ.get("IPSEC_POLL_EVERY", "3"))  # every N cycles
LOG_FILE  = "/var/log/pritunl-portfwd-daemon.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [DAEMON] %(levelname)s %(message)s",
    handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler(sys.stdout)]
)
log = logging.getLogger("portfwd-daemon")

running = True
applied_state = {}   # rule_id -> {"target_ip": str, "entries": [[proto,ext,int], ...]}


def handle_signal(sig, frame):
    global running
    log.info(f"Signal {sig} received, shutting down and flushing rules…")
    running = False


signal.signal(signal.SIGTERM, handle_signal)
signal.signal(signal.SIGINT, handle_signal)


# --------------------------------------------------------------------- #
# Pritunl MongoDB
# --------------------------------------------------------------------- #

def get_connected_pritunl_clients():
    """Returns {user_id: virtual_ip} for currently connected Pritunl clients."""
    try:
        import pymongo, ipaddress
        client = pymongo.MongoClient(MONGO_URI, serverSelectionTimeoutMS=3000)
        db = client[MONGO_DB]
        result = {}
        for doc in db.clients.find():
            uid = str(doc.get("user_id") or doc.get("user") or "")
            vip_raw = doc.get("virtual_address") or doc.get("virt_address") or ""
            vip = vip_raw.split("/")[0].strip() if vip_raw else ""
            if uid and vip:
                try:
                    ipaddress.ip_address(vip)
                    result[uid] = vip
                except ValueError:
                    pass
        client.close()
        return result
    except Exception as e:
        log.warning(f"MongoDB query failed: {e}")
        return {}


# --------------------------------------------------------------------- #
# StrongSwan / IPsec tunnel status  (best-effort)
# --------------------------------------------------------------------- #

def get_ipsec_status():
    """
    Returns {tunnel_name: {"status": "up"|"down"}}.

    Tries `swanctl` (modern strongSwan, vici-based) first, then falls back
    to legacy `ipsec statusall`. Output formats vary across strongSwan
    versions and configs, so this is a best-effort parser. If your tunnel
    names aren't detected correctly, run the relevant command manually
    on this host and adjust the regex below to match your output.

    If neither binary exists (no StrongSwan installed), this returns {}
    quietly - ipsec-type rules just won't show tunnel health, but the
    DNAT rule still applies normally since "ipsec" rules don't depend on
    tunnel state to be applied (see module docstring).
    """
    tunnels = {}

    # ---- swanctl (preferred — modern strongSwan / vici) ----
    try:
        conns = subprocess.run(["swanctl", "--list-conns"],
                                capture_output=True, text=True, timeout=5)
        if conns.returncode == 0:
            for line in conns.stdout.splitlines():
                m = re.match(r'^(\S+):\s', line)
                if m:
                    tunnels[m.group(1)] = {"status": "down"}

            sas = subprocess.run(["swanctl", "--list-sas"],
                                  capture_output=True, text=True, timeout=5)
            if sas.returncode == 0:
                for line in sas.stdout.splitlines():
                    m = re.match(r'^(\S+):\s+#\d+,\s+(\S+)', line)
                    if m:
                        name, state = m.group(1), m.group(2)
                        if name in tunnels and state.upper().startswith("ESTABLISHED"):
                            tunnels[name]["status"] = "up"
            if tunnels:
                return tunnels
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # ---- legacy `ipsec statusall` fallback ----
    try:
        result = subprocess.run(["ipsec", "statusall"],
                                 capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                line = line.strip()
                m = re.match(r'^([\w.\-]+)\{\d+\}:\s+(\S+)', line)
                if m:
                    name, state = m.group(1), m.group(2)
                    tunnels.setdefault(name, {"status": "down"})
                    if "ESTABLISHED" in line.upper() or "INSTALLED" in line.upper():
                        tunnels[name]["status"] = "up"
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    return tunnels


# --------------------------------------------------------------------- #
# Conflict detection
# --------------------------------------------------------------------- #

def get_foreign_nat_rules():
    """Raw PREROUTING DNAT rule lines NOT owned by this tool."""
    try:
        result = subprocess.run(["iptables", "-t", "nat", "-S", "PREROUTING"],
                                 capture_output=True, text=True, timeout=5)
        return [l for l in result.stdout.splitlines() if COMMENT_PREFIX not in l]
    except Exception as e:
        log.warning(f"Failed to read PREROUTING rules: {e}")
        return []


def find_conflict(proto, port, local_ports, foreign_rules):
    """Returns a human-readable conflict reason, or None if no conflict."""
    if port in local_ports.get(proto, set()):
        return (f"a local service is already listening on {proto}/{port} — "
                f"this forward would hijack that traffic")
    needle_proto = f"-p {proto}"
    needle_port = f"--dport {port}"
    for line in foreign_rules:
        if needle_proto in line and needle_port in line:
            return f"an existing (non-portfwd) iptables rule already forwards {proto}/{port}"
    return None


# --------------------------------------------------------------------- #
# iptables rule application
# --------------------------------------------------------------------- #

def run_ipt(args):
    result = subprocess.run(["iptables"] + args, capture_output=True, text=True)
    if result.returncode != 0:
        log.warning(f"iptables error: {result.stderr.strip()}")
    return result.returncode == 0


def apply_forward(target_ip, proto, ext_port, int_port, rule_id):
    comment = comment_tag(rule_id, proto, ext_port)
    run_ipt(["-t", "nat", "-A", "PREROUTING", "-p", proto, "--dport", str(ext_port),
             "-j", "DNAT", "--to-destination", f"{target_ip}:{int_port}",
             "-m", "comment", "--comment", comment])
    run_ipt(["-A", "FORWARD", "-p", proto, "-d", target_ip, "--dport", str(int_port),
             "-j", "ACCEPT", "-m", "comment", "--comment", comment])
    log.info(f"Applied: {proto} *:{ext_port} → {target_ip}:{int_port}  [{comment}]")


def remove_forward(target_ip, proto, ext_port, int_port, rule_id):
    comment = comment_tag(rule_id, proto, ext_port)
    for table, chain in [("nat", "PREROUTING"), (None, "FORWARD")]:
        cmd = ["iptables"] + (["-t", table] if table else []) + ["-S", chain]
        result = subprocess.run(cmd, capture_output=True, text=True)
        for line in result.stdout.splitlines():
            if comment in line:
                del_args = line.replace("-A ", "-D ", 1).split()
                full = ["iptables"] + (["-t", table] if table else []) + del_args
                subprocess.run(full, capture_output=True)
    log.info(f"Removed: {proto} *:{ext_port} → {target_ip}:{int_port}  [{comment}]")


def flush_all_portfwd_rules():
    log.info("Flushing all pritunl-portfwd iptables rules…")
    for table, chain in [("nat", "PREROUTING"), (None, "FORWARD")]:
        cmd = ["iptables"] + (["-t", table] if table else []) + ["-S", chain]
        result = subprocess.run(cmd, capture_output=True, text=True)
        for line in result.stdout.splitlines():
            if COMMENT_PREFIX in line:
                del_args = line.replace("-A ", "-D ", 1).split()
                full = ["iptables"] + (["-t", table] if table else []) + del_args
                subprocess.run(full, capture_output=True)
    log.info("Flush complete.")


# --------------------------------------------------------------------- #
# Target resolution
# --------------------------------------------------------------------- #

def resolve_target(rule, pritunl_clients, ipsec_status):
    """
    Returns {"target_ip": str|None, "active": bool, "reason": str}

    'active' means "the DNAT rule should be applied right now". For
    pritunl-type rules that's only true while the user is connected.
    For static/ipsec rules it's true as soon as a target_ip is configured
    - those don't depend on a live VPN session (see module docstring).
    """
    etype = rule.get("endpoint_type", "pritunl")  # old rules default to pritunl

    if etype == "pritunl":
        vip = pritunl_clients.get(rule.get("user_id"))
        return {"target_ip": vip, "active": vip is not None,
                "reason": "connected" if vip else "disconnected"}

    if etype == "static":
        ip = rule.get("target_ip")
        return {"target_ip": ip, "active": bool(ip), "reason": "static"}

    if etype == "ipsec":
        ip = rule.get("target_ip")
        tunnel = rule.get("tunnel_name", "")
        tstate = ipsec_status.get(tunnel, {}).get("status", "unknown")
        return {"target_ip": ip, "active": bool(ip), "reason": f"tunnel_{tstate}"}

    return {"target_ip": None, "active": False, "reason": "unknown_endpoint_type"}


# --------------------------------------------------------------------- #
# Sync — the heart of the daemon
# --------------------------------------------------------------------- #

def sync(rules, pritunl_clients, ipsec_status):
    global applied_state

    local_ports   = get_local_listening_ports()
    foreign_rules = get_foreign_nat_rules()

    desired   = {}
    conflicts = []
    resolved  = {}

    for rule in rules:
        rid  = rule["id"]
        info = resolve_target(rule, pritunl_clients, ipsec_status)
        resolved[rid] = info

        if not info["active"] or not info["target_ip"]:
            continue

        entries = []
        for proto in expand_protos(rule["proto"]):
            ext, intp = rule["external_port"], rule["internal_port"]
            reason = find_conflict(proto, ext, local_ports, foreign_rules)
            if reason:
                conflicts.append({"rule_id": rid, "proto": proto,
                                   "port": ext, "reason": reason})
                continue
            entries.append([proto, ext, intp])

        if entries:
            desired[rid] = {"target_ip": info["target_ip"], "entries": entries}

    # ---- Removals (stale entries, or target IP changed) ----
    for rid, old in list(applied_state.items()):
        new = desired.get(rid)
        ip_changed = (new is None) or (new["target_ip"] != old["target_ip"])
        old_entries = [tuple(e) for e in old["entries"]]
        if ip_changed:
            # IP changed (e.g. Pritunl user reconnected with a new virtual
            # IP) - tear down everything under the OLD ip unconditionally.
            for proto, ext, intp in old_entries:
                remove_forward(old["target_ip"], proto, ext, intp, rid)
        else:
            new_set = set(tuple(e) for e in new["entries"])
            for proto, ext, intp in old_entries:
                if (proto, ext, intp) not in new_set:
                    remove_forward(old["target_ip"], proto, ext, intp, rid)

    # ---- Additions ----
    for rid, info in desired.items():
        old = applied_state.get(rid)
        ip_changed = (old is None) or (old["target_ip"] != info["target_ip"])
        old_set = set() if ip_changed else set(tuple(e) for e in old["entries"])
        for proto, ext, intp in info["entries"]:
            if (proto, ext, intp) not in old_set:
                apply_forward(info["target_ip"], proto, ext, intp, rid)

    applied_state = desired

    # ---- Status snapshot for the web UI ----
    save_status({
        "updated_at": datetime.utcnow().isoformat(),
        "rules": {
            rid: {
                "target_ip": resolved[rid]["target_ip"],
                "applied":   rid in desired,
                "reason":    resolved[rid]["reason"],
            } for rid in resolved
        },
        "ipsec_tunnels": ipsec_status,
        "conflicts": conflicts,
    })


# --------------------------------------------------------------------- #
# Main loop
# --------------------------------------------------------------------- #

def main():
    log.info("pritunl-portfwd daemon starting")
    log.info(f"MongoDB: {MONGO_URI}{MONGO_DB}  |  Poll every {POLL_SECS}s")

    flush_all_portfwd_rules()

    cycle = 0
    ipsec_status = {}

    while running:
        try:
            rules = load_rules()
            pritunl_clients = get_connected_pritunl_clients()

            if cycle % IPSEC_POLL_EVERY == 0:
                ipsec_status = get_ipsec_status()

            sync(rules, pritunl_clients, ipsec_status)

        except Exception as e:
            log.error(f"Sync error: {e}", exc_info=True)

        cycle += 1
        for _ in range(POLL_SECS * 2):
            if not running:
                break
            time.sleep(0.5)

    flush_all_portfwd_rules()
    log.info("Daemon stopped cleanly.")


if __name__ == "__main__":
    main()
