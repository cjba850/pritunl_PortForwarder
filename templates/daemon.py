#!/usr/bin/env python3
"""
pritunl-portfwd daemon
Polls Pritunl MongoDB for connected VPN clients and applies/removes
iptables DNAT rules according to /etc/pritunl-portfwd/rules.json
"""

import os
import sys
import time
import json
import signal
import logging
import subprocess
import ipaddress
from datetime import datetime

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

RULES_FILE  = os.environ.get("RULES_FILE",  "/etc/pritunl-portfwd/rules.json")
MONGO_URI   = os.environ.get("MONGO_URI",   "mongodb://localhost:27017/")
MONGO_DB    = os.environ.get("MONGO_DB",    "pritunl")
POLL_SECS   = int(os.environ.get("POLL_SECS", "10"))
LOG_FILE    = "/var/log/pritunl-portfwd-daemon.log"

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [DAEMON] %(levelname)s %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)
log = logging.getLogger("portfwd-daemon")

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------

# active_forwards: user_id → {"virtual_ip": str, "rules": [(proto, ext, int)]}
active_forwards = {}
running = True


# ---------------------------------------------------------------------------
# Signal handling
# ---------------------------------------------------------------------------

def handle_signal(sig, frame):
    global running
    log.info(f"Signal {sig} received, shutting down and flushing rules…")
    running = False


signal.signal(signal.SIGTERM, handle_signal)
signal.signal(signal.SIGINT,  handle_signal)


# ---------------------------------------------------------------------------
# Rule loading
# ---------------------------------------------------------------------------

def load_rules():
    if not os.path.exists(RULES_FILE):
        return []
    try:
        with open(RULES_FILE) as f:
            return json.load(f)
    except Exception as e:
        log.error(f"Failed to load rules file: {e}")
        return []


# ---------------------------------------------------------------------------
# MongoDB
# ---------------------------------------------------------------------------

def get_connected_clients():
    """
    Returns dict: user_id (str) → virtual_ip (str)
    Handles both older and newer Pritunl MongoDB schemas.
    """
    try:
        import pymongo
        client = pymongo.MongoClient(MONGO_URI, serverSelectionTimeoutMS=3000)
        db = client[MONGO_DB]
        result = {}
        for doc in db.clients.find():
            uid = str(doc.get("user_id") or doc.get("user") or "")
            vip_raw = doc.get("virtual_address") or doc.get("virt_address") or ""
            vip = vip_raw.split("/")[0].strip() if vip_raw else ""
            if uid and vip:
                try:
                    ipaddress.ip_address(vip)  # validate
                    result[uid] = vip
                except ValueError:
                    pass
        client.close()
        return result
    except Exception as e:
        log.warning(f"MongoDB query failed: {e}")
        return {}


# ---------------------------------------------------------------------------
# iptables helpers
# ---------------------------------------------------------------------------

COMMENT_PREFIX = "pritunl-portfwd"


def _comment(user_id, proto, ext_port):
    return f"{COMMENT_PREFIX}:{user_id[:8]}:{proto}:{ext_port}"


def run_ipt(args, check=True):
    cmd = ["iptables"] + args
    log.debug("iptables " + " ".join(args))
    result = subprocess.run(cmd, capture_output=True, text=True)
    if check and result.returncode != 0:
        log.warning(f"iptables error: {result.stderr.strip()}")
    return result.returncode == 0


def rule_exists_nat(comment):
    result = subprocess.run(
        ["iptables", "-t", "nat", "-S", "PREROUTING"],
        capture_output=True, text=True
    )
    return comment in result.stdout


def rule_exists_filter(comment):
    result = subprocess.run(
        ["iptables", "-S", "FORWARD"],
        capture_output=True, text=True
    )
    return comment in result.stdout


def apply_forward(virtual_ip, proto, ext_port, int_port, user_id):
    """
    Add PREROUTING DNAT + FORWARD ACCEPT for one proto/port pair.
    Skips silently if the rule is already present (idempotent).
    """
    comment = _comment(user_id, proto, ext_port)

    if not rule_exists_nat(comment):
        run_ipt([
            "-t", "nat", "-A", "PREROUTING",
            "-p", proto,
            "--dport", str(ext_port),
            "-j", "DNAT",
            "--to-destination", f"{virtual_ip}:{int_port}",
            "-m", "comment", "--comment", comment
        ])

    if not rule_exists_filter(comment):
        run_ipt([
            "-A", "FORWARD",
            "-p", proto,
            "-d", virtual_ip,
            "--dport", str(int_port),
            "-j", "ACCEPT",
            "-m", "comment", "--comment", comment
        ])

    log.info(f"Applied: {proto} *:{ext_port} → {virtual_ip}:{int_port} ({comment})")


def remove_forward(virtual_ip, proto, ext_port, int_port, user_id):
    """Remove PREROUTING DNAT + FORWARD ACCEPT rules by comment match."""
    comment = _comment(user_id, proto, ext_port)

    # NAT table
    result = subprocess.run(
        ["iptables", "-t", "nat", "-S", "PREROUTING"],
        capture_output=True, text=True
    )
    for line in result.stdout.splitlines():
        if comment in line:
            delete_args = line.replace("-A ", "-D ", 1).split()
            run_ipt(["-t", "nat"] + delete_args, check=False)

    # Filter table
    result = subprocess.run(
        ["iptables", "-S", "FORWARD"],
        capture_output=True, text=True
    )
    for line in result.stdout.splitlines():
        if comment in line:
            delete_args = line.replace("-A ", "-D ", 1).split()
            run_ipt(delete_args, check=False)

    log.info(f"Removed: {proto} *:{ext_port} → {virtual_ip}:{int_port} ({comment})")


def flush_all_portfwd_rules():
    """Remove every rule we own (identified by COMMENT_PREFIX)."""
    log.info("Flushing all pritunl-portfwd iptables rules…")

    for table, chain in [("nat", "PREROUTING"), (None, "FORWARD")]:
        cmd = ["iptables"]
        if table:
            cmd += ["-t", table]
        cmd += ["-S", chain]
        result = subprocess.run(cmd, capture_output=True, text=True)
        for line in result.stdout.splitlines():
            if COMMENT_PREFIX in line:
                delete_args = line.replace("-A ", "-D ", 1).split()
                full_cmd = ["iptables"]
                if table:
                    full_cmd += ["-t", table]
                full_cmd += delete_args
                subprocess.run(full_cmd, capture_output=True)

    log.info("Flush complete.")


# ---------------------------------------------------------------------------
# Expand proto "both" → ["tcp", "udp"]
# ---------------------------------------------------------------------------

def expand_protos(proto):
    if proto == "both":
        return ["tcp", "udp"]
    return [proto]


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def sync(rules, connected):
    """
    Compare desired state (rules + connected) with active_forwards,
    applying and removing iptables rules as needed.
    """
    global active_forwards

    # Build desired: user_id → [(proto, ext_port, int_port), …]
    desired = {}
    for rule in rules:
        uid = rule["user_id"]
        if uid not in connected:
            continue  # user not online
        vip = connected[uid]
        for proto in expand_protos(rule["proto"]):
            desired.setdefault(uid, {"virtual_ip": vip, "entries": []})
            desired[uid]["entries"].append(
                (proto, rule["external_port"], rule["internal_port"])
            )

    # --- Apply new rules ---
    for uid, info in desired.items():
        vip = info["virtual_ip"]
        current_entries = set(
            active_forwards.get(uid, {}).get("entries", [])
        )
        for entry in info["entries"]:
            if entry not in current_entries:
                proto, ext, int_ = entry
                apply_forward(vip, proto, ext, int_, uid)

    # --- Remove stale rules (user disconnected or rule deleted) ---
    for uid in list(active_forwards.keys()):
        old_info = active_forwards[uid]
        old_vip  = old_info["virtual_ip"]
        new_entries = set(
            tuple(e) for e in desired.get(uid, {}).get("entries", [])
        )
        for entry in old_info["entries"]:
            if tuple(entry) not in new_entries:
                proto, ext, int_ = entry
                remove_forward(old_vip, proto, ext, int_, uid)

    # Update active state
    active_forwards = {
        uid: {
            "virtual_ip": info["virtual_ip"],
            "entries": info["entries"]
        }
        for uid, info in desired.items()
    }


def main():
    log.info("pritunl-portfwd daemon starting")
    log.info(f"Rules file : {RULES_FILE}")
    log.info(f"MongoDB    : {MONGO_URI}{MONGO_DB}")
    log.info(f"Poll every : {POLL_SECS}s")

    # Flush any leftover rules from a previous run
    flush_all_portfwd_rules()

    last_rules_mtime = 0

    while running:
        try:
            # Reload rules if file has changed
            if os.path.exists(RULES_FILE):
                mtime = os.path.getmtime(RULES_FILE)
                if mtime != last_rules_mtime:
                    last_rules_mtime = mtime
                    log.info("Rules file changed, reloading…")

            rules     = load_rules()
            connected = get_connected_clients()
            sync(rules, connected)

        except Exception as e:
            log.error(f"Sync error: {e}", exc_info=True)

        # Sleep in short intervals so SIGTERM is responsive
        for _ in range(POLL_SECS * 2):
            if not running:
                break
            time.sleep(0.5)

    # Clean up on exit
    flush_all_portfwd_rules()
    log.info("Daemon stopped cleanly.")


if __name__ == "__main__":
    main()
