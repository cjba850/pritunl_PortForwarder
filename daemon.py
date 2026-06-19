#!/usr/bin/env python3
"""
pritunl-portfwd daemon

Polls Pritunl's MongoDB for connected VPN clients, checks StrongSwan/IPsec
tunnel state, and applies/removes iptables rules for two rule directions:

  inbound  - a fresh incoming connection on an external port gets DNAT'd
             to a target (Pritunl user / static IP / IPsec endpoint).
             Same mechanism regardless of target type; see resolve_target().

  outbound - traffic FROM a target (same three endpoint kinds) gets its
             SOURCE PORT rewritten (SNAT/MASQUERADE) to a fixed port as it
             leaves, optionally scoped to a specific destination IP. This
             exists for services that expect outbound traffic to originate
             from one specific, predictable source port rather than an
             arbitrary one - e.g.:

                 1.2.3.4 -> VPN -> 192.1.2.3   :5000  (inbound rule)
                 192.1.2.3 -> VPN -> 1.2.3.4   src-port pinned to :5001  (outbound rule)

             IMPORTANT: outbound rules are inserted at the TOP of
             POSTROUTING (-I, not -A), because Pritunl already has its own
             broad MASQUERADE rule there for general client internet
             access, and a connection's NAT table lookup stops at the
             first match - appending would mean ours never gets reached.

             ALSO IMPORTANT: this cannot redirect reply packets that
             already belong to an established, conntrack-tracked
             connection - the kernel reuses that connection's cached NAT
             translation without re-consulting the nat table. Outbound
             rules only affect genuinely new connections/packets leaving
             the target. For most real protocols (a flow's own replies
             coming back through conntrack) no rule is needed at all;
             these rules matter when the same source port needs to be
             presented consistently across separate, distinct outbound
             connections.

Two more responsibilities:

  Conflict detection - before applying an inbound rule, checks whether a
  local process already owns that port, and whether an existing,
  non-portfwd iptables rule already forwards an overlapping port range.

  Rule import - every cycle, scans PREROUTING for DNAT rules NOT owned by
  this tool and publishes them as "importable" candidates in status.json.
  When the (unprivileged) web UI requests an import, this daemon (root)
  deletes the original raw rule and creates an equivalent managed entry.

  Traffic capture - on request (via capture_requests.json, written by the
  unprivileged web UI), spawns a filtered tcpdump for a given rule and
  writes its output to a log file the UI tails. Auto-stops after
  MAX_CAPTURE_SECONDS as a safety net against orphaned captures.
"""

import os
import re
import sys
import time
import shutil
import signal
import logging
import subprocess
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import (
    load_rules, save_rules, save_status,
    load_import_requests, save_import_requests, rule_signature,
    load_capture_requests, save_capture_requests,
    load_capture_status, save_capture_status, capture_log_path,
    expand_protos, comment_tag, get_local_listening_ports,
    parse_port_spec, format_port_spec, ranges_overlap, valid_ip, valid_port_spec,
    gen_rule_id, COMMENT_PREFIX, CAPTURE_LOG_DIR, MAX_CAPTURE_SECONDS,
)

# --------------------------------------------------------------------- #
# Config
# --------------------------------------------------------------------- #

MONGO_URI = os.environ.get("MONGO_URI", "mongodb://localhost:27017/")
MONGO_DB  = os.environ.get("MONGO_DB",  "pritunl")
POLL_SECS = int(os.environ.get("POLL_SECS", "10"))
IPSEC_POLL_EVERY = int(os.environ.get("IPSEC_POLL_EVERY", "3"))  # every N sync cycles
LOG_FILE  = "/var/log/pritunl-portfwd-daemon.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [DAEMON] %(levelname)s %(message)s",
    handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler(sys.stdout)]
)
log = logging.getLogger("portfwd-daemon")

running = True
# rule_id -> {"kind": "inbound"/"outbound", "target_ip": str, "entries": [...]}
applied_state = {}
# session_id -> {"proc": Popen, "started_at": float, "log_path": str, "logf": file}
active_captures = {}


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
    Returns {tunnel_name: {"status": "up"|"down"}}. Tries `swanctl`
    (modern strongSwan, vici-based) first, then falls back to legacy
    `ipsec statusall`. Output formats vary across strongSwan
    versions/configs, so this is a best-effort parser - see README.
    """
    tunnels = {}
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
# Reading existing iptables state — used for conflict detection and
# rule import (discovering pre-existing, non-portfwd DNAT rules)
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


def get_foreign_forward_rules():
    """Raw FORWARD rule lines NOT owned by this tool (used to clean up a
    matching ACCEPT rule when a DNAT rule gets imported)."""
    try:
        result = subprocess.run(["iptables", "-S", "FORWARD"],
                                 capture_output=True, text=True, timeout=5)
        return [l for l in result.stdout.splitlines() if COMMENT_PREFIX not in l]
    except Exception as e:
        log.warning(f"Failed to read FORWARD rules: {e}")
        return []


DPORT_RE = re.compile(r'-p (\w+)\b.*?--dport (\d+)(?::(\d+))?')
TODEST_RE = re.compile(r'--to-destination ([\d.]+)(?::(\d+)(?:-(\d+))?)?')


def parse_dport(line):
    m = DPORT_RE.search(line)
    if not m:
        return None
    proto = m.group(1)
    low = int(m.group(2))
    high = int(m.group(3)) if m.group(3) else low
    return proto, low, high


def parse_importable_rules(foreign_lines):
    """Parses foreign (non-portfwd) PREROUTING DNAT lines into structured
    import candidates. Lines that aren't DNAT rules are skipped."""
    candidates = []
    for line in foreign_lines:
        if "-j DNAT" not in line:
            continue
        dport = parse_dport(line)
        m_dest = TODEST_RE.search(line)
        if not dport or not m_dest:
            continue
        proto, ext_low, ext_high = dport
        target_ip = m_dest.group(1)
        if m_dest.group(2):
            int_low = int(m_dest.group(2))
            int_high = int(m_dest.group(3)) if m_dest.group(3) else int_low
        else:
            int_low, int_high = ext_low, ext_high
        candidates.append({
            "id": rule_signature(line),
            "raw": line.strip(),
            "proto": proto,
            "external_port": format_port_spec(ext_low, ext_high),
            "internal_port": format_port_spec(int_low, int_high),
            "target_ip": target_ip,
        })
    return candidates


def process_import_requests(pritunl_clients):
    """Consumes pending import requests from the web UI: deletes the
    original raw iptables rule and appends a corresponding managed entry
    to rules.json (picked up by sync() immediately after)."""
    requests = load_import_requests()
    if not requests:
        return

    foreign_nat = get_foreign_nat_rules()
    foreign_fwd = get_foreign_forward_rules()
    candidates = {c["id"]: c for c in parse_importable_rules(foreign_nat)}

    rules = load_rules()
    changed = False

    for req in requests:
        rid = req.get("id")
        cand = candidates.get(rid)
        if not cand:
            log.warning(f"Import request {rid} no longer matches any existing "
                        f"iptables rule — dropping request.")
            continue

        del_args = cand["raw"].replace("-A ", "-D ", 1).split()
        subprocess.run(["iptables", "-t", "nat"] + del_args, capture_output=True)

        for fline in foreign_fwd:
            if f"-d {cand['target_ip']}" in fline and "-j ACCEPT" in fline:
                fdel = fline.replace("-A ", "-D ", 1).split()
                subprocess.run(["iptables"] + fdel, capture_output=True)
                break

        user_id = next((uid for uid, vip in pritunl_clients.items()
                         if vip == cand["target_ip"]), None)

        new_rule = {
            "id": gen_rule_id(),
            "direction": "inbound",
            "proto": cand["proto"],
            "external_port": cand["external_port"],
            "internal_port": cand["internal_port"],
            "comment": "Imported from existing iptables configuration",
            "created_at": datetime.utcnow().isoformat(),
        }
        if user_id:
            new_rule["endpoint_type"] = "pritunl"
            new_rule["user_id"] = user_id
            new_rule["user_name"] = ""
        else:
            new_rule["endpoint_type"] = "static"
            new_rule["target_ip"] = cand["target_ip"]
            new_rule["label"] = "Imported rule"

        rules.append(new_rule)
        changed = True
        log.info(f"Imported foreign rule into managed rules: {cand['proto']} "
                 f"{cand['external_port']} -> {cand['target_ip']}:{cand['internal_port']}")

    if changed:
        save_rules(rules)
    save_import_requests([])  # fire-and-forget: always clear after one attempt


# --------------------------------------------------------------------- #
# Conflict detection (inbound rules only — see find_outbound_duplicate
# in app.py for the equivalent check on the outbound side, which is a
# pure config-level check and doesn't need root)
# --------------------------------------------------------------------- #

def find_conflict(proto, ext_low, ext_high, local_ports, foreign_lines):
    local_set = local_ports.get(proto, set())
    if any(p in local_set for p in range(ext_low, ext_high + 1)):
        span = format_port_spec(ext_low, ext_high)
        return (f"a local service is already listening on one or more ports "
                f"in {proto}/{span} — this forward would hijack that traffic")
    for line in foreign_lines:
        parsed = parse_dport(line)
        if not parsed:
            continue
        f_proto, f_low, f_high = parsed
        if f_proto == proto and ranges_overlap(ext_low, ext_high, f_low, f_high):
            f_span = format_port_spec(f_low, f_high)
            return f"an existing (non-portfwd) iptables rule already forwards {proto}/{f_span}"
    return None


# --------------------------------------------------------------------- #
# iptables rule application — inbound (DNAT) and outbound (SNAT) — both
# range-aware on the ports involved
# --------------------------------------------------------------------- #

def run_ipt(args):
    result = subprocess.run(["iptables"] + args, capture_output=True, text=True)
    if result.returncode != 0:
        log.warning(f"iptables error: {result.stderr.strip()}")
    return result.returncode == 0


def _match_syntax(low, high):
    """iptables MATCH syntax uses a colon for ranges: --dport 8000:8010"""
    return str(low) if low == high else f"{low}:{high}"


def _dest_syntax(low, high):
    """iptables --to-destination / --to-ports syntax uses a hyphen: 8000-8010"""
    return str(low) if low == high else f"{low}-{high}"


def apply_forward(target_ip, proto, ext_spec, int_spec, rule_id):
    comment = comment_tag(rule_id, proto, ext_spec)
    ext_low, ext_high = parse_port_spec(ext_spec)
    int_low, int_high = parse_port_spec(int_spec)

    run_ipt(["-t", "nat", "-A", "PREROUTING", "-p", proto,
             "--dport", _match_syntax(ext_low, ext_high),
             "-j", "DNAT", "--to-destination",
             f"{target_ip}:{_dest_syntax(int_low, int_high)}",
             "-m", "comment", "--comment", comment])
    run_ipt(["-A", "FORWARD", "-p", proto, "-d", target_ip,
             "--dport", _match_syntax(int_low, int_high),
             "-j", "ACCEPT", "-m", "comment", "--comment", comment])
    log.info(f"Applied inbound: {proto} *:{ext_spec} → {target_ip}:{int_spec}  [{comment}]")


def remove_forward(target_ip, proto, ext_spec, int_spec, rule_id):
    comment = comment_tag(rule_id, proto, ext_spec)
    for table, chain in [("nat", "PREROUTING"), (None, "FORWARD")]:
        cmd = ["iptables"] + (["-t", table] if table else []) + ["-S", chain]
        result = subprocess.run(cmd, capture_output=True, text=True)
        for line in result.stdout.splitlines():
            if comment in line:
                del_args = line.replace("-A ", "-D ", 1).split()
                full = ["iptables"] + (["-t", table] if table else []) + del_args
                subprocess.run(full, capture_output=True)
    log.info(f"Removed inbound: {proto} *:{ext_spec} → {target_ip}:{int_spec}  [{comment}]")


def apply_outbound(source_ip, proto, source_port_spec, destination_ip, rule_id):
    """
    Pins the apparent source port of outbound traffic from source_ip to a
    fixed port (or pool of ports, if a range), using MASQUERADE so the
    egress IP is whatever this host's outbound interface already uses (no
    need to know/hardcode the public IP). Inserted at POSTROUTING position
    1 — see module docstring for why this MUST be an insert, not an append.
    """
    comment = comment_tag(rule_id, proto, source_port_spec)
    low, high = parse_port_spec(source_port_spec)

    args = ["-t", "nat", "-I", "POSTROUTING", "1", "-s", source_ip]
    if destination_ip:
        args += ["-d", destination_ip]
    args += ["-p", proto, "-j", "MASQUERADE", "--to-ports", _dest_syntax(low, high),
             "-m", "comment", "--comment", comment]
    run_ipt(args)
    dest_desc = destination_ip or "any destination"
    log.info(f"Applied outbound: {source_ip} → {dest_desc} src-port pinned to "
             f"{source_port_spec} [{comment}]")


def remove_outbound(source_ip, proto, source_port_spec, destination_ip, rule_id):
    comment = comment_tag(rule_id, proto, source_port_spec)
    result = subprocess.run(["iptables", "-t", "nat", "-S", "POSTROUTING"],
                             capture_output=True, text=True)
    for line in result.stdout.splitlines():
        if comment in line:
            del_args = line.replace("-A ", "-D ", 1).split()
            subprocess.run(["iptables", "-t", "nat"] + del_args, capture_output=True)
    log.info(f"Removed outbound: {source_ip} → {destination_ip or 'any'} [{comment}]")


def apply_entry(kind, target_ip, entry, rule_id):
    proto = entry[0]
    if kind == "inbound":
        _, ext_spec, int_spec = entry
        apply_forward(target_ip, proto, ext_spec, int_spec, rule_id)
    else:
        _, src_spec, dest_ip = entry
        apply_outbound(target_ip, proto, src_spec, dest_ip, rule_id)


def remove_entry(kind, target_ip, entry, rule_id):
    proto = entry[0]
    if kind == "inbound":
        _, ext_spec, int_spec = entry
        remove_forward(target_ip, proto, ext_spec, int_spec, rule_id)
    else:
        _, src_spec, dest_ip = entry
        remove_outbound(target_ip, proto, src_spec, dest_ip, rule_id)


def flush_all_portfwd_rules():
    log.info("Flushing all pritunl-portfwd iptables rules…")
    for table, chain in [("nat", "PREROUTING"), (None, "FORWARD"), ("nat", "POSTROUTING")]:
        cmd = ["iptables"] + (["-t", table] if table else []) + ["-S", chain]
        result = subprocess.run(cmd, capture_output=True, text=True)
        for line in result.stdout.splitlines():
            if COMMENT_PREFIX in line:
                del_args = line.replace("-A ", "-D ", 1).split()
                full = ["iptables"] + (["-t", table] if table else []) + del_args
                subprocess.run(full, capture_output=True)
    log.info("Flush complete.")


# --------------------------------------------------------------------- #
# Target resolution — shared by both directions. For inbound rules the
# resolved IP is the forwarding DESTINATION; for outbound rules it's the
# SOURCE whose egress traffic gets source-port-pinned. Same dynamic vs.
# persistent lifecycle rules apply either way (see README).
# --------------------------------------------------------------------- #

def resolve_target(rule, pritunl_clients, ipsec_status):
    etype = rule.get("endpoint_type", "pritunl")

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

    local_ports = get_local_listening_ports()
    foreign_nat = get_foreign_nat_rules()
    importable  = parse_importable_rules(foreign_nat)

    desired   = {}
    conflicts = []
    resolved  = {}

    for rule in rules:
        rid = rule["id"]
        direction = rule.get("direction", "inbound")
        info = resolve_target(rule, pritunl_clients, ipsec_status)
        resolved[rid] = info

        if not info["active"] or not info["target_ip"]:
            continue

        if direction == "inbound":
            try:
                ext_low, ext_high = parse_port_spec(rule["external_port"])
                parse_port_spec(rule["internal_port"])  # validate, value unused here
            except (ValueError, KeyError) as e:
                conflicts.append({"rule_id": rid, "proto": rule.get("proto", "?"),
                                   "port": str(rule.get("external_port")),
                                   "reason": f"invalid port spec: {e}"})
                continue

            entries = []
            for proto in expand_protos(rule["proto"]):
                reason = find_conflict(proto, ext_low, ext_high, local_ports, foreign_nat)
                if reason:
                    conflicts.append({"rule_id": rid, "proto": proto,
                                       "port": format_port_spec(ext_low, ext_high),
                                       "reason": reason})
                    continue
                entries.append([proto, rule["external_port"], rule["internal_port"]])

            if entries:
                desired[rid] = {"kind": "inbound", "target_ip": info["target_ip"], "entries": entries}

        elif direction == "outbound":
            try:
                parse_port_spec(rule["source_port"])  # validate
            except (ValueError, KeyError) as e:
                conflicts.append({"rule_id": rid, "proto": rule.get("proto", "?"),
                                   "port": str(rule.get("source_port")),
                                   "reason": f"invalid port spec: {e}"})
                continue

            destination_ip = rule.get("destination_ip") or None
            entries = [[proto, rule["source_port"], destination_ip]
                       for proto in expand_protos(rule["proto"])]
            desired[rid] = {"kind": "outbound", "target_ip": info["target_ip"], "entries": entries}

    # ---- Removals (stale entries, target IP changed, or kind changed) ----
    for rid, old in list(applied_state.items()):
        new = desired.get(rid)
        changed = (new is None) or (new["target_ip"] != old["target_ip"]) or (new["kind"] != old["kind"])
        old_entries = [tuple(e) for e in old["entries"]]
        if changed:
            for entry in old_entries:
                remove_entry(old["kind"], old["target_ip"], entry, rid)
        else:
            new_set = set(tuple(e) for e in new["entries"])
            for entry in old_entries:
                if entry not in new_set:
                    remove_entry(old["kind"], old["target_ip"], entry, rid)

    # ---- Additions ----
    for rid, info in desired.items():
        old = applied_state.get(rid)
        changed = (old is None) or (old["target_ip"] != info["target_ip"]) or (old["kind"] != info["kind"])
        old_set = set() if changed else set(tuple(e) for e in old["entries"])
        for entry in info["entries"]:
            if tuple(entry) not in old_set:
                apply_entry(info["kind"], info["target_ip"], entry, rid)

    applied_state = desired

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
        "importable": importable,
    })


# --------------------------------------------------------------------- #
# Traffic capture (tcpdump) management
# --------------------------------------------------------------------- #

def update_capture_status(session_id, state, message):
    status = load_capture_status()
    status[session_id] = {"state": state, "message": message,
                           "updated_at": datetime.utcnow().isoformat()}
    save_capture_status(status)


def build_bpf_filter(filt):
    """
    Builds a BPF filter expression from a strictly validated, structured
    dict. Every value is checked here regardless of what app.py already
    validated — this runs as root, so nothing reaches tcpdump's argv
    unchecked. Raises ValueError on anything invalid.
    """
    groups = []

    target_ip = filt.get("target_ip")
    if target_ip:
        if not valid_ip(target_ip):
            raise ValueError("invalid target_ip")
        groups.append(f"host {target_ip}")

    port_terms = []
    for p in (filt.get("ports") or []):
        if not valid_port_spec(p):
            raise ValueError(f"invalid port spec: {p}")
        lo, hi = parse_port_spec(p)
        port_terms.append(f"port {lo}" if lo == hi else f"portrange {lo}-{hi}")
    if port_terms:
        groups.append("(" + " or ".join(port_terms) + ")")

    proto = filt.get("proto")
    if proto in ("tcp", "udp"):
        groups.append(proto)

    extra_ip = filt.get("extra_ip")
    if extra_ip:
        if not valid_ip(extra_ip):
            raise ValueError("invalid extra_ip filter")
        groups.append(f"host {extra_ip}")

    extra_port = filt.get("extra_port")
    if extra_port:
        if not valid_port_spec(extra_port):
            raise ValueError("invalid extra_port filter")
        lo, hi = parse_port_spec(extra_port)
        groups.append(f"port {lo}" if lo == hi else f"portrange {lo}-{hi}")

    extra_proto = filt.get("extra_proto")
    if extra_proto in ("tcp", "udp"):
        groups.append(extra_proto)

    if not groups:
        raise ValueError("no usable filter criteria")
    return " and ".join(groups)


def start_capture(session_id, filt):
    os.makedirs(CAPTURE_LOG_DIR, exist_ok=True)
    try:
        os.chmod(CAPTURE_LOG_DIR, 0o755)
    except Exception:
        pass

    if shutil.which("tcpdump") is None:
        update_capture_status(session_id, "error",
                               "tcpdump is not installed on this host "
                               "(try: sudo apt install tcpdump)")
        return

    try:
        bpf = build_bpf_filter(filt)
    except ValueError as e:
        update_capture_status(session_id, "error", f"invalid filter: {e}")
        return

    log_path = capture_log_path(session_id)
    try:
        logf = open(log_path, "w")
        os.chmod(log_path, 0o644)
        proc = subprocess.Popen(
            ["tcpdump", "-i", "any", "-n", "-l", "-tttt", bpf],
            stdout=logf, stderr=subprocess.STDOUT
        )
    except Exception as e:
        update_capture_status(session_id, "error", f"failed to start tcpdump: {e}")
        return

    active_captures[session_id] = {
        "proc": proc, "started_at": time.time(),
        "log_path": log_path, "logf": logf,
    }
    update_capture_status(session_id, "running", f"capturing with filter: {bpf}")
    log.info(f"Capture {session_id} started: {bpf}")


def stop_capture(session_id, reason="stopped"):
    info = active_captures.pop(session_id, None)
    if not info:
        return
    try:
        info["proc"].terminate()
        try:
            info["proc"].wait(timeout=3)
        except subprocess.TimeoutExpired:
            info["proc"].kill()
    except Exception:
        pass
    try:
        info["logf"].close()
    except Exception:
        pass
    try:
        os.remove(info["log_path"])  # purely a live "peek" tool — no retained history
    except Exception:
        pass
    update_capture_status(session_id, "stopped", reason)
    log.info(f"Capture {session_id} stopped: {reason}")


def process_capture_requests():
    requests = load_capture_requests()
    if requests:
        for req in requests:
            action = req.get("action")
            sid = req.get("session_id")
            if not sid:
                continue
            if action == "start" and sid not in active_captures:
                start_capture(sid, req.get("filter", {}))
            elif action == "stop":
                stop_capture(sid, reason="stopped by user")
        save_capture_requests([])  # fire-and-forget, same pattern as import requests

    now = time.time()
    for sid, info in list(active_captures.items()):
        if now - info["started_at"] > MAX_CAPTURE_SECONDS:
            stop_capture(sid, reason=f"auto-stopped after {MAX_CAPTURE_SECONDS}s safety limit")


# --------------------------------------------------------------------- #
# Main loop
# --------------------------------------------------------------------- #

def main():
    log.info("pritunl-portfwd daemon starting")
    log.info(f"MongoDB: {MONGO_URI}{MONGO_DB}  |  Poll every {POLL_SECS}s")

    flush_all_portfwd_rules()
    os.makedirs(CAPTURE_LOG_DIR, exist_ok=True)

    cycle = 0
    ipsec_status = {}
    last_sync = 0.0

    while running:
        now = time.time()

        try:
            process_capture_requests()
        except Exception as e:
            log.error(f"Capture management error: {e}", exc_info=True)

        if now - last_sync >= POLL_SECS:
            try:
                pritunl_clients = get_connected_pritunl_clients()
                process_import_requests(pritunl_clients)
                rules = load_rules()
                if cycle % IPSEC_POLL_EVERY == 0:
                    ipsec_status = get_ipsec_status()
                sync(rules, pritunl_clients, ipsec_status)
            except Exception as e:
                log.error(f"Sync error: {e}", exc_info=True)
            cycle += 1
            last_sync = now

        time.sleep(0.5)

    for sid in list(active_captures.keys()):
        stop_capture(sid, reason="daemon shutting down")
    flush_all_portfwd_rules()
    log.info("Daemon stopped cleanly.")


if __name__ == "__main__":
    main()
