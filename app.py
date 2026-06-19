#!/usr/bin/env python3
"""
pritunl-portfwd - Port Forward Manager for Pritunl VPN (Community Edition)
Web UI for managing iptables DNAT rules targeting Pritunl VPN clients,
static/local IPs, or IPsec (StrongSwan) tunnel endpoints — with single-port
or port-range mappings, and discovery/import of pre-existing iptables rules.
"""

import os
import hashlib
import secrets
import logging
from datetime import datetime
from functools import wraps

from flask import (
    Flask, render_template, request, jsonify,
    session, redirect, url_for
)

from common import (
    load_rules, save_rules, load_status,
    load_import_requests, save_import_requests,
    load_capture_requests, save_capture_requests,
    load_capture_status, capture_log_path,
    gen_rule_id, gen_session_id, valid_ip,
    parse_port_spec, valid_port_spec, ranges_compatible, ranges_overlap,
    expand_protos, get_local_listening_ports,
    VALID_ENDPOINT_TYPES, VALID_PROTOS, VALID_DIRECTIONS,
)

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("/var/log/pritunl-portfwd.log"),
        logging.StreamHandler()
    ]
)
log = logging.getLogger("portfwd")

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

CONFIG_FILE  = os.environ.get("CONFIG_FILE",  "/etc/pritunl-portfwd/config.json")
MONGO_URI    = os.environ.get("MONGO_URI",    "mongodb://localhost:27017/")
MONGO_DB     = os.environ.get("MONGO_DB",     "pritunl")
LISTEN_HOST  = os.environ.get("LISTEN_HOST",  "127.0.0.1")
LISTEN_PORT  = int(os.environ.get("LISTEN_PORT", "8181"))

import json as _json

def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE) as f:
            return _json.load(f)
    return {}


def save_config(cfg):
    os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
    with open(CONFIG_FILE, "w") as f:
        _json.dump(cfg, f, indent=2)


# ---------------------------------------------------------------------------
# Pritunl MongoDB helpers (used for dropdown population only - live
# rule state comes from the daemon's status.json, not from here)
# ---------------------------------------------------------------------------

def get_mongo_db():
    try:
        import pymongo
        client = pymongo.MongoClient(MONGO_URI, serverSelectionTimeoutMS=2000)
        client.server_info()
        return client[MONGO_DB]
    except Exception as e:
        log.warning(f"MongoDB unavailable: {e}")
        return None


def get_active_clients():
    db = get_mongo_db()
    if db is None:
        return {}
    try:
        return {str(c.get("user_id", c.get("user", ""))): c for c in db.clients.find()}
    except Exception as e:
        log.warning(f"Failed to query clients: {e}")
        return {}


def get_pritunl_users():
    db = get_mongo_db()
    if db is None:
        return []
    try:
        users = []
        for u in db.users.find({}, {"name": 1, "org_id": 1}):
            org_name = ""
            if u.get("org_id"):
                org = db.organizations.find_one({"_id": u["org_id"]}, {"name": 1})
                org_name = org["name"] if org else ""
            users.append({"id": str(u["_id"]), "name": u.get("name", "unknown"), "org": org_name})
        return sorted(users, key=lambda x: x["name"].lower())
    except Exception as e:
        log.warning(f"Failed to query users: {e}")
        return []


def get_server_info():
    db = get_mongo_db()
    if db is None:
        return []
    try:
        servers = []
        for s in db.servers.find({}, {"name": 1, "network": 1, "protocol": 1, "port": 1}):
            servers.append({
                "id": str(s["_id"]), "name": s.get("name", "unknown"),
                "network": s.get("network", ""), "protocol": s.get("protocol", "udp"),
                "port": s.get("port", 1194)
            })
        return servers
    except Exception as e:
        log.warning(f"Failed to query servers: {e}")
        return []


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("authenticated"):
            if request.is_json:
                return jsonify(error="Unauthorized"), 401
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


def check_password(password):
    cfg = load_config()
    stored = cfg.get("password_hash")
    if not stored:
        return False
    return hashlib.sha256(password.encode()).hexdigest() == stored


# ---------------------------------------------------------------------------
# Routes — Auth
# ---------------------------------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    cfg = load_config()
    if not cfg.get("password_hash"):
        return redirect(url_for("setup"))
    if request.method == "POST":
        pw = request.form.get("password", "")
        if check_password(pw):
            session["authenticated"] = True
            session.permanent = True
            log.info(f"Admin login from {request.remote_addr}")
            return redirect(url_for("index"))
        log.warning(f"Failed login attempt from {request.remote_addr}")
        return render_template("login.html", error="Invalid password")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/setup", methods=["GET", "POST"])
def setup():
    cfg = load_config()
    if cfg.get("password_hash"):
        return redirect(url_for("login"))
    if request.method == "POST":
        pw = request.form.get("password", "")
        pw2 = request.form.get("password2", "")
        if len(pw) < 8:
            return render_template("setup.html", error="Password must be at least 8 characters")
        if pw != pw2:
            return render_template("setup.html", error="Passwords do not match")
        cfg["password_hash"] = hashlib.sha256(pw.encode()).hexdigest()
        cfg["created_at"] = datetime.utcnow().isoformat()
        save_config(cfg)
        log.info("Initial admin password configured")
        return redirect(url_for("login"))
    return render_template("setup.html")


# ---------------------------------------------------------------------------
# Routes — UI
# ---------------------------------------------------------------------------

@app.route("/")
@login_required
def index():
    return render_template("index.html")


# ---------------------------------------------------------------------------
# Routes — API
# ---------------------------------------------------------------------------

@app.route("/api/status")
@login_required
def api_status():
    status = load_status()
    rules = load_rules()
    active_count = sum(1 for r in status.get("rules", {}).values() if r.get("applied"))
    return jsonify({
        "mongodb": get_mongo_db() is not None,
        "daemon_seen": bool(status),
        "last_update": status.get("updated_at"),
        "rules_total": len(rules),
        "rules_active": active_count,
        "conflicts": len(status.get("conflicts", [])),
        "importable": len(status.get("importable", [])),
        "clients_online": len(get_active_clients()),
    })


@app.route("/api/rules", methods=["GET"])
@login_required
def api_get_rules():
    rules = load_rules()
    status = load_status()
    status_rules = status.get("rules", {})
    conflicts = {c["rule_id"]: c["reason"] for c in status.get("conflicts", [])}

    enriched = []
    for rule in rules:
        r = dict(rule)
        s = status_rules.get(rule["id"], {})
        r["target_ip"] = s.get("target_ip")
        r["active"]    = s.get("applied", False)
        r["reason"]    = s.get("reason", "unknown")
        if rule["id"] in conflicts:
            r["conflict"] = conflicts[rule["id"]]
        enriched.append(r)
    return jsonify(enriched)


def _validate_inbound_ports(data, errors):
    """external_port/internal_port, range-aware. Returns (ext_spec, int_spec)
    as normalized strings, or (None, None) if invalid."""
    ext_raw = data.get("external_port")
    int_raw = data.get("internal_port")

    if not valid_port_spec(ext_raw):
        errors.append("external_port must be a port (1-65535) or a range like 8000-8010")
    if not valid_port_spec(int_raw):
        errors.append("internal_port must be a port (1-65535) or a range like 8000-8010")
    if errors:
        return None, None

    ext_low, ext_high = parse_port_spec(ext_raw)
    int_low, int_high = parse_port_spec(int_raw)

    if not ranges_compatible(ext_low, ext_high, int_low, int_high):
        errors.append(
            f"external range ({ext_low}-{ext_high}) and internal range "
            f"({int_low}-{int_high}) aren't compatible — ranges on both "
            f"sides must either match in size, or one side must be a "
            f"single port"
        )
        return None, None

    return str(ext_raw).strip(), str(int_raw).strip()


def _find_outbound_duplicate(rules, etype, user_id, target_ip, destination_ip, protos_to_check, src_low, src_high):
    """
    Cross-rule duplicate check for outbound rules: flags another existing
    outbound rule that pins the same source endpoint to an overlapping
    source port for an overlapping destination + protocol. Unlike inbound
    conflicts, this doesn't need root/iptables - it's purely a check
    against our own stored config, since outbound rules are always
    inserted at the top of POSTROUTING (no shadowing-by-other-rules risk
    to detect).
    """
    for r in rules:
        if r.get("direction") != "outbound":
            continue
        # Same source endpoint?
        same_source = False
        if etype == "pritunl" and r.get("endpoint_type") == "pritunl":
            same_source = r.get("user_id") == user_id
        elif etype in ("static", "ipsec") and r.get("endpoint_type") in ("static", "ipsec"):
            same_source = r.get("target_ip") == target_ip
        if not same_source:
            continue

        r_dest = r.get("destination_ip") or None
        if destination_ip and r_dest and destination_ip != r_dest:
            continue  # different specific destinations - no overlap

        r_protos = ["tcp", "udp"] if r.get("proto") == "both" else [r.get("proto")]
        if not (set(protos_to_check) & set(r_protos)):
            continue

        try:
            r_low, r_high = parse_port_spec(r.get("source_port"))
        except (ValueError, TypeError):
            continue
        if ranges_overlap(src_low, src_high, r_low, r_high):
            return r
    return None


def _validate_rule_payload(data, etype, direction, other_rules):
    """
    Validates and normalizes the editable fields for a rule — shared by
    both rule creation (POST) and rule editing (PATCH), so an edit can't
    silently bypass the same conflict/overlap/format checks a new rule
    goes through. `other_rules` should be every OTHER rule already in
    rules.json (the full list for a create; the list with the rule being
    edited excluded, for an update) — overlap/duplicate checks run
    against this set.

    Returns (fields_dict, None, None) on success, or
    (None, error_message, status_code) on failure. status_code is 409
    for a genuine conflict/overlap with something else, 400 for a plain
    invalid-input problem.
    """
    errors = []

    proto = str(data.get("proto", "")).lower().strip()
    if proto not in VALID_PROTOS:
        errors.append("proto must be tcp, udp, or both")

    comment = str(data.get("comment", "")).strip()[:120]
    fields = {"proto": proto, "comment": comment}

    if etype == "pritunl":
        user_id = str(data.get("user_id", "")).strip()
        if not user_id:
            errors.append("user_id is required for endpoint_type 'pritunl'")
        fields["user_id"] = user_id
        fields["user_name"] = str(data.get("user_name", "")).strip()
    elif etype == "static":
        target_ip = str(data.get("target_ip", "")).strip()
        if not valid_ip(target_ip):
            errors.append("a valid target_ip is required for endpoint_type 'static'")
        fields["target_ip"] = target_ip
        fields["label"] = str(data.get("label", "")).strip()[:60]
    elif etype == "ipsec":
        target_ip = str(data.get("target_ip", "")).strip()
        tunnel_name = str(data.get("tunnel_name", "")).strip()
        if not valid_ip(target_ip):
            errors.append("a valid target_ip is required for endpoint_type 'ipsec'")
        if not tunnel_name:
            errors.append("tunnel_name is required for endpoint_type 'ipsec'")
        fields["target_ip"] = target_ip
        fields["tunnel_name"] = tunnel_name
        fields["label"] = str(data.get("label", "")).strip()[:60]

    if errors:
        return None, "; ".join(errors), 400

    protos_to_check = ["tcp", "udp"] if proto == "both" else [proto]

    if direction == "inbound":
        ext_spec, int_spec = _validate_inbound_ports(data, errors)
        if errors:
            return None, "; ".join(errors), 400

        ext_low, ext_high = parse_port_spec(ext_spec)

        for r in other_rules:
            if r.get("direction", "inbound") != "inbound":
                continue
            try:
                r_low, r_high = parse_port_spec(r["external_port"])
            except (ValueError, KeyError):
                continue
            r_protos = ["tcp", "udp"] if r["proto"] == "both" else [r["proto"]]
            if set(protos_to_check) & set(r_protos) and ranges_overlap(ext_low, ext_high, r_low, r_high):
                return None, (f"External port(s) {ext_spec}/{proto} overlap "
                               f"with an existing rule ({r['external_port']})"), 409

        local_ports = get_local_listening_ports()
        for p in protos_to_check:
            local_set = local_ports.get(p, set())
            if any(port in local_set for port in range(ext_low, ext_high + 1)):
                return None, (f"Port(s) {ext_spec}/{p} are already in use by a "
                               f"local service on this host — choose a "
                               f"different external port"), 409

        fields["external_port"] = ext_spec
        fields["internal_port"] = int_spec

    else:  # outbound
        source_port_raw = data.get("source_port")
        destination_ip = str(data.get("destination_ip", "")).strip() or None
        if not valid_port_spec(source_port_raw):
            errors.append("source_port must be a port (1-65535) or a range like 8000-8010")
        if destination_ip and not valid_ip(destination_ip):
            errors.append("destination_ip must be a valid IP if provided")
        if errors:
            return None, "; ".join(errors), 400

        src_low, src_high = parse_port_spec(source_port_raw)
        dup = _find_outbound_duplicate(other_rules, etype, fields.get("user_id"), fields.get("target_ip"),
                                        destination_ip, protos_to_check, src_low, src_high)
        if dup:
            return None, (f"This overlaps with an existing outbound rule "
                           f"(source port {dup.get('source_port')}, "
                           f"destination {dup.get('destination_ip') or 'any'})"), 409

        fields["source_port"] = str(source_port_raw).strip()
        fields["destination_ip"] = destination_ip

    return fields, None, None


@app.route("/api/rules", methods=["POST"])
@login_required
def api_add_rule():
    data = request.json or {}

    etype = str(data.get("endpoint_type", "pritunl")).strip()
    if etype not in VALID_ENDPOINT_TYPES:
        return jsonify(error="endpoint_type must be one of: pritunl, static, ipsec"), 400

    direction = str(data.get("direction", "inbound")).strip()
    if direction not in VALID_DIRECTIONS:
        return jsonify(error="direction must be 'inbound' or 'outbound'"), 400

    rules = load_rules()
    fields, error, status = _validate_rule_payload(data, etype, direction, rules)
    if error:
        return jsonify(error=error), status

    new_rule = {
        "id": gen_rule_id(),
        "endpoint_type": etype,
        "direction": direction,
        "created_at": datetime.utcnow().isoformat(),
        **fields,
    }
    rules.append(new_rule)
    save_rules(rules)
    log.info(f"Rule added ({etype}, {direction}): {new_rule['proto']} "
             f"{new_rule.get('external_port') or new_rule.get('source_port')}")
    return jsonify(new_rule), 201


@app.route("/api/rules/<rule_id>", methods=["PATCH"])
@login_required
def api_update_rule(rule_id):
    data = request.json or {}
    rules = load_rules()
    target = next((r for r in rules if r["id"] == rule_id), None)
    if not target:
        return jsonify(error="Rule not found"), 404

    # endpoint_type and direction are intentionally fixed for the life of
    # a rule — changing either changes which fields even apply (a totally
    # different field set), so delete-and-recreate is the supported way
    # to do that. Everything else (ports, proto, comment, and the
    # endpoint's own identity fields) goes through the exact same
    # validation a new rule would, just with this rule excluded from the
    # overlap/conflict checks so it doesn't flag itself.
    etype = target["endpoint_type"]
    direction = target.get("direction", "inbound")

    merged = dict(target)
    merged.update(data)
    other_rules = [r for r in rules if r["id"] != rule_id]

    fields, error, status = _validate_rule_payload(merged, etype, direction, other_rules)
    if error:
        return jsonify(error=error), status

    target.update(fields)
    target["updated_at"] = datetime.utcnow().isoformat()
    save_rules(rules)
    log.info(f"Rule updated: {rule_id}")
    return jsonify(target)


@app.route("/api/rules/<rule_id>", methods=["DELETE"])
@login_required
def api_delete_rule(rule_id):
    rules = load_rules()
    original = len(rules)
    rules = [r for r in rules if r["id"] != rule_id]
    if len(rules) == original:
        return jsonify(error="Rule not found"), 404
    save_rules(rules)
    log.info(f"Rule deleted: {rule_id}")
    return jsonify(ok=True)


SNAPSHOT_FORMAT = "pritunl-portfwd-rules-snapshot"
SNAPSHOT_SCHEMA_VERSION = 1


@app.route("/api/rules/export")
@login_required
def api_export_rules():
    """
    Downloadable backup of every current rule definition, wrapped with
    enough metadata to be recognized and safely re-validated on import.
    This is a config snapshot only - it doesn't capture *live* state
    (which Pritunl user happens to be connected right now, current tunnel
    health, etc.), since that's inherently a moving target; re-importing
    it re-creates the same rule definitions, which the daemon then applies
    according to whatever's actually live at restore time.
    """
    rules = load_rules()
    snapshot = {
        "format": SNAPSHOT_FORMAT,
        "schema_version": SNAPSHOT_SCHEMA_VERSION,
        "exported_at": datetime.utcnow().isoformat(),
        "rule_count": len(rules),
        "rules": rules,
    }
    ts = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    resp = jsonify(snapshot)
    resp.headers["Content-Disposition"] = f'attachment; filename="pritunl-portfwd-rules-{ts}.json"'
    return resp


@app.route("/api/rules/restore", methods=["POST"])
@login_required
def api_restore_rules():
    """
    Restores rules from a previously exported snapshot. Every rule in the
    file is re-validated exactly as if it were being added by hand (port
    format, range compatibility, conflict/overlap checks) - anything that
    doesn't pass is skipped and reported, rather than blocking the whole
    restore or being silently applied unchecked. Rule IDs are always
    regenerated, so re-importing the same file twice (or importing it on
    a different host) never collides with anything by coincidence.

    mode "merge"   - keep existing rules, add the snapshot's rules to them
    mode "replace" - wipe existing rules first (the web UI confirms this
                      with the admin before sending the request)
    """
    body = request.json or {}
    mode = str(body.get("mode", "merge")).strip()
    if mode not in ("merge", "replace"):
        return jsonify(error="mode must be 'merge' or 'replace'"), 400

    snapshot = body.get("snapshot")
    if not isinstance(snapshot, dict) or snapshot.get("format") != SNAPSHOT_FORMAT:
        return jsonify(error="This doesn't look like a pritunl-portfwd rules export file"), 400

    incoming = snapshot.get("rules")
    if not isinstance(incoming, list):
        return jsonify(error="Snapshot file has no rules list"), 400

    existing = [] if mode == "replace" else load_rules()
    applied = []
    skipped = []

    for raw in incoming:
        if not isinstance(raw, dict):
            skipped.append({"rule": str(raw)[:80], "reason": "not a valid rule object"})
            continue

        etype = str(raw.get("endpoint_type", "")).strip()
        direction = str(raw.get("direction", "inbound")).strip()
        port_hint = raw.get("external_port") or raw.get("source_port") or "?"
        summary = f"{etype or '?'}/{direction} :{port_hint}"

        if etype not in VALID_ENDPOINT_TYPES:
            skipped.append({"rule": summary, "reason": "invalid or missing endpoint_type"})
            continue
        if direction not in VALID_DIRECTIONS:
            skipped.append({"rule": summary, "reason": "invalid direction"})
            continue

        # Validate against both the untouched pre-existing rules (merge
        # mode only) and whatever's already been accepted from this same
        # snapshot, so duplicates *within* the file are caught too.
        fields, error, _status = _validate_rule_payload(raw, etype, direction, existing + applied)
        if error:
            skipped.append({"rule": summary, "reason": error})
            continue

        applied.append({
            "id": gen_rule_id(),
            "endpoint_type": etype,
            "direction": direction,
            "created_at": datetime.utcnow().isoformat(),
            **fields,
        })

    save_rules(existing + applied)
    log.info(f"Rules restored ({mode}): {len(applied)} applied, {len(skipped)} skipped, "
             f"{len(incoming)} total in snapshot")
    return jsonify(applied=len(applied), skipped=skipped, total=len(incoming))


@app.route("/api/users")
@login_required
def api_users():
    return jsonify(get_pritunl_users())


@app.route("/api/servers")
@login_required
def api_servers():
    return jsonify(get_server_info())


@app.route("/api/active-clients")
@login_required
def api_active_clients():
    active = get_active_clients()
    result = []
    for uid, c in active.items():
        vip = c.get("virtual_address") or c.get("real_address", "")
        result.append({
            "user_id": uid,
            "virtual_ip": vip.split("/")[0] if vip else None,
            "remote_ip": c.get("real_address", "").split(":")[0]
        })
    return jsonify(result)


@app.route("/api/ipsec-tunnels")
@login_required
def api_ipsec_tunnels():
    """
    Tunnel list/health as last observed by the daemon (root process - the
    web UI never shells out to swanctl/ipsec itself).
    """
    status = load_status()
    tunnels = status.get("ipsec_tunnels", {})
    return jsonify([{"name": k, "status": v.get("status", "unknown")} for k, v in tunnels.items()])


@app.route("/api/importable-rules")
@login_required
def api_importable_rules():
    """
    Pre-existing iptables DNAT rules not created by this tool, as last
    discovered by the daemon. The web UI never reads iptables directly.
    """
    status = load_status()
    return jsonify(status.get("importable", []))


@app.route("/api/import-rule", methods=["POST"])
@login_required
def api_import_rule():
    """
    Queues an import request for the root daemon to actually act on (only
    the daemon can delete/re-tag real iptables rules). Processed on the
    daemon's next sync cycle (~10s) - the imported rule then shows up
    through the normal /api/rules listing, fully editable from then on.
    """
    data = request.json or {}
    rid = str(data.get("id", "")).strip()
    if not rid:
        return jsonify(error="id is required"), 400

    requests_list = load_import_requests()
    if not any(r.get("id") == rid for r in requests_list):
        requests_list.append({"id": rid, "requested_at": datetime.utcnow().isoformat()})
        save_import_requests(requests_list)
    log.info(f"Import requested for foreign rule {rid}")
    return jsonify(ok=True, message="Import queued — will be applied within ~10s"), 202


@app.route("/api/capture/start", methods=["POST"])
@login_required
def api_capture_start():
    """
    Starts a live tcpdump "peek" for a given rule. Filter fields relevant
    to the rule itself (target IP, ports, proto) are taken from the rule's
    own stored definition and the daemon's live status — not from the
    request body — only the optional narrowing filters (extra_ip/port/
    proto) come from the browser, and those are validated here AND again
    by the root daemon before ever reaching tcpdump's argv.
    """
    data = request.json or {}
    rule_id = str(data.get("rule_id", "")).strip()
    rules = load_rules()
    rule = next((r for r in rules if r["id"] == rule_id), None)
    if not rule:
        return jsonify(error="Rule not found"), 404

    status = load_status()
    target_ip = status.get("rules", {}).get(rule_id, {}).get("target_ip")
    if not target_ip:
        return jsonify(error="This rule has no active target IP right now "
                              "(offline/disconnected) — nothing to capture"), 400

    direction = rule.get("direction", "inbound")
    if direction == "inbound":
        ports = [rule.get("external_port"), rule.get("internal_port")]
    else:
        ports = [rule.get("source_port")]
    ports = [p for p in ports if p]

    extra_ip = str(data.get("extra_ip", "")).strip()
    extra_port = str(data.get("extra_port", "")).strip()
    extra_proto = str(data.get("extra_proto", "")).strip().lower()

    if extra_ip and not valid_ip(extra_ip):
        return jsonify(error="Invalid extra IP filter"), 400
    if extra_port and not valid_port_spec(extra_port):
        return jsonify(error="Invalid extra port filter"), 400
    if extra_proto and extra_proto not in ("tcp", "udp"):
        return jsonify(error="Extra protocol filter must be tcp or udp"), 400

    session_id = gen_session_id()
    filt = {
        "target_ip": target_ip,
        "proto": rule.get("proto"),
        "ports": ports,
        "extra_ip": extra_ip or None,
        "extra_port": extra_port or None,
        "extra_proto": extra_proto or None,
    }

    requests_list = load_capture_requests()
    requests_list.append({"action": "start", "session_id": session_id, "filter": filt})
    save_capture_requests(requests_list)

    log.info(f"Capture requested for rule {rule_id} (session {session_id})")
    return jsonify(session_id=session_id), 202


@app.route("/api/capture/<session_id>/log")
@login_required
def api_capture_log(session_id):
    """
    Polled by the browser (~1s) while the inspect modal is open. Returns
    a full snapshot rather than an incremental tail — capture sessions are
    short-lived and filtered, so this stays cheap; this is a live "peek",
    not a packet-firehose tool.
    """
    status = load_capture_status().get(session_id, {})
    lines = []
    try:
        with open(capture_log_path(session_id)) as f:
            lines = f.readlines()[-500:]
    except FileNotFoundError:
        pass
    return jsonify(
        state=status.get("state", "unknown"),
        message=status.get("message", ""),
        lines=[l.rstrip("\n") for l in lines],
    )


@app.route("/api/capture/stop", methods=["POST"])
@login_required
def api_capture_stop():
    data = request.json or {}
    session_id = str(data.get("session_id", "")).strip()
    if not session_id:
        return jsonify(error="session_id is required"), 400
    requests_list = load_capture_requests()
    requests_list.append({"action": "stop", "session_id": session_id})
    save_capture_requests(requests_list)
    return jsonify(ok=True)


@app.route("/api/change-password", methods=["POST"])
@login_required
def api_change_password():
    data = request.json or {}
    current = data.get("current", "")
    new_pw  = data.get("new", "")
    if not check_password(current):
        return jsonify(error="Current password is incorrect"), 403
    if len(new_pw) < 8:
        return jsonify(error="New password must be at least 8 characters"), 400
    cfg = load_config()
    cfg["password_hash"] = hashlib.sha256(new_pw.encode()).hexdigest()
    save_config(cfg)
    log.info("Admin password changed")
    return jsonify(ok=True)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app.run(host=LISTEN_HOST, port=LISTEN_PORT, debug=False)
