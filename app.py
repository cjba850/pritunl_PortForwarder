#!/usr/bin/env python3
"""
pritunl-portfwd - Port Forward Manager for Pritunl VPN (Community Edition)
Web UI for managing iptables DNAT rules targeting Pritunl VPN clients,
static/local IPs, or IPsec (StrongSwan) tunnel endpoints.
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
    gen_rule_id, valid_ip, valid_port,
    get_local_listening_ports,
    VALID_ENDPOINT_TYPES, VALID_PROTOS,
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


@app.route("/api/rules", methods=["POST"])
@login_required
def api_add_rule():
    data = request.json or {}
    errors = []

    etype = str(data.get("endpoint_type", "pritunl")).strip()
    if etype not in VALID_ENDPOINT_TYPES:
        errors.append("endpoint_type must be one of: pritunl, static, ipsec")

    proto = str(data.get("proto", "")).lower().strip()
    if proto not in VALID_PROTOS:
        errors.append("proto must be tcp, udp, or both")

    ext_port_raw = data.get("external_port")
    int_port_raw = data.get("internal_port")
    if not valid_port(ext_port_raw):
        errors.append("external_port must be 1–65535")
    if not valid_port(int_port_raw):
        errors.append("internal_port must be 1–65535")

    comment = str(data.get("comment", "")).strip()[:120]

    user_id = user_name = target_ip = tunnel_name = label = None

    if etype == "pritunl":
        user_id = str(data.get("user_id", "")).strip()
        user_name = str(data.get("user_name", "")).strip()
        if not user_id:
            errors.append("user_id is required for endpoint_type 'pritunl'")

    elif etype == "static":
        target_ip = str(data.get("target_ip", "")).strip()
        label = str(data.get("label", "")).strip()[:60]
        if not valid_ip(target_ip):
            errors.append("a valid target_ip is required for endpoint_type 'static'")

    elif etype == "ipsec":
        target_ip = str(data.get("target_ip", "")).strip()
        tunnel_name = str(data.get("tunnel_name", "")).strip()
        label = str(data.get("label", "")).strip()[:60]
        if not valid_ip(target_ip):
            errors.append("a valid target_ip is required for endpoint_type 'ipsec'")
        if not tunnel_name:
            errors.append("tunnel_name is required for endpoint_type 'ipsec'")

    if errors:
        return jsonify(error="; ".join(errors)), 400

    ext_port = int(ext_port_raw)
    int_port = int(int_port_raw)
    rules = load_rules()
    protos_to_check = ["tcp", "udp"] if proto == "both" else [proto]

    # Conflict 1: another rule in our own store already uses this port/proto
    for r in rules:
        r_protos = ["tcp", "udp"] if r["proto"] == "both" else [r["proto"]]
        if r["external_port"] == ext_port and set(protos_to_check) & set(r_protos):
            return jsonify(error=f"External port {ext_port}/{proto} is already "
                                  f"assigned to another rule"), 409

    # Conflict 2: immediate, best-effort check against locally bound ports.
    # (Deeper checks against pre-existing, non-portfwd iptables rules run
    # in the daemon and surface as a "conflict" badge within ~10s.)
    local_ports = get_local_listening_ports()
    for p in protos_to_check:
        if ext_port in local_ports.get(p, set()):
            return jsonify(error=f"Port {ext_port}/{p} is already in use by a "
                                  f"local service on this host — choose a "
                                  f"different external port"), 409

    new_rule = {
        "id": gen_rule_id(),
        "endpoint_type": etype,
        "proto": proto,
        "external_port": ext_port,
        "internal_port": int_port,
        "comment": comment,
        "created_at": datetime.utcnow().isoformat(),
    }
    if etype == "pritunl":
        new_rule["user_id"] = user_id
        new_rule["user_name"] = user_name
    elif etype == "static":
        new_rule["target_ip"] = target_ip
        new_rule["label"] = label
    elif etype == "ipsec":
        new_rule["target_ip"] = target_ip
        new_rule["tunnel_name"] = tunnel_name
        new_rule["label"] = label

    rules.append(new_rule)
    save_rules(rules)
    log.info(f"Rule added ({etype}): {proto} :{ext_port} -> :{int_port}")
    return jsonify(new_rule), 201


@app.route("/api/rules/<rule_id>", methods=["PATCH"])
@login_required
def api_update_rule(rule_id):
    data = request.json or {}
    rules = load_rules()
    target = next((r for r in rules if r["id"] == rule_id), None)
    if not target:
        return jsonify(error="Rule not found"), 404

    # Editing is intentionally limited to cosmetic/port fields. To change
    # endpoint_type itself, delete and recreate the rule - this keeps
    # validation logic in one place (api_add_rule) instead of duplicated.
    allowed_fields = {
        "proto", "external_port", "internal_port", "comment",
        "user_id", "user_name", "target_ip", "tunnel_name", "label"
    }
    for k, v in data.items():
        if k in allowed_fields:
            target[k] = v
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
    web UI never shells out to swanctl/ipsec itself). Empty list just
    means the daemon hasn't seen any StrongSwan connections (or hasn't
    run yet) - the IPsec endpoint type's tunnel_name field still accepts
    free text, so this is a convenience suggestion list, not a hard
    requirement.
    """
    status = load_status()
    tunnels = status.get("ipsec_tunnels", {})
    return jsonify([{"name": k, "status": v.get("status", "unknown")} for k, v in tunnels.items()])


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
