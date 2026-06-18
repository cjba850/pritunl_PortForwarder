#!/usr/bin/env python3
"""
pritunl-portfwd - Port Forward Manager for Pritunl VPN (Community Edition)
Web UI for managing iptables DNAT rules mapped to VPN client virtual IPs.
"""

import os
import json
import hashlib
import secrets
import logging
from datetime import datetime
from functools import wraps

from flask import (
    Flask, render_template, request, jsonify,
    session, redirect, url_for, flash
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

RULES_FILE   = os.environ.get("RULES_FILE",   "/etc/pritunl-portfwd/rules.json")
CONFIG_FILE  = os.environ.get("CONFIG_FILE",  "/etc/pritunl-portfwd/config.json")
MONGO_URI    = os.environ.get("MONGO_URI",    "mongodb://localhost:27017/")
MONGO_DB     = os.environ.get("MONGO_DB",     "pritunl")
LISTEN_HOST  = os.environ.get("LISTEN_HOST",  "127.0.0.1")
LISTEN_PORT  = int(os.environ.get("LISTEN_PORT", "8181"))


def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE) as f:
            return json.load(f)
    return {}


def save_config(cfg):
    os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
    with open(CONFIG_FILE, "w") as f:
        json.dump(cfg, f, indent=2)


# ---------------------------------------------------------------------------
# Rule persistence
# ---------------------------------------------------------------------------

def load_rules():
    if not os.path.exists(RULES_FILE):
        return []
    with open(RULES_FILE) as f:
        return json.load(f)


def save_rules(rules):
    os.makedirs(os.path.dirname(RULES_FILE), exist_ok=True)
    with open(RULES_FILE, "w") as f:
        json.dump(rules, f, indent=2)


# ---------------------------------------------------------------------------
# Pritunl MongoDB helpers
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
    """Return dict of user_id → client doc for currently connected clients."""
    db = get_mongo_db()
    if db is None:
        return {}
    try:
        return {
            str(c.get("user_id", c.get("user", ""))): c
            for c in db.clients.find()
        }
    except Exception as e:
        log.warning(f"Failed to query clients: {e}")
        return {}


def get_pritunl_users():
    """Return list of {id, name, org} for all Pritunl users."""
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
            users.append({
                "id": str(u["_id"]),
                "name": u.get("name", "unknown"),
                "org": org_name
            })
        return sorted(users, key=lambda x: x["name"].lower())
    except Exception as e:
        log.warning(f"Failed to query users: {e}")
        return []


def get_server_info():
    """Return list of VPN servers and their networks."""
    db = get_mongo_db()
    if db is None:
        return []
    try:
        servers = []
        for s in db.servers.find({}, {"name": 1, "network": 1, "protocol": 1, "port": 1}):
            servers.append({
                "id": str(s["_id"]),
                "name": s.get("name", "unknown"),
                "network": s.get("network", ""),
                "protocol": s.get("protocol", "udp"),
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
    db = get_mongo_db()
    active = get_active_clients()
    rules = load_rules()
    active_rule_count = sum(1 for r in rules if r["user_id"] in active)
    return jsonify({
        "mongodb": db is not None,
        "rules_total": len(rules),
        "rules_active": active_rule_count,
        "clients_online": len(active)
    })


@app.route("/api/rules", methods=["GET"])
@login_required
def api_get_rules():
    rules = load_rules()
    active = get_active_clients()
    enriched = []
    for rule in rules:
        r = dict(rule)
        client = active.get(rule["user_id"])
        r["active"] = client is not None
        r["virtual_ip"] = None
        if client:
            # virtual_address may be like "10.x.x.x/24" — strip prefix
            vip = client.get("virtual_address") or client.get("real_address", "")
            r["virtual_ip"] = vip.split("/")[0] if vip else None
        enriched.append(r)
    return jsonify(enriched)


@app.route("/api/rules", methods=["POST"])
@login_required
def api_add_rule():
    data = request.json or {}
    errors = []

    user_id      = str(data.get("user_id", "")).strip()
    user_name    = str(data.get("user_name", "")).strip()
    proto        = str(data.get("proto", "")).lower().strip()
    ext_port     = data.get("external_port")
    int_port     = data.get("internal_port")
    comment      = str(data.get("comment", "")).strip()[:120]

    if not user_id:
        errors.append("user_id is required")
    if proto not in ("tcp", "udp", "both"):
        errors.append("proto must be tcp, udp, or both")
    try:
        ext_port = int(ext_port)
        assert 1 <= ext_port <= 65535
    except Exception:
        errors.append("external_port must be 1–65535")
    try:
        int_port = int(int_port)
        assert 1 <= int_port <= 65535
    except Exception:
        errors.append("internal_port must be 1–65535")

    if errors:
        return jsonify(error="; ".join(errors)), 400

    rules = load_rules()

    # Port conflict check (same proto + ext port already used)
    protos_to_check = ["tcp", "udp"] if proto == "both" else [proto]
    for r in rules:
        r_protos = ["tcp", "udp"] if r["proto"] == "both" else [r["proto"]]
        if r["external_port"] == ext_port and set(protos_to_check) & set(r_protos):
            return jsonify(
                error=f"External port {ext_port}/{proto} is already assigned to '{r['user_name']}'"
            ), 409

    new_rule = {
        "id":            secrets.token_hex(6),
        "user_id":       user_id,
        "user_name":     user_name,
        "proto":         proto,
        "external_port": ext_port,
        "internal_port": int_port,
        "comment":       comment,
        "created_at":    datetime.utcnow().isoformat()
    }
    rules.append(new_rule)
    save_rules(rules)
    log.info(f"Rule added: {proto} :{ext_port}→{user_name}:{int_port}")
    return jsonify(new_rule), 201


@app.route("/api/rules/<rule_id>", methods=["PATCH"])
@login_required
def api_update_rule(rule_id):
    data = request.json or {}
    rules = load_rules()
    target = next((r for r in rules if r["id"] == rule_id), None)
    if not target:
        return jsonify(error="Rule not found"), 404

    allowed_fields = {"proto", "external_port", "internal_port", "comment", "user_id", "user_name"}
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
