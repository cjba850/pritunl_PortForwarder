# pritunl-portfwd

**Port Forward Manager for Pritunl VPN — Community Edition**

A self-hosted web UI and background daemon that lets you define TCP/UDP port forward rules on a Pritunl VPN server, forwarding traffic to:

- **Pritunl VPN users** — forwards to whatever virtual IP Pritunl currently has the user on (dynamic, tracked live)
- **Static / local IPs** — forwards to any fixed IP reachable from the server (a LAN device, another VLAN, anything routable)
- **IPsec tunnel endpoints** — forwards to a fixed IP reachable through a named StrongSwan/IPsec connection, with tunnel health surfaced in the UI

Before any rule is applied, it's checked against ports already in use locally and against pre-existing iptables rules, so it won't silently steal traffic from another service.

Works with **Pritunl Community Edition** — no Enterprise subscription required.

---

## Screenshots

The web UI uses a dark admin theme consistent with Pritunl's own interface:

- **Dashboard** — live stats (total rules, active forwards, clients online, conflicts)
- **Rules table** — per-endpoint rules with live status (connected/offline, static, tunnel up/down, or conflict)
- **Add rule form** — pick an endpoint type (Pritunl user / static IP / IPsec tunnel), set ports
- **Password management** — change admin password from within the UI

---

## How It Works

```
Internet
   │
   ▼  e.g. TCP :8443
VPN Server (public IP)
   │
   │  iptables PREROUTING DNAT
   ▼
   ├── Pritunl VPN user's virtual IP   (e.g. 10.10.10.5:443)  — dynamic, gated on connection
   ├── Static / local IP               (e.g. 192.168.1.50:443) — persistent
   └── IP reachable via IPsec tunnel   (e.g. 10.20.0.5:443)    — persistent, tunnel health tracked
```

1. **`daemon.py`** (runs as root) polls Pritunl's MongoDB every 10 seconds for connected clients, and checks StrongSwan tunnel health on a slower interval.
2. For each rule, it resolves a target IP based on the rule's `endpoint_type` — looked up dynamically for Pritunl users, or read directly from the rule for static/IPsec rules — then applies or removes the matching `iptables` DNAT rule.
3. Before applying any rule, it checks for a port already bound by a local service, and for any pre-existing (non-portfwd) iptables rule on the same port — conflicts are skipped and reported rather than applied blindly.
4. The daemon writes a status snapshot (`/etc/pritunl-portfwd/status.json`) describing what's currently applied, tunnel health, and any conflicts.
5. **`app.py`** (runs unprivileged) serves the web UI, reading rule definitions from `/etc/pritunl-portfwd/rules.json` and live status from the daemon's snapshot — it never touches `iptables` or StrongSwan directly.

---

## Requirements

| Component | Version |
|-----------|---------|
| OS        | Ubuntu 20.04+ / Debian 11+ (other Linux distros should work) |
| Python    | 3.8+ |
| Pritunl   | Any version (Community or Enterprise) |
| MongoDB   | Pritunl's bundled MongoDB (localhost:27017) |
| iptables  | Must be available (`ip_forward` enabled) |
| StrongSwan | Optional — only needed if you use IPsec-type rules |

> **Note:** Root access is required for the daemon (iptables manipulation, and StrongSwan status checks if used). The web UI runs as an unprivileged user and never calls `iptables` or `swanctl`/`ipsec` directly.

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/pritunl-portfwd.git
cd pritunl-portfwd
```

### 2. Run the installer

```bash
sudo bash scripts/install.sh
```

The installer will:
- Install Python dependencies into an isolated virtualenv at `/opt/pritunl-portfwd/venv`
- Create a `portfwd` system user for the web UI
- Install two `systemd` services (`pritunl-portfwd-ui` and `pritunl-portfwd-daemon`)
- Create config directory at `/etc/pritunl-portfwd/`
- Start both services automatically

### 3. Enable IP forwarding (if not already set)

Pritunl usually enables this, but verify:

```bash
sysctl net.ipv4.ip_forward
# Should output: net.ipv4.ip_forward = 1

# If not, enable permanently:
echo 'net.ipv4.ip_forward = 1' | sudo tee -a /etc/sysctl.d/99-ip-forward.conf
sudo sysctl -p /etc/sysctl.d/99-ip-forward.conf
```

### 4. Open the web UI

The UI listens on `127.0.0.1:8181` by default (localhost only).

**Option A — SSH tunnel (quickest, no nginx needed):**
```bash
ssh -L 8181:127.0.0.1:8181 user@your-vpn-server
# Then open: http://localhost:8181
```

**Option B — Nginx reverse proxy (recommended for ongoing use):**
See [docs/nginx.conf](docs/nginx.conf) for a ready-to-use nginx config.
With this approach the UI is accessible only from inside the VPN subnet.

### 5. First login — set your password

On first visit you'll be prompted to set an admin password (minimum 8 characters).
This is stored as a SHA-256 hash in `/etc/pritunl-portfwd/config.json`.

---

## Usage

### Endpoint types

Every rule has an **endpoint type**, which determines where traffic gets forwarded and how its lifecycle is managed:

#### 1. Pritunl VPN User — dynamic

Forwards to whichever virtual IP Pritunl currently has the selected user on. **Dynamic**: the daemon only applies the rule while that user is connected, and looks up their current virtual IP from MongoDB each cycle.

- Select the user from the dropdown (populated from Pritunl's database)
- If the user reconnects with a different virtual IP (no static IP pinned in Pritunl), the daemon detects the change and re-applies the rule under the new IP automatically
- Status badge: **● Connected** / **○ Offline**

*Example: forward `:8443` → Alice's laptop `:443` whenever Alice is connected to the VPN.*

#### 2. Static / Local IP — persistent

Forwards to a fixed IP you specify directly — a device on the LAN, another VLAN, anything routable from the VPN server. **Persistent**: applied as soon as the rule exists, with no dependency on any VPN session.

- Enter the **Target IP** and a **Label** (e.g. "NAS Server")
- Status badge: **● Static**

*Example: forward `:2222` → a NAS at `192.168.1.50:22`, always on regardless of who's connected to the VPN.*

#### 3. IPsec Tunnel (StrongSwan) — persistent, with health tracking

Forwards to a fixed IP reachable through a named StrongSwan/IPsec site-to-site connection. **Persistent** like Static — the DNAT rule itself doesn't depend on the tunnel being up at this exact moment (the same way a real firewall config doesn't delete a forwarding rule just because the far end is briefly unreachable). Tunnel health *is* tracked separately and shown as a status badge so you know whether traffic will actually get through right now.

- Enter the **Tunnel Name** (your StrongSwan connection name, e.g. from `swanctl.conf`) and the **Target IP** inside that tunnel's remote subnet, plus a **Label**
- The tunnel name field offers autocomplete suggestions from tunnels the daemon has detected, but also accepts free text — useful if tunnel detection doesn't match your exact StrongSwan setup (see [IPsec / StrongSwan caveats](#ipsec--strongswan-integration) below)
- Status badge: **● Tunnel Up** / **○ Tunnel Down** / **? Tunnel Unknown**

*Example: forward `:8080` → a server at `10.20.0.5:80` reachable through your `site-b` StrongSwan tunnel.*

### Adding a rule

1. Open the web UI
2. Choose the **Endpoint Type**
3. Fill in the fields shown for that type (VPN user dropdown, or target IP + label, or tunnel name + target IP + label)
4. Choose **Protocol**: TCP, UDP, or TCP+UDP (both)
5. Set **External Port** (the port on the VPN server's public IP that traffic arrives on) and **Internal Port** (the port to forward to)
6. Optionally add a **Comment**
7. Click **Add Rule**

The daemon picks up the new rule within ~10 seconds (Pritunl-type rules apply immediately if the user is already connected; static/IPsec rules apply on the next sync regardless of any VPN state).

### Conflict detection

Two layers of checking happen before a rule is actually applied:

1. **Immediate (web UI)** — when you click Add Rule, the UI reads `/proc/net/tcp` and `/proc/net/udp` to check whether some other local process is already bound to that external port. If so, the rule is rejected outright with a `409` error, since a DNAT rule on that port would otherwise hijack traffic meant for the existing service (DNAT in `PREROUTING` happens before local delivery).
2. **Deeper (daemon)** — every sync cycle (~10s), the daemon also checks the existing `iptables -t nat -S PREROUTING` ruleset for any rule on that port/proto *not* tagged by this tool — e.g. something added manually or by other tooling. If found, that specific rule is skipped and surfaced in the UI as a **⚠ Conflict** badge (hover for the reason) rather than being silently applied or silently dropped.

The deeper check can only run in the daemon because reading `iptables` requires root; the immediate check works for any user since `/proc/net/*` is world-readable.

### Rule status badges

| Badge | Meaning |
|---|---|
| ● Connected | Pritunl user is connected; rule is live |
| ○ Offline | Pritunl user is not connected; rule will apply on their next connection |
| ● Static | Static/local IP rule; always applied |
| ● Tunnel Up | IPsec rule; StrongSwan tunnel currently established |
| ○ Tunnel Down | IPsec rule; tunnel not currently up (rule still applied, just won't carry traffic until the tunnel comes up) |
| ? Tunnel Unknown | IPsec rule; daemon couldn't determine tunnel state (see StrongSwan caveats) |
| ⚠ Conflict | Rule skipped — collides with a port already in use or an existing non-portfwd iptables rule |

### Deleting a rule

Click the **✕** button on any rule row. The iptables rule is removed within ~10 seconds.

### Protocol options explained

| Option | iptables rules created |
|--------|----------------------|
| TCP    | One DNAT rule for TCP only |
| UDP    | One DNAT rule for UDP only |
| TCP + UDP | Two DNAT rules, one per protocol |

---

## Configuration

### Environment variables

Edit `/etc/pritunl-portfwd/env` to change defaults:

```bash
# Path to rules file
RULES_FILE=/etc/pritunl-portfwd/rules.json

# Path to the daemon's live-status snapshot (written by daemon.py, read
# by app.py). World-readable JSON, no secrets in it.
STATUS_FILE=/etc/pritunl-portfwd/status.json

# Path to config file (stores password hash)
CONFIG_FILE=/etc/pritunl-portfwd/config.json

# Pritunl MongoDB connection
MONGO_URI=mongodb://localhost:27017/
MONGO_DB=pritunl

# Web UI bind address and port
LISTEN_HOST=127.0.0.1
LISTEN_PORT=8181

# How often the daemon polls MongoDB (seconds)
POLL_SECS=10

# How often (in poll cycles) to refresh StrongSwan/IPsec tunnel status.
# Only relevant if you use IPsec-type rules — each check spawns a
# subprocess, so it's checked less often than the main sync loop.
IPSEC_POLL_EVERY=3
```

After editing, restart both services:
```bash
sudo systemctl restart pritunl-portfwd-ui pritunl-portfwd-daemon
```

### Rules file

Rules are stored as JSON at `/etc/pritunl-portfwd/rules.json`. Each rule has an `endpoint_type` of `pritunl`, `static`, or `ipsec`, with type-specific fields:

```json
[
  {
    "id": "a1b2c3d4",
    "endpoint_type": "pritunl",
    "user_id": "64f2a1b3c4d5e6f7a8b9c0d1",
    "user_name": "alice",
    "proto": "tcp",
    "external_port": 8443,
    "internal_port": 443,
    "comment": "Alice's home web server",
    "created_at": "2024-01-15T12:00:00.000000"
  },
  {
    "id": "e5f6a7b8",
    "endpoint_type": "static",
    "target_ip": "192.168.1.50",
    "label": "NAS Server",
    "proto": "tcp",
    "external_port": 2222,
    "internal_port": 22,
    "comment": "",
    "created_at": "2024-01-15T12:05:00.000000"
  },
  {
    "id": "c9d0e1f2",
    "endpoint_type": "ipsec",
    "target_ip": "10.20.0.5",
    "tunnel_name": "site-b",
    "label": "Site B File Server",
    "proto": "tcp",
    "external_port": 8080,
    "internal_port": 80,
    "comment": "",
    "created_at": "2024-01-15T12:10:00.000000"
  }
]
```

> **Tip:** Changes to the rules file are picked up automatically by the daemon on its next sync cycle. No restart needed.

> **Migrating from an older version:** rules created before endpoint types existed don't have an `endpoint_type` field. They're treated as `pritunl` automatically — no manual migration needed, and your existing `user_id`-based rules keep working exactly as before.

---

## Services

### Manage with systemctl

```bash
# Status of both services
sudo systemctl status pritunl-portfwd-ui
sudo systemctl status pritunl-portfwd-daemon

# Restart after config changes
sudo systemctl restart pritunl-portfwd-ui pritunl-portfwd-daemon

# View logs
sudo journalctl -u pritunl-portfwd-ui -f
sudo journalctl -u pritunl-portfwd-daemon -f

# Or tail log files directly
sudo tail -f /var/log/pritunl-portfwd.log
sudo tail -f /var/log/pritunl-portfwd-daemon.log
```

### Service overview

| Service | User | Purpose |
|---------|------|---------|
| `pritunl-portfwd-ui` | `portfwd` (unprivileged) | Flask web UI on 127.0.0.1:8181 |
| `pritunl-portfwd-daemon` | `root` | Polls MongoDB, manages iptables rules |

---

## IPsec / StrongSwan Integration

IPsec-type rules forward to a fixed IP reachable through a named StrongSwan connection. The DNAT rule itself is applied persistently and doesn't require StrongSwan to be reachable at all — only tunnel *health reporting* depends on it.

### How tunnel status is detected

The daemon (running as root, so no extra permissions setup needed) tries, in order:

1. **`swanctl --list-conns`** + **`swanctl --list-sas`** — the modern, vici-socket-based interface used by current StrongSwan versions. Preferred when available.
2. **`ipsec statusall`** — the legacy `ipsec` starter command, used as a fallback.
3. If neither binary exists, tunnel status is simply omitted — IPsec-type rules will show **? Tunnel Unknown**, but the forwarding rule is still applied normally.

### Known limitation: best-effort parsing

`swanctl`/`ipsec` output formats vary across StrongSwan versions and configurations, so the parser here is a reasonable best-effort, not a guaranteed match for every setup. If your tunnels show as **? Tunnel Unknown** even though they're actually up:

```bash
# Run these manually on the server to see your actual output format:
sudo swanctl --list-conns
sudo swanctl --list-sas
# or, for older/legacy setups:
sudo ipsec statusall
```

Compare against the regex patterns in `get_ipsec_status()` in `daemon.py` and adjust to match your output. This doesn't block functionality either way — the `tunnel_name` field in the UI always accepts free text, so you can configure IPsec rules correctly even if status detection needs tuning for your environment.

---

## Security Considerations

### Network access
- The web UI binds to `127.0.0.1` only by default — it is **not** exposed to the internet
- Use the nginx config in `docs/nginx.conf` with an IP allowlist restricted to your VPN subnet
- This means only connected VPN users can reach the admin UI

### Firewall
- Port forwards open traffic from the public internet to VPN client IPs
- Only create rules for trusted users and ports you actually need
- The daemon uses `iptables` comment tags (`pritunl-portfwd:...`) to track its own rules and never touches unrelated rules

### Static VPN IPs
- VPN client IPs are assigned dynamically by Pritunl per session by default
- For reliable port forwarding, set a **Static IP** for each user in Pritunl's admin console (`Users → Edit User → Static IP`)
- Without a static IP, the iptables rule is automatically updated each time the user reconnects (the daemon detects the IP change and re-applies the rule), but there is a brief window (~10s) during reconnection

### Static / local IP and IPsec rules
- Unlike Pritunl-user rules, **static and IPsec rules are applied persistently** — they don't depend on any VPN session, so they stay live even if no VPN client is connected at all
- This means a static/IPsec rule effectively opens a path from the internet straight to that target IP for as long as the rule exists — treat it with the same care as a manual firewall rule, and delete it when no longer needed
- The conflict checks (port-in-use, existing iptables rules) apply to these rule types too, but neither checks whether the *target* IP itself is actually reachable — a misconfigured static IP or a tunnel that's down just means traffic goes nowhere, not that the rule is rejected

### Authentication
- The admin password is stored as a SHA-256 hash in `/etc/pritunl-portfwd/config.json`
- Sessions are server-side; change the `SECRET_KEY` env var to invalidate all sessions
- For production use, put the UI behind nginx with TLS

---

## Troubleshooting

### Web UI not loading
```bash
sudo systemctl status pritunl-portfwd-ui
sudo tail -20 /var/log/pritunl-portfwd.log
```
Check that port 8181 is not already in use: `sudo ss -tlnp | grep 8181`

### Rules not being applied
```bash
sudo systemctl status pritunl-portfwd-daemon
sudo tail -30 /var/log/pritunl-portfwd-daemon.log
```
Verify MongoDB is accessible: `mongo --eval "db.adminCommand('ping')" --quiet`

### Check active iptables rules
```bash
# See all portfwd DNAT rules
sudo iptables -t nat -L PREROUTING -n --line-numbers | grep pritunl-portfwd

# See all portfwd FORWARD rules
sudo iptables -L FORWARD -n --line-numbers | grep pritunl-portfwd
```

### Manually flush all portfwd rules
```bash
sudo systemctl stop pritunl-portfwd-daemon
# The daemon flushes all its rules on clean shutdown.
# To force-flush without restarting:
sudo iptables -t nat -S PREROUTING | grep pritunl-portfwd | \
  sed 's/-A/-D/' | xargs -r -L1 sudo iptables -t nat
sudo iptables -S FORWARD | grep pritunl-portfwd | \
  sed 's/-A/-D/' | xargs -r -L1 sudo iptables
```

### User dropdown is empty
The UI reads users from Pritunl's MongoDB. If the dropdown is empty:
- Check the MongoDB connection in `/etc/pritunl-portfwd/env`
- Verify Pritunl's MongoDB is running: `sudo systemctl status pritunl-mongodb`
- Confirm the database name matches (default: `pritunl`)

### A rule shows "⚠ Conflict"
Hover the badge for the specific reason. This means either:
- another process on this host is already bound to that external port (`sudo ss -tlnp | grep <port>` to identify it), or
- a pre-existing, non-portfwd iptables rule already forwards that port/proto (`sudo iptables -t nat -S PREROUTING | grep -- '--dport <port>'`)

Resolve the underlying conflict (free the port, or remove/adjust the other rule), and the daemon will pick the rule back up on its next sync cycle.

### IPsec tunnel always shows "? Tunnel Unknown"
This means the daemon's `swanctl`/`ipsec` parser didn't match your StrongSwan output format — see [IPsec / StrongSwan Integration](#ipsec--strongswan-integration) above for how to diagnose and adjust it. The forwarding rule itself still works regardless of this status display.

### Checking the live status snapshot
```bash
# What the daemon currently believes is applied, with target IPs,
# tunnel health, and any conflicts:
sudo cat /etc/pritunl-portfwd/status.json | python3 -m json.tool
```

---

## Uninstallation

```bash
sudo bash scripts/uninstall.sh
```

This stops and removes both services and application files. It will ask separately whether to delete your configuration and rules.

---

## Architecture

```
/opt/pritunl-portfwd/
├── app.py               # Flask web application (unprivileged)
├── daemon.py             # iptables management daemon (root)
├── common.py             # Shared helpers (rule/status I/O, validation,
│                          # local-port scanning) imported by both
├── templates/
│   ├── index.html       # Main admin UI
│   ├── login.html       # Login page
│   └── setup.html       # First-run password setup
└── venv/                # Python virtualenv (created by installer)

/etc/pritunl-portfwd/
├── config.json          # Admin password hash
├── rules.json           # Port forward rule definitions
├── status.json           # Live status snapshot, written by daemon.py,
│                          # read by app.py (target IPs, applied state,
│                          # tunnel health, conflicts) — world-readable,
│                          # contains no secrets
└── env                  # Environment variable overrides
```

---

## Contributing

Pull requests welcome. Please open an issue first for significant changes.

When adding features, keep in mind:
- The daemon must be safe to restart at any time (idempotent rule application)
- The web UI must work without any build step (plain HTML/CSS/JS)
- Compatibility with Pritunl Community Edition is a hard requirement

---

## License

MIT License — see [LICENSE](LICENSE)

---

## Acknowledgements

Built on top of [Pritunl](https://pritunl.com/) — an excellent open-source VPN server.
