# pritunl-portfwd

**Port Forward Manager for Pritunl VPN — Community Edition**

A self-hosted web UI and background daemon that lets you define per-user TCP/UDP port forward rules on a Pritunl VPN server. Traffic arriving at the VPN server on a given external port is forwarded via `iptables` DNAT to the matching VPN client's virtual IP.

Works with **Pritunl Community Edition** — no Enterprise subscription required.

---

## Screenshots

The web UI uses a dark admin theme consistent with Pritunl's own interface:

- **Dashboard** — live stats (total rules, active forwards, clients online)
- **Rules table** — per-user rules with live active/offline status and virtual IP
- **Add rule form** — select user from Pritunl, choose TCP/UDP/both, set ports
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
VPN Client virtual IP (e.g. 10.10.10.5:443)
```

1. **`daemon.py`** polls Pritunl's MongoDB every 10 seconds for connected clients.
2. When a client with a defined rule connects, the daemon adds an `iptables` DNAT rule mapping the external port to the client's assigned virtual IP and internal port.
3. When the client disconnects, the rule is removed.
4. **`app.py`** serves a web UI to manage rules, which are stored in `/etc/pritunl-portfwd/rules.json`.

---

## Requirements

| Component | Version |
|-----------|---------|
| OS        | Ubuntu 20.04+ / Debian 11+ (other Linux distros should work) |
| Python    | 3.8+ |
| Pritunl   | Any version (Community or Enterprise) |
| MongoDB   | Pritunl's bundled MongoDB (localhost:27017) |
| iptables  | Must be available (`ip_forward` enabled) |

> **Note:** Root access is required for the daemon (iptables manipulation). The web UI runs as an unprivileged user.

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

### Adding a port forward rule

1. Open the web UI
2. Select the **VPN user** from the dropdown (populated from Pritunl's database)
3. Choose **Protocol**: TCP, UDP, or TCP+UDP (both)
4. Set **External Port** — the port on the VPN server's public IP that external traffic arrives on
5. Set **Internal Port** — the port on the VPN client's machine to forward to
6. Optionally add a **Comment** (e.g. "Alice's home server HTTPS")
7. Click **Add Rule**

The daemon picks up the new rule within 10 seconds. If the user is already connected, the iptables rule is applied immediately. If not, it will be applied when they next connect.

### Rule status

The rules table shows:
- **● Active** — the user is currently connected and the iptables rule is live
- **○ Offline** — the user is not connected (rule will apply on their next connection)
- **Virtual IP** — the client's current VPN IP (shown when active)

### Deleting a rule

Click the **✕** button on any rule row. The iptables rule is removed within 10 seconds.

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
```

After editing, restart both services:
```bash
sudo systemctl restart pritunl-portfwd-ui pritunl-portfwd-daemon
```

### Rules file

Rules are stored as JSON at `/etc/pritunl-portfwd/rules.json`. You can inspect or edit this file directly if needed:

```json
[
  {
    "id": "a1b2c3d4",
    "user_id": "64f2a1b3c4d5e6f7a8b9c0d1",
    "user_name": "alice",
    "proto": "tcp",
    "external_port": 8443,
    "internal_port": 443,
    "comment": "Alice's home web server",
    "created_at": "2024-01-15T12:00:00.000000"
  }
]
```

> **Tip:** Changes to the rules file are detected automatically by the daemon (via file modification time). No restart needed.

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
- Without a static IP, the iptables rule is automatically updated each time the user reconnects (the daemon handles this), but there is a brief window (~10s) during reconnection

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
├── app.py               # Flask web application
├── daemon.py            # iptables management daemon
├── templates/
│   ├── index.html       # Main admin UI
│   ├── login.html       # Login page
│   └── setup.html       # First-run password setup
└── venv/                # Python virtualenv (created by installer)

/etc/pritunl-portfwd/
├── config.json          # Admin password hash
├── rules.json           # Port forward rule definitions
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
