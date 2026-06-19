# pritunl-portfwd

**Port Forward Manager for Pritunl VPN — Community Edition**

A self-hosted web UI and background daemon that lets you define TCP/UDP port forward rules on a Pritunl VPN server, forwarding traffic to:

- **Pritunl VPN users** — forwards to whatever virtual IP Pritunl currently has the user on (dynamic, tracked live)
- **Static / local IPs** — forwards to any fixed IP reachable from the server (a LAN device, another VLAN, anything routable)
- **IPsec tunnel endpoints** — forwards to a fixed IP reachable through a named StrongSwan/IPsec connection, with tunnel health surfaced in the UI

Beyond basic forwarding:
- **Port ranges** on either side of a rule (`8000-8010`), not just single ports
- **Outbound rules** that pin the source port of an endpoint's outgoing connections via SNAT — for remote services that expect traffic from one fixed, predictable port
- **Import** of pre-existing iptables port-forward rules already on the host, so they become fully managed by this tool
- **Live traffic inspection** — peek at a rule's traffic with `tcpdump`, filterable by IP/port/protocol, running only while you have it open
- **Backup and restore** — export every rule definition to a JSON file, and re-import it later (merge or full replace) with the same validation a hand-added rule goes through

Before any rule is applied, it's checked against ports already in use locally and against pre-existing iptables rules, so it won't silently steal traffic from another service.

Works with **Pritunl Community Edition** — no Enterprise subscription required.

---

## Screenshots

The web UI uses a dark admin theme consistent with Pritunl's own interface:

- **Dashboard** — live stats (total rules, active forwards, clients online, conflicts, discovered/importable rules)
- **Rules table** — per-endpoint rules with live status (connected/offline, static, tunnel up/down, or conflict), direction (inbound/outbound), and a one-click traffic inspector
- **Add rule form** — pick an endpoint type (Pritunl user / static IP / IPsec tunnel) and direction (inbound / outbound), set ports or port ranges
- **Discovered rules panel** — one-click import of pre-existing, unmanaged iptables rules
- **Password management** — change admin password from within the UI

---

## How It Works

```
Internet
   │
   ▼  e.g. TCP :8443
VPN Server (public IP)
   │
   │  iptables PREROUTING DNAT  (inbound rules)
   ▼
   ├── Pritunl VPN user's virtual IP   (e.g. 10.10.10.5:443)  — dynamic, gated on connection
   ├── Static / local IP               (e.g. 192.168.1.50:443) — persistent
   └── IP reachable via IPsec tunnel   (e.g. 10.20.0.5:443)    — persistent, tunnel health tracked

   ▲
   │  iptables POSTROUTING MASQUERADE  (outbound rules — pins the source port
   │  of NEW outgoing connections from one of the endpoints above)
   │
Internet
```

1. **`daemon.py`** (runs as root) polls Pritunl's MongoDB every 10 seconds for connected clients, and checks StrongSwan tunnel health on a slower interval.
2. For each rule, it resolves a target IP based on the rule's `endpoint_type` — looked up dynamically for Pritunl users, or read directly from the rule for static/IPsec rules — then, based on the rule's `direction`, applies or removes either a `PREROUTING` DNAT rule (inbound) or a `POSTROUTING` MASQUERADE rule (outbound, source-port pinning).
3. Before applying any inbound rule, it checks for a port already bound by a local service, and for any pre-existing (non-portfwd) iptables rule on the same port — conflicts are skipped and reported rather than applied blindly. It also scans for pre-existing DNAT rules it doesn't own and surfaces them as importable.
4. The daemon writes a status snapshot (`/etc/pritunl-portfwd/status.json`) describing what's currently applied, tunnel health, conflicts, and discovered/importable rules — and, on a sub-second loop independent of the main sync, services tcpdump capture start/stop requests for the live traffic inspector.
5. **`app.py`** (runs unprivileged) serves the web UI, reading rule definitions from `/etc/pritunl-portfwd/rules.json` and live status from the daemon's snapshot — it never touches `iptables`, StrongSwan, or `tcpdump` directly. Anything that needs root (applying rules, importing a discovered rule, running a capture) goes through a request file the daemon picks up.

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
4. Choose **Direction**: `Inbound` (forward incoming connections to this endpoint) or `Outbound` (pin the source port of this endpoint's outgoing connections — see [Outbound rules](#outbound-rules--pinning-a-source-port-snat) below)
5. Choose **Protocol**: TCP, UDP, or TCP+UDP (both)
6. For inbound rules, set **External Port(s)** and **Internal Port(s)** — either can be a single port (`8443`) or a range (`8000-8010`), see [Port ranges](#port-ranges) below. For outbound rules, set the **Source Port(s)** to pin to and, optionally, a **Destination IP** to scope the pin to one external service.
7. Optionally add a **Comment**
8. Click **Add Rule**

The daemon picks up the new rule within ~10 seconds (Pritunl-type rules apply immediately if the user is already connected; static/IPsec rules apply on the next sync regardless of any VPN state).

### Port ranges

Both `external_port` and `internal_port` on an inbound rule accept either a single port (`8443`) or a range (`8000-8010`). Valid combinations:

| External | Internal | Behavior |
|---|---|---|
| single | single | the original, simple case |
| range | single | many-to-one — all ports in the external range forward to the same internal port |
| single | range | one-to-many — iptables load-balances the single matched port across the internal range |
| range | range (same size) | parallel, offset-preserving mapping (e.g. `8000-8010` → `9000-9010` maps `8000→9000`, `8001→9001`, …) |

Two differently-sized ranges on both sides aren't supported — that isn't something a single iptables rule can express. The web UI validates this when you add a rule, and the daemon re-validates it on every sync.

### Outbound rules — pinning a source port (SNAT)

Some external services expect **all** traffic from a device to arrive from one fixed, predictable source port, rather than the arbitrary port a normal outbound connection (and Pritunl's own default MASQUERADE) would use. A concrete example:

```
1.2.3.4  →  VPN  →  192.1.2.3:5000    inbound:  external service connects in on :5000
192.1.2.3  →  VPN  →  1.2.3.4          outbound: 192.1.2.3 must appear to originate from :5001
```

An **outbound** rule handles the second leg: it inserts an SNAT/MASQUERADE rule that rewrites the source port of new outgoing connections from the chosen endpoint to a fixed port (or pool of ports, if you give it a range), using `MASQUERADE --to-ports` so the egress IP itself is whatever this host's outbound interface already uses — no need to hardcode the server's public IP.

Two implementation details matter and are handled for you:

- The rule is inserted at the **top** of the `POSTROUTING` chain (`-I POSTROUTING 1`), not appended. Pritunl already installs its own broad MASQUERADE rule there for general client internet access, and the kernel stops at the *first* matching rule for each new connection — appending after Pritunl's rule would mean ours never gets reached.
- An optional **Destination IP** scopes the pin to traffic going to one specific external service, so it doesn't affect the endpoint's other outbound traffic.

**Important limitation:** this only affects *genuinely new* outbound connections. Once a connection is established, the kernel reuses its cached NAT translation (via conntrack) for all subsequent packets on that connection without re-consulting the nat table at all — so an outbound rule cannot redirect or reposition the source port of a connection that's already underway. If you need this kind of pinning, it has to be in place *before* the connection that needs it gets established.

A rule's `direction` (inbound/outbound) is independent of its `endpoint_type` (pritunl/static/ipsec) — an outbound rule can pin a Pritunl VPN user's connection just as easily as a static IP's.

### Importing existing iptables rules

If this host already has DNAT port-forward rules that predate this tool (set up by hand, or by other tooling), they show up automatically in a **Discovered Existing iptables Rules** card above the main rules table — the daemon scans `PREROUTING` every cycle for DNAT rules it doesn't own.

Click **Import** on any discovered rule and, within ~10 seconds:
1. The original raw iptables rule (and its matching `FORWARD` ACCEPT rule, if found) is deleted
2. An equivalent entry is added to `rules.json`, tagged and managed like any rule you created in the UI
3. It becomes fully editable/deletable from the main rules table from then on

The daemon guesses `endpoint_type` on import: if the rule's target IP matches a *currently connected* Pritunl client's virtual IP, it's imported as a `pritunl` rule; otherwise it's imported as a `static` rule labeled "Imported rule" (you can edit the label afterward). Imported rules always come in as `direction: inbound`, since that's the only thing a `PREROUTING` DNAT rule can represent.

### Traffic inspection (tcpdump)

Click the **👁** button on any rule to open a live traffic inspector for it. While the modal is open, the daemon runs a `tcpdump` filtered to that rule's target IP/port(s) (plus an optional IP/port/protocol filter you can narrow it with), and the modal polls and displays the latest output roughly once a second.

A few things worth knowing:
- The capture **only runs while the modal is open** — closing it (or pressing Escape, or clicking outside it) stops `tcpdump` immediately.
- There's a 10-minute (`MAX_CAPTURE_SECONDS`) safety auto-stop in case a browser tab gets left open and forgotten.
- This is intentionally a live "peek," not a logging tool — no capture history is retained after a session ends; the log file is deleted on stop.
- Requires `tcpdump` to be installed (the installer adds it automatically; if it's missing, the modal shows an inline error with the install command instead of failing silently).
- Like the rest of this tool's privilege model, the unprivileged web UI never runs `tcpdump` itself — it only queues a request that the root daemon acts on, and every filter value is re-validated by the daemon before it ever reaches `tcpdump`'s command line.

### Conflict detection

This applies to **inbound** rules — outbound rules don't bind a listening port, so the "is this port already in use" question doesn't apply to them (see the separate outbound check below). Two layers of checking happen before an inbound rule is actually applied:

1. **Immediate (web UI)** — when you click Add Rule, the UI reads `/proc/net/tcp` and `/proc/net/udp` to check whether some other local process is already bound to that external port (or any port in the range, if you used one). If so, the rule is rejected outright with a `409` error, since a DNAT rule on that port would otherwise hijack traffic meant for the existing service (DNAT in `PREROUTING` happens before local delivery).
2. **Deeper (daemon)** — every sync cycle (~10s), the daemon also checks the existing `iptables -t nat -S PREROUTING` ruleset for any rule with an *overlapping* port range on that proto *not* tagged by this tool — e.g. something added manually or by other tooling. If found, that specific rule is skipped and surfaced in the UI as a **⚠ Conflict** badge (hover for the reason) rather than being silently applied or silently dropped.

The deeper check can only run in the daemon because reading `iptables` requires root; the immediate check works for any user since `/proc/net/*` is world-readable.

**Outbound rules** get a simpler, config-level check instead: when you add one, the UI checks whether another existing outbound rule already pins the *same* source endpoint to an overlapping source port for an overlapping destination scope, and rejects the new rule with a `409` if so. This doesn't need root/iptables access, since outbound rules are always inserted at the top of the chain — there's no "shadowed by an earlier rule" scenario to detect the way there is for inbound rules.

**Resolving a conflict:** there's no "force apply anyway" option — that's intentional, the whole point is to never silently hijack traffic. Depending on the reason shown:
- *Local service already listening* → stop/reconfigure that service, or edit the rule (✏️) to use a free port instead
- *Existing non-portfwd iptables rule* → either import it via the [Discovered Existing iptables Rules](#importing-existing-iptables-rules) panel if you want to keep and manage what it does, or remove it yourself (`sudo iptables -t nat -D ...`) if it's stale, or edit your rule to a non-overlapping port

Once the underlying conflict clears, the daemon picks the rule back up automatically on its next sync — no restart needed.

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

### Editing a rule

Click **✏️** on any rule to change its protocol, ports (or source port / destination IP, for an outbound rule), or comment — the same validation a new rule goes through (port format, range compatibility, conflict/overlap checks) runs on save, just excluding the rule itself from the overlap checks so it doesn't flag against its own current values.

`endpoint_type` and `direction` are intentionally **not** editable — changing either means a completely different field set applies (e.g. ports vs. source-port-and-destination), so delete and recreate the rule for that case instead. The endpoint identity itself (which VPN user / which static IP / which tunnel) is shown read-only in the edit dialog for the same reason.

### Deleting a rule

Click the **✕** button on any rule row. The iptables rule is removed within ~10 seconds.

### Backup and restore

Click **⬇ Export** in the header to download every current rule definition as a single JSON file (`pritunl-portfwd-rules-<timestamp>.json`) — a config-only snapshot, not a capture of live state (which Pritunl user happens to be connected right now, current tunnel health, etc. is inherently a moving target). Keep it somewhere off the host as an actual backup, check it into your own private config-management repo, or use it to set up a second/replacement server with the same rules.

To bring a snapshot back, click **⬆ Import**, choose the file, and pick a mode:

- **Merge** — adds the snapshot's rules to whatever's already configured, skipping anything that conflicts with an existing rule
- **Replace** — deletes all current rules first, then applies the snapshot from a clean slate (the UI asks for confirmation before doing this, since it's destructive)

Every rule in the file goes through the exact same validation a manually-added rule would — port format, range compatibility, conflict/overlap checks — so a corrupted or hand-edited file can't silently produce a broken or conflicting rule set. Anything that doesn't pass is **skipped and listed with a reason** rather than blocking the rest of the restore, so one bad entry doesn't prevent the rest of a snapshot from coming back. Rule IDs are always regenerated on import (never reused from the file), so importing the same snapshot twice — or onto a different host entirely — never collides with anything by coincidence.

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

# Queue files for the privilege-separated async actions below — the
# unprivileged web UI writes a request, the root daemon acts on it and
# clears the queue on its next cycle (or, for captures, within ~1s).
IMPORT_REQUESTS_FILE=/etc/pritunl-portfwd/import_requests.json
CAPTURE_REQUESTS_FILE=/etc/pritunl-portfwd/capture_requests.json
CAPTURE_STATUS_FILE=/etc/pritunl-portfwd/capture_status.json
CAPTURE_LOG_DIR=/etc/pritunl-portfwd/captures

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

# Safety auto-stop for the tcpdump "Inspect" feature (seconds), in case a
# browser tab gets left open and forgotten.
MAX_CAPTURE_SECONDS=600
```

After editing, restart both services:
```bash
sudo systemctl restart pritunl-portfwd-ui pritunl-portfwd-daemon
```

### Rules file

Rules are stored as JSON at `/etc/pritunl-portfwd/rules.json`. Every rule has an `endpoint_type` (`pritunl`, `static`, or `ipsec`) and a `direction` (`inbound` or `outbound`), with direction-specific port fields:

```json
[
  {
    "id": "a1b2c3d4",
    "endpoint_type": "pritunl",
    "direction": "inbound",
    "user_id": "64f2a1b3c4d5e6f7a8b9c0d1",
    "user_name": "alice",
    "proto": "tcp",
    "external_port": "8443",
    "internal_port": "443",
    "comment": "Alice's home web server",
    "created_at": "2024-01-15T12:00:00.000000"
  },
  {
    "id": "e5f6a7b8",
    "endpoint_type": "static",
    "direction": "inbound",
    "target_ip": "192.168.1.50",
    "label": "NAS Server",
    "proto": "tcp",
    "external_port": "8000-8010",
    "internal_port": "8000-8010",
    "comment": "Range mapping, offset-preserving",
    "created_at": "2024-01-15T12:05:00.000000"
  },
  {
    "id": "c9d0e1f2",
    "endpoint_type": "ipsec",
    "direction": "inbound",
    "target_ip": "10.20.0.5",
    "tunnel_name": "site-b",
    "label": "Site B File Server",
    "proto": "tcp",
    "external_port": "8080",
    "internal_port": "80",
    "comment": "",
    "created_at": "2024-01-15T12:10:00.000000"
  },
  {
    "id": "f1a2b3c4",
    "endpoint_type": "static",
    "direction": "outbound",
    "target_ip": "192.1.2.3",
    "label": "Pinned callback source port",
    "proto": "tcp",
    "source_port": "5001",
    "destination_ip": "1.2.3.4",
    "comment": "External service expects all traffic from a fixed source port",
    "created_at": "2024-01-15T12:15:00.000000"
  }
]
```

Note that for `direction: outbound`, `target_ip` identifies the **source** endpoint (the device whose outbound traffic gets pinned), not a forwarding destination — `resolve_target()` in the daemon works identically either way, only the `direction` field changes how the resolved IP is used.

> **Tip:** Changes to the rules file are picked up automatically by the daemon on its next sync cycle. No restart needed.

> **Migrating from an older version:** rules created before endpoint types existed don't have an `endpoint_type` field (treated as `pritunl` automatically), and rules created before ranges/outbound rules existed have plain integer `external_port`/`internal_port` values and no `direction` field (treated as `direction: inbound` automatically). No manual migration needed either way.

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

### Traffic inspection (tcpdump)
- The web UI never invokes `tcpdump` itself — it only writes a capture *request*; the root daemon is the only thing that ever spawns the process, and it re-validates every filter value (IP/port/protocol) server-side before building the `tcpdump` command line, regardless of what the browser sent
- Capture logs are deleted as soon as a session stops — there's no retained traffic history sitting on disk between sessions
- Anyone with admin access to the UI can capture any traffic flowing through any rule — treat admin UI access with the same care you'd give direct root/SSH access to this host

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
# See all portfwd DNAT rules (inbound)
sudo iptables -t nat -L PREROUTING -n --line-numbers | grep pritunl-portfwd

# See all portfwd FORWARD rules
sudo iptables -L FORWARD -n --line-numbers | grep pritunl-portfwd

# See all portfwd SNAT/MASQUERADE rules (outbound) — these should appear
# ABOVE Pritunl's own MASQUERADE rule; if an outbound rule isn't taking
# effect, check it's actually rule #1 here, not below Pritunl's:
sudo iptables -t nat -L POSTROUTING -n --line-numbers
```

### Manually flush all portfwd rules
```bash
sudo systemctl stop pritunl-portfwd-daemon
# The daemon flushes all its rules (including outbound POSTROUTING
# entries) on clean shutdown. To force-flush without restarting:
sudo iptables -t nat -S PREROUTING | grep pritunl-portfwd | \
  sed 's/-A/-D/' | xargs -r -L1 sudo iptables -t nat
sudo iptables -t nat -S POSTROUTING | grep pritunl-portfwd | \
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
Hover the badge for the specific reason. For an **inbound** rule, this means either:
- another process on this host is already bound to that external port (`sudo ss -tlnp | grep <port>` to identify it), or
- a pre-existing, non-portfwd iptables rule already forwards that port/proto (`sudo iptables -t nat -S PREROUTING | grep -- '--dport <port>'`)

Resolve the underlying conflict (free the port, or remove/adjust the other rule), and the daemon will pick the rule back up on its next sync cycle.

### Outbound rule doesn't seem to be pinning the source port
- Confirm `tcpdump` actually shows the connection leaving with the new source port (the [Traffic inspection](#traffic-inspection-tcpdump) modal is the easiest way to check this live) — note it only affects *new* connections, not ones already established when the rule was added (see [Outbound rules](#outbound-rules--pinning-a-source-port-snat)).
- Check the rule is actually first in `POSTROUTING` (see `Check active iptables rules` above) — if Pritunl's own MASQUERADE rule got re-added above it (e.g. after a Pritunl service restart), it'll shadow ours until the daemon's next sync re-asserts ordering.
- If you scoped the rule to a `destination_ip`, confirm the device is actually talking to that IP — traffic to anywhere else won't match.

### "Inspect" modal shows an error about tcpdump
`tcpdump` isn't installed on the host (the installer adds it automatically, but it can be removed afterward by other tooling/cleanup). Install it manually: `sudo apt-get install tcpdump`, no service restart needed — the next "Inspect" click will work once it's present.

### "Inspect" modal opens but shows no traffic
- Confirm the rule actually has an active target (an offline VPN user, for instance, has no `target_ip` to capture against — the modal will say so).
- If you added an IP/port/protocol filter, double check it isn't excluding the traffic you're expecting to see — clear the filters and click **Apply Filter** to capture broadly first.

### Import (restore) says "This doesn't look like a pritunl-portfwd rules export file"
The uploaded file is either not a valid JSON export from this tool's **⬇ Export** button, or it's been hand-edited and lost its `format` field. Re-export a fresh snapshot, or add `"format": "pritunl-portfwd-rules-snapshot"` back to the file if you're confident the rest of its structure is intact.

### Import (restore) skipped some rules
This is expected if those specific rules don't pass the normal validation a hand-added rule would — check the listed reason for each (most commonly: a port conflicts with something that wasn't conflicting when the snapshot was taken, or the file was edited by hand and a port field is malformed). Fix the underlying issue and re-run the import, or add that one rule manually instead.

### IPsec tunnel always shows "? Tunnel Unknown"
This means the daemon's `swanctl`/`ipsec` parser didn't match your StrongSwan output format — see [IPsec / StrongSwan Integration](#ipsec--strongswan-integration) above for how to diagnose and adjust it. The forwarding rule itself still works regardless of this status display.

### Checking the live status snapshot
```bash
# What the daemon currently believes is applied, with target IPs,
# tunnel health, conflicts, and discovered/importable rules:
sudo cat /etc/pritunl-portfwd/status.json | python3 -m json.tool

# Current tcpdump capture session state, if any "Inspect" modal is open:
sudo cat /etc/pritunl-portfwd/capture_status.json | python3 -m json.tool
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
├── config.json              # Admin password hash
├── rules.json               # Port forward rule definitions
├── status.json               # Live status snapshot, written by daemon.py,
│                              # read by app.py (target IPs, applied state,
│                              # tunnel health, conflicts, discovered/
│                              # importable rules) — world-readable,
│                              # contains no secrets
├── import_requests.json     # Pending "import this foreign rule" requests,
│                              # written by app.py, consumed by daemon.py
├── capture_requests.json    # Pending tcpdump start/stop requests, written
│                              # by app.py, consumed by daemon.py
├── capture_status.json      # Live capture session state, written by
│                              # daemon.py, read by app.py — world-readable
├── captures/                 # Transient tcpdump log files — deleted as
│                              # soon as each capture session stops; no
│                              # history is retained between sessions
└── env                       # Environment variable overrides
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
