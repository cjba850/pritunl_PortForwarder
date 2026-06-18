# Advanced Configuration & Troubleshooting

## Changing the MongoDB connection

If Pritunl's MongoDB uses authentication or a non-default port, edit `/etc/pritunl-portfwd/env`:

```bash
MONGO_URI=mongodb://username:password@localhost:27017/
MONGO_DB=pritunl
```

Then restart: `sudo systemctl restart pritunl-portfwd-ui pritunl-portfwd-daemon`

---

## Running on a non-default port

```bash
# /etc/pritunl-portfwd/env
LISTEN_PORT=9090
```

---

## IPv6 support

The daemon currently manages `iptables` (IPv4) only. To add IPv6:

1. Edit `daemon.py` and duplicate the `apply_forward` / `remove_forward` functions using `ip6tables`
2. Use `virtual_ip6` from Pritunl's client document (if available)
3. Ensure `net.ipv6.conf.all.forwarding = 1` in sysctl

IPv6 DNAT rules follow the same pattern:
```bash
ip6tables -t nat -A PREROUTING -p tcp --dport 8443 \
  -j DNAT --to-destination [fd00::5]:443
```

---

## Persisting iptables rules across reboots

The daemon re-applies all active rules at startup, so persistence is handled automatically as long as both systemd services are enabled. You do **not** need `iptables-persistent` for this to work.

If you want belt-and-suspenders persistence anyway:
```bash
sudo apt install iptables-persistent
sudo netfilter-persistent save
```

---

## Multiple Pritunl servers / clusters

If you run multiple Pritunl servers in a cluster, install pritunl-portfwd on each node. The `rules.json` file should be the same on all nodes — consider syncing it with a cron job or shared storage (e.g. NFS, rsync).

The daemon on each node will only apply rules for clients connected to **that node**.

---

## Adjusting poll interval

The default poll is every 10 seconds. For near-instant rule application:

```bash
# /etc/pritunl-portfwd/env
POLL_SECS=3
```

Lower values increase MongoDB query frequency but have negligible performance impact for typical deployments.

---

## Checking iptables rules manually

```bash
# View all active DNAT rules (pretty format)
sudo iptables -t nat -L PREROUTING -n -v --line-numbers

# View only portfwd rules
sudo iptables -t nat -S PREROUTING | grep pritunl-portfwd
sudo iptables -S FORWARD | grep pritunl-portfwd

# Count active portfwd rules
sudo iptables -t nat -S PREROUTING | grep -c pritunl-portfwd
```

---

## Locking down the Web UI with HTTP Basic Auth (nginx)

For an extra layer of protection on top of the application login:

```nginx
location /portfwd/ {
    auth_basic           "Port Forward Manager";
    auth_basic_user_file /etc/nginx/.portfwd-htpasswd;
    proxy_pass           http://127.0.0.1:8181/;
    ...
}
```

Generate the htpasswd file:
```bash
sudo apt install apache2-utils
sudo htpasswd -c /etc/nginx/.portfwd-htpasswd adminuser
```
