# Host firewall (M3b)

Turns LogSentinel's bans into **firewall drops** on the lab box, so a banned IP never reaches Python again, and narrows what the network can reach in the first place.

```
                     ┌──────────────── lab box (Xubuntu) ─────────────────┐
 Kali 192.168.0.104 ─┤ nftables  table inet securevault  (priority -10)    │
                     │   ip saddr @banned_v4 → drop     ◄─── ban helper ◄──┼─ LogSentinel, own user
                     │ ufw (priority 0): default deny inbound              │   (sudo -n, one command)
                     │   22/tcp   from admin laptop only                   │
                     │   5000/tcp from 192.168.0.0/24 (SecureVault API)    │
                     └─────────────────────────────────────────────────────┘
```

## Files

| File | Installed as | Purpose |
|---|---|---|
| `securevault.nft` | `/etc/securevault/securevault.nft` | Separate nftables table with an expiring ban set (`timeout 1h`) |
| `securevault-firewall.service` | `/etc/systemd/system/` | Loads the table at boot. **Don't** enable the distro's `nftables.service`: its default config runs `flush ruleset`, which would wipe ufw |
| `ban_ip.py` | `/usr/local/sbin/securevault-ban-ip` | The only thing LogSentinel can run as root. It accepts exactly one canonical unicast IPv4 address and calls `nft` with a fixed argument list |
| `securevault.sudoers` | `/etc/sudoers.d/securevault` | Lets `securevault-sentinel` run the helper, and nothing else, without a password |
| `securevault-sentinel.service` | `/etc/systemd/system/` | Runs LogSentinel as `securevault-sentinel` (no login, no home), sandboxed, at boot |
| `../../LogSentinel/sentinel.py` | `/opt/securevault/sentinel.py` | Root-owned copy the service runs, so its user can't edit its own code |
| `never-ban.example` | `/etc/securevault/never-ban` | Addresses the helper refuses to ban (the admin laptop) |

## Design decisions

- **ufw keeps the base policy; nftables only bans.** Two tools editing one ruleset fight each other. A separate table at a higher-priority hook avoids that.
- **LogSentinel never runs as root, or as the admin.** A log parser fed by attacker-controlled input is exactly what you don't want running as root. The root part is a small helper that validates its input itself, because sudo passes arguments through unchecked. LogSentinel has its own system user, `securevault-sentinel`: if it's compromised, the attacker can't read the vault's `.env` (Fernet key, API key) or database (`ProtectHome=yes` hides `/home` entirely), and can't use the admin's sudo.
- **The two shared files moved out of the repo**, so both users can reach them without opening up `/home`: `app.log` in `/var/log/securevault/` (the API writes, LogSentinel reads) and `blocklist.txt` in `/var/lib/securevault/` (LogSentinel writes, the API reads). The group `securevault` connects them.
- **No `NoNewPrivileges=yes`** on the service, nor any option that implies it: it would stop `sudo` from gaining root, so every firewall ban would fail.
- **Bans expire** (1 hour), because a shared NAT IP or a mistake shouldn't be permanent. `blocklist.txt` still blocks at the app level.
- **The admin laptop is on a never-ban list**, so a forged or mistaken ban can't lock out the person who has to fix it.
- **The helper and the service's copy of `sentinel.py` are root-owned.** If the calling user could edit the helper, the sudoers rule would be a root shell.

## Prerequisites

1. **Reserve the admin laptop's IP** (`192.168.0.101`) in the Tenda router (IP-MAC Binding), the same way as the lab box. Step 5 restricts SSH to that one address, so if the laptop's IP moves, you lose SSH.
2. Kali VM with a **bridged** adapter on `192.168.0.0/24`.
3. Keep **one SSH session open** the whole time; open a second one to test each change.

## Install (on the lab box)

```bash
# 1. Get the code
sudo apt install -y python3-venv nftables git
git clone https://github.com/cre-scen/SecureVault_Suite.git ~/SecureVault_Suite
cd ~/SecureVault_Suite
python3 -m venv venv && . venv/bin/activate && pip install -r requirements.txt

# 2. LogSentinel's own user (no login, no home) and the group that shares files with the API
sudo groupadd --system securevault
sudo useradd --system --gid securevault --no-create-home --home-dir /nonexistent \
  --shell /usr/sbin/nologin securevault-sentinel
sudo usermod -aG securevault cardinal       # the API reads blocklist.txt through this group
sudo install -d -o cardinal -g securevault -m 2750 /var/log/securevault   # API writes, sentinel reads
id securevault-sentinel                     # expect: gid=...(securevault), no other groups

# 3. Install the firewall pieces (root-owned, so neither user can modify them)
sudo install -d -m 0755 /etc/securevault
sudo install -m 0644 -o root -g root deploy/firewall/securevault.nft /etc/securevault/
sudo install -m 0644 -o root -g root deploy/firewall/never-ban.example /etc/securevault/never-ban
sudo install -m 0755 -o root -g root deploy/firewall/ban_ip.py /usr/local/sbin/securevault-ban-ip
sudo install -m 0644 -o root -g root deploy/firewall/securevault-firewall.service /etc/systemd/system/
sudo visudo -cf deploy/firewall/securevault.sudoers && \
  sudo install -m 0440 -o root -g root deploy/firewall/securevault.sudoers /etc/sudoers.d/securevault
sudo install -d -m 0755 /opt/securevault
sudo install -m 0644 -o root -g root LogSentinel/sentinel.py /opt/securevault/
sudo install -m 0644 -o root -g root deploy/firewall/securevault-sentinel.service /etc/systemd/system/

# 4. Load the ban table now and at every boot
sudo systemctl daemon-reload
sudo systemctl enable --now securevault-firewall.service
sudo nft list table inet securevault        # expect: set banned_v4, chain input, priority filter - 10

# 5. Narrow ufw: SSH from the admin laptop only, API from the lab subnet only
#    (add the new SSH rule BEFORE deleting the old ones)
sudo ufw allow from 192.168.0.101 to any port 22 proto tcp comment 'SSH: admin laptop'
sudo ufw delete allow from 192.168.0.0/24 to any port 22 proto tcp
sudo ufw delete allow from 192.168.100.0/24 to any port 22 proto tcp
sudo ufw allow from 192.168.0.0/24 to any port 5000 proto tcp comment 'SecureVault API (lab)'
sudo ufw status numbered
```

## Run

**Log in again first** (a new SSH session) so `cardinal` picks up the `securevault` group: `id` must list `securevault`. Without it the API can't read `blocklist.txt`, and every request fails with `500` (it fails closed).

API, in a terminal on the box (inside `~/SecureVault_Suite`, venv active). The debugger stays off and refuses to start on a LAN address:

```bash
cd SecureVaultAPI
# Create .env with fresh keys, without showing them on screen (never commit it)
if [ -e .env ]; then echo ".env already exists"; else
umask 077; python - <<'EOF'
import secrets
from cryptography.fernet import Fernet
with open(".env", "w") as f:
    f.write(f"VALID_API_KEY={secrets.token_urlsafe(32)}\n"
            f"VAULT_ENCRYPTION_KEY={Fernet.generate_key().decode()}\n")
EOF
fi
python db_test.py
# umask 027: app.log must not be group-writable, or LogSentinel's user could forge
# or erase audit lines. The two paths must match securevault-sentinel.service.
(umask 027
 VAULT_HOST=192.168.0.103 \
 VAULT_LOG_PATH=/var/log/securevault/app.log \
 VAULT_BLOCKLIST_PATH=/var/lib/securevault/blocklist.txt \
 python app.py)
```

In another terminal: `ls -l /var/log/securevault/` must show `app.log` as `-rw-r----- cardinal securevault`. If it shows `-rw-rw-r--` (created earlier without the umask), run `chmod 640 /var/log/securevault/app.log*`.

LogSentinel, as a service (it waits for `app.log` to appear):

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now securevault-sentinel.service
journalctl -u securevault-sentinel -f       # its alerts and FIREWALL lines appear here
```

After pulling a new `sentinel.py`, re-run the `install … /opt/securevault/` line and `sudo systemctl restart securevault-sentinel`.

### Check the separation

```bash
ps -o user:24=,args= -C python3 | grep sentinel            # expect: securevault-sentinel /usr/bin/python3 -I -u /opt/securevault/sentinel.py
sudo ls -A /proc/$(systemctl show -p MainPID --value securevault-sentinel)/root/home   # expect: nothing (the service sees an empty /home)
sudo -u securevault-sentinel sudo -n id; echo "exit=$?"     # expect: refused, exit 1 (no sudo beyond the helper)
sudo -u securevault-sentinel sudo -n securevault-ban-ip 192.0.2.10   # expect: banned 192.0.2.10 (TEST-NET, harmless)
sudo nft delete element inet securevault banned_v4 '{ 192.0.2.10 }'
ls -l /var/lib/securevault/                                 # after the first ban: blocklist.txt  -rw-r----- securevault-sentinel securevault
```

## Prove it (from Kali)

```bash
nmap -Pn -p- --min-rate 1000 192.168.0.103 -oN after-m3b.txt   # expect: 5000/tcp open, 22 filtered (Kali isn't the admin)
for i in 1 2 3 4 5; do curl -s -o /dev/null -w "%{http_code}\n" -H "X-API-Key: wrong" http://192.168.0.103:5000/secret/x; done
curl -m 5 -s -o /dev/null -w "%{http_code}\n" http://192.168.0.103:5000/   # expect: 000 after a timeout (dropped, no HTTP reply)
```

On the box:

```bash
sudo nft list set inet securevault banned_v4    # expect: 192.168.0.104 expires 59m…
sudo nft list chain inet securevault input      # the drop counter climbs as Kali retries
```

**Expiry:** to watch a ban expire without waiting an hour, reload with a short timeout, ban again, then reload normally:

```bash
sed 's/timeout 1h/timeout 2m/' /etc/securevault/securevault.nft | sudo nft -f -
sudo securevault-ban-ip 192.168.0.104 && sleep 125 && sudo nft list set inet securevault banned_v4   # empty again
sudo systemctl restart securevault-firewall.service    # back to 1h
```

**Unban by hand:** `sudo nft delete element inet securevault banned_v4 '{ 192.168.0.104 }'`, and remove the app-level entry with `sudo sed -i '/^192\.168\.0\.104,/d' /var/lib/securevault/blocklist.txt`.

**Moving from the first M3b setup** (LogSentinel run by hand as `cardinal`): stop that process, then follow Install step 2 and the new lines in step 3. The new `blocklist.txt` starts empty, so IPs blocked in the old repo-root file are no longer refused by the app.

## Tested

- `tests/test_firewall.py`: the helper rejects 16 kinds of bad input (shell and nft injection, CIDRs, leading zeros, IPv6, loopback, broadcast, multicast, whitespace) and the never-ban list; it calls nft with a fixed argument list. LogSentinel only calls the helper when `VAULT_FIREWALL_BAN=1`, uses `sudo -n`, and keeps the app-level block if the push fails. The API binds to localhost by default and the debugger refuses a LAN address.
- End to end on real kernel nftables, using two network namespaces: an attacker got `200`, then after the real helper ran, connections were dropped (counter climbed). An nft injection attempt was refused with the table intact. After the (test) timeout, the attacker got `200` again.
- `tests/test_sentinel_deploy.py`: the sudoers rule grants only the helper and only to `securevault-sentinel`; the unit runs as that user with `ProtectHome=yes` and `ProtectSystem=strict`, sets none of the options that would block sudo, runs the root-owned copy with `python3 -I`, and uses the same two paths as the API command above; `sentinel.py` imports only the standard library.
- Permissions, with stand-in users (`cardinal` and `securevault-sentinel` in a test container, no systemd): LogSentinel as its own user detected 5 × `401`, wrote `blocklist.txt` as `-rw-r----- securevault-sentinel securevault`; the API user could read it and an unrelated user couldn't; LogSentinel's user couldn't write `app.log` or read `cardinal`'s `.env`. The sudo push and the systemd sandbox still need the live run.
- **Live on the lab box (2026-11-04)**, LogSentinel still run by hand as `cardinal`, with a Kali VM as the attacker: nmap before and after, a brute force banned and dropped (no HTTP response), and expiry. Full output in [docs/m3b-firewall-evidence.md](../../docs/m3b-firewall-evidence.md).
