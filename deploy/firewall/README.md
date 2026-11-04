# Host firewall (M3b)

Turns LogSentinel's bans into **firewall drops** on the lab box, so a banned IP never reaches Python again, and narrows what the network can reach in the first place.

```
                     ┌──────────────── lab box (Xubuntu) ─────────────────┐
 Kali 192.168.0.104 ─┤ nftables  table inet securevault  (priority -10)    │
                     │   ip saddr @banned_v4 → drop     ◄─── ban helper ◄──┼─ LogSentinel
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
| `securevault.sudoers` | `/etc/sudoers.d/securevault` | Lets `cardinal` run the helper, and nothing else, without a password |
| `never-ban.example` | `/etc/securevault/never-ban` | Addresses the helper refuses to ban (the admin laptop) |

## Design decisions

- **ufw keeps the base policy; nftables only bans.** Two tools editing one ruleset fight each other. A separate table at a higher-priority hook avoids that.
- **LogSentinel never runs as root.** A log parser fed by attacker-controlled input is exactly what you don't want running as root. The root part is a small helper that validates its input itself, because sudo passes arguments through unchecked.
- **Bans expire** (1 hour), because a shared NAT IP or a mistake shouldn't be permanent. `blocklist.txt` still blocks at the app level.
- **The admin laptop is on a never-ban list**, so a forged or mistaken ban can't lock out the person who has to fix it.
- **The helper is root-owned and not writable by `cardinal`.** If the calling user could edit the helper, the sudoers rule would be a root shell.

## Prerequisites

1. **Reserve the admin laptop's IP** (`192.168.0.101`) in the Tenda router (IP-MAC Binding), the same way as the lab box. Step 4 restricts SSH to that one address, so if the laptop's IP moves, you lose SSH.
2. Kali VM with a **bridged** adapter on `192.168.0.0/24`.
3. Keep **one SSH session open** the whole time; open a second one to test each change.

## Install (on the lab box)

```bash
# 1. Get the code
sudo apt install -y python3-venv nftables git
git clone https://github.com/cre-scen/SecureVault_Suite.git ~/SecureVault_Suite
cd ~/SecureVault_Suite
python3 -m venv venv && . venv/bin/activate && pip install -r requirements.txt

# 2. Install the firewall pieces (root-owned, so cardinal can't modify them)
sudo install -d -m 0755 /etc/securevault
sudo install -m 0644 -o root -g root deploy/firewall/securevault.nft /etc/securevault/
sudo install -m 0644 -o root -g root deploy/firewall/never-ban.example /etc/securevault/never-ban
sudo install -m 0755 -o root -g root deploy/firewall/ban_ip.py /usr/local/sbin/securevault-ban-ip
sudo install -m 0644 -o root -g root deploy/firewall/securevault-firewall.service /etc/systemd/system/
sudo visudo -cf deploy/firewall/securevault.sudoers && \
  sudo install -m 0440 -o root -g root deploy/firewall/securevault.sudoers /etc/sudoers.d/securevault

# 3. Load the ban table now and at every boot
sudo systemctl daemon-reload
sudo systemctl enable --now securevault-firewall.service
sudo nft list table inet securevault        # expect: set banned_v4, chain input, priority filter - 10

# 4. Narrow ufw: SSH from the admin laptop only, API from the lab subnet only
#    (add the new SSH rule BEFORE deleting the old ones)
sudo ufw allow from 192.168.0.101 to any port 22 proto tcp comment 'SSH: admin laptop'
sudo ufw delete allow from 192.168.0.0/24 to any port 22 proto tcp
sudo ufw delete allow from 192.168.100.0/24 to any port 22 proto tcp
sudo ufw allow from 192.168.0.0/24 to any port 5000 proto tcp comment 'SecureVault API (lab)'
sudo ufw status numbered
```

## Run

Two terminals on the box (inside `~/SecureVault_Suite`, venv active):

```bash
# Terminal A: API on the LAN address (the debugger stays off and refuses to start on a LAN address)
cd SecureVaultAPI && cp -n .env.example .env
# Put real values in .env (never commit it):
#   VALID_API_KEY:        python -c "import secrets; print(secrets.token_urlsafe(32))"
#   VAULT_ENCRYPTION_KEY: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
nano .env
python db_test.py
VAULT_HOST=192.168.0.103 python app.py

# Terminal B: LogSentinel, also pushing bans to the firewall
cd LogSentinel && VAULT_FIREWALL_BAN=1 python sentinel.py
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

**Unban by hand:** `sudo nft delete element inet securevault banned_v4 '{ 192.168.0.104 }'` (and remove the line from `blocklist.txt`).

## Tested

- `tests/test_firewall.py`: the helper rejects 16 kinds of bad input (shell and nft injection, CIDRs, leading zeros, IPv6, loopback, broadcast, multicast, whitespace) and the never-ban list; it calls nft with a fixed argument list. LogSentinel only calls the helper when `VAULT_FIREWALL_BAN=1`, uses `sudo -n`, and keeps the app-level block if the push fails. The API binds to localhost by default and the debugger refuses a LAN address.
- End to end on real kernel nftables, using two network namespaces: an attacker got `200`, then after the real helper ran, connections were dropped (counter climbed). An nft injection attempt was refused with the table intact. After the (test) timeout, the attacker got `200` again.
