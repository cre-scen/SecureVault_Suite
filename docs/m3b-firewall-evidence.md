# M3b evidence: host firewall on the lab box

Live run on 2026-11-04 (times are EAT, UTC+3). Output below is copied from the terminals; nothing is paraphrased except where marked. Setup and design are in [deploy/firewall/README.md](../deploy/firewall/README.md).

| Machine | Address | Role |
|---|---|---|
| Lab box (HP Chromebook, Xubuntu, user `cardinal`) | `192.168.0.103`, reserved on the router | Runs the API, LogSentinel, ufw and the nftables ban table |
| Admin laptop (Windows) | `192.168.0.101`, reserved on the router (IP-MAC binding to the Wi-Fi adapter) | The only SSH source after M3b |
| Kali VM, bridged adapter | `192.168.0.104` | Attacker / scanner |

Code under test: `main` at `4b370c8` (merge of PR #9).

## Definition of done

| Item (PLAN.md, M3b) | Result | Section |
|---|---|---|
| nmap from another lab VM shows only the allowed ports | Before: `22/tcp open`. After: `5000/tcp open`, SSH filtered from Kali | [1](#1-exposure-before-and-after) |
| A simulated brute force puts the attacker's IP in the set, and its next connections are dropped with no HTTP response | Banned at 22:44:11; next connection timed out; drop counter 5 packets | [3](#3-brute-force-ban-drop) |
| The ban expires after the timeout | 2-minute test timeout: set emptied, then Kali got an HTTP `403` (app-level fallback) instead of a drop | [4](#4-expiry) |
| Tests show the helper rejects anything that isn't an IP | `tests/test_firewall.py` in CI, plus the live checks below as LogSentinel calls it | [2](#ban-helper-called-the-way-logsentinel-calls-it) |
| Threat model updated | T13, T14 and the new boundary updated | [threat-model.md](threat-model.md) |

## 1. Exposure before and after

From Kali: `nmap -Pn -p- --min-rate 1000 192.168.0.103`

Before M3b (21:55; ufw allowed SSH from `192.168.0.0/24` and `192.168.100.0/24`):
```
Not shown: 65534 filtered tcp ports (no-response)
PORT   STATE SERVICE
22/tcp open  ssh
Nmap done: 1 IP address (1 host up) scanned in 144.56 seconds
```

After M3b (22:30; API running):
```
Not shown: 65534 filtered tcp ports (no-response)
PORT     STATE SERVICE
5000/tcp open  upnp
Nmap done: 1 IP address (1 host up) scanned in 144.40 seconds
```
`upnp` is only nmap's name for port 5000; the service is the SecureVault API. SSH is filtered from Kali because only `192.168.0.101` may reach it.

The first baseline attempt (21:54) reported `0 hosts up` in 0.48 s: the ARP request from the bridged adapter got no reply, so nmap had nothing to scan, even with `-Pn`. An immediate re-run worked, and the file above is from that run.

ufw after the change:
```
$ sudo ufw status
Status: active

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW       192.168.0.101              # SSH: admin laptop
5000/tcp                   ALLOW       192.168.0.0/24             # SecureVault API (lab)
```
A new SSH login from the laptop worked after the old subnet rules were deleted (the first session stayed open throughout).

What listens, on the box:
```
$ ss -tlnH | grep -E ':5000|:22'
LISTEN 0      4096         0.0.0.0:22         0.0.0.0:*
LISTEN 0      128    192.168.0.103:5000       0.0.0.0:*
LISTEN 0      4096            [::]:22            [::]:*
$ tail -3 SecureVaultAPI/app.log
... WARNING: This is a development server. ...
 * Running on http://192.168.0.103:5000
```
The API binds to the LAN address only (not `0.0.0.0`) with `Debug mode: off`. sshd also listens on IPv6, but there is no IPv6 allow rule, so ufw's default policy drops it.

## 2. Ban table and helper

Table loaded by `securevault-firewall.service` (enabled at boot), with ufw untouched afterwards:
```
table inet securevault {
        set banned_v4 {
                type ipv4_addr
                timeout 1h
        }
        chain input {
                type filter hook input priority filter - 10; policy accept;
                ip saddr @banned_v4 counter packets 0 bytes 0 drop comment "LogSentinel bans"
        }
}
```
`nftables.service` stays `disabled`: its default config runs `flush ruleset`, which would wipe ufw.

### Ban helper, called the way LogSentinel calls it

The sudo password cache was cleared first (`sudo -k`), so `sudo -n` could only succeed through the NOPASSWD rule:
```
$ sudo -n securevault-ban-ip '1.2.3.4; id'; echo "exit=$?"
refused: not a single unicast IPv4 host address
exit=2
$ sudo -n securevault-ban-ip 192.168.0.0/24; echo "exit=$?"
refused: not a single unicast IPv4 host address
exit=2
$ sudo -n securevault-ban-ip 192.168.0.101; echo "exit=$?"
refused: 192.168.0.101 is on the never-ban list
exit=3
$ sudo -n securevault-ban-ip 192.0.2.10; echo "exit=$?"
banned 192.0.2.10
exit=0
```
`192.0.2.10` is a documentation address (TEST-NET-1); it appeared as `expires 59m36s197ms` and was then deleted by hand. The installed files are root-owned, so `cardinal` can't modify them: helper `-rwxr-xr-x root root`, `/etc/sudoers.d/securevault` `-r--r----- root root`. `sudo -l` showed `(root) NOPASSWD: /usr/local/sbin/securevault-ban-ip`. The box uses sudo-rs, and the rule behaves the same.

## 3. Brute force, ban, drop

API in one SSH session (`VAULT_HOST=192.168.0.103 python app.py`), LogSentinel in a fresh one (`VAULT_FIREWALL_BAN=1 python sentinel.py`, no sudo run in that session).

From Kali, five wrong keys:
```
$ for i in 1 2 3 4 5; do curl -s -o /dev/null -w "%{http_code}\n" -H "X-API-Key: wrong" http://192.168.0.103:5000/secret/x; done
401
401
401
401
401
```
LogSentinel:
```
[!] Hit detected from 192.168.0.104. Count: 1/5
...
[!] Hit detected from 192.168.0.104. Count: 5/5
!!! SECURITY ALERT: BRUTE FORCE DETECTED !!!
[#] ACTION TAKEN: 192.168.0.104 BLOCKED!
[#] TIME: 2026-11-04 22:44:11
[#] LOCATION: Local Network

banned 192.168.0.104
[#] FIREWALL: 192.168.0.104 dropped at nftables (expires automatically)
```
On the box:
```
$ sudo nft list set inet securevault banned_v4
                elements = { 192.168.0.104 expires 54m43s596ms }
$ tail -2 blocklist.txt
192.168.0.104,2026-11-04 22:44:11,Local Network
```
Kali's next connection (22:51:20) got no HTTP response at all:
```
$ curl -v -m 5 http://192.168.0.103:5000/ 2>&1 | tail -3
* closing connection #0
curl: (28) Connection timed out after 5003 milliseconds
```
and the drop rule counted it:
```
ip saddr @banned_v4 counter packets 5 bytes 300 drop comment "LogSentinel bans"
```
Five 60-byte packets is the size of TCP connection attempts (SYNs) and their retries, all dropped before ufw or Python saw them. The exact packet count depends on Kali's retry timing; the point is that it rose from 0 while the connection got no reply. An earlier attempt at 22:46 had a typo in the address (`192168.0.103`) and never left Kali, which is why the counter was still 0 when first checked; it is not counted as evidence.

## 4. Expiry

To avoid waiting an hour, the table was reloaded with a 2-minute timeout (`sed 's/timeout 1h/timeout 2m/' … | sudo nft -f -`, which also cleared the live ban) and Kali was banned by hand:
```
$ sudo securevault-ban-ip 192.168.0.104; date
banned 192.168.0.104
Wed Nov  4 10:53:05 PM EAT 2026
$ sudo nft list set inet securevault banned_v4
                timeout 2m
                elements = { 192.168.0.104 expires 1m59s944ms }
```
After the timeout:
```
$ sudo nft list set inet securevault banned_v4
                timeout 2m
        }            # no elements line: the ban removed itself
```
Kali, more than four minutes after the ban:
```
Wed Nov  4 10:57:32 PM EAT 2026
403
Wed Nov  4 10:57:52 PM EAT 2026
403
```
An immediate `403` (not a timeout) shows the firewall no longer drops Kali, while `blocklist.txt` still refuses it in the app: the intended fallback.

Gaps in this run, stated plainly: no Kali request was made during the 2-minute ban, and the empty-set listing has no timestamp. The drop itself is proven in section 3, and the `403`s at 22:57 come well after the 22:55 expiry.

## Remaining exposure

See "Residual risks accepted at M3b" in [threat-model.md](threat-model.md). In short: the API is reachable from the whole LAN on the dev server while it runs, LogSentinel runs as the admin user, bans are IPv4 only, and reloading the table clears every ban.
