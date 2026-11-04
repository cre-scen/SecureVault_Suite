#!/usr/bin/python3 -I
"""Add one IPv4 address to the SecureVault nftables ban set.

Installed as /usr/local/sbin/securevault-ban-ip (root:root, 0755) and called
by LogSentinel through a sudoers rule that allows this one command only.
Because it runs as root on input that came from a log file, it accepts exactly
one argument, and only if that argument is a plain, unicast IPv4 host address
written in canonical form. Anything else is refused before nft is called, and
nft is always called with a fixed argument list, never through a shell.

`-I` (isolated mode) makes Python ignore PYTHON* variables and the user's
site-packages, so the calling user can't inject code into this root process.

Exit codes: 0 banned, 1 nft failed, 2 invalid input, 3 address is protected.
The ban expires on its own: the set has a default timeout (securevault.nft).
"""

import ipaddress

# subprocess is needed to call nft; the arguments are fixed and validated above
import subprocess  # nosec B404
import sys

NFT = "/usr/sbin/nft"
TABLE_FAMILY, TABLE, SET = "inet", "securevault", "banned_v4"
# One address or CIDR per line; '#' starts a comment. Put the admin machine here
# so a typo or a forged log line can never lock the administrator out.
NEVER_BAN_FILE = "/etc/securevault/never-ban"


def parse_target(arg):
    """Return the IPv4Address to ban, or None if `arg` isn't acceptable."""
    try:
        ip = ipaddress.IPv4Address(arg)
    except ValueError:
        return None
    # Canonical form only: rejects "010.1.1.1", whitespace, and anything odd
    if str(ip) != arg:
        return None
    if ip.is_loopback or ip.is_multicast or ip.is_unspecified or ip.is_reserved or ip.is_link_local:
        return None
    if ip == ipaddress.IPv4Address("255.255.255.255"):
        return None
    return ip


def protected_networks(path):
    nets = []
    try:
        with open(path, encoding="ascii") as f:
            for line in f:
                line = line.split("#", 1)[0].strip()
                if line:
                    nets.append(ipaddress.IPv4Network(line, strict=False))
    except FileNotFoundError:
        pass
    return nets


def main(argv):
    if len(argv) != 2:
        print("usage: securevault-ban-ip <ipv4-address>", file=sys.stderr)
        return 2
    ip = parse_target(argv[1])
    if ip is None:
        print("refused: not a single unicast IPv4 host address", file=sys.stderr)
        return 2
    if any(ip in net for net in protected_networks(NEVER_BAN_FILE)):
        print(f"refused: {ip} is on the never-ban list", file=sys.stderr)
        return 3
    cmd = [NFT, "add", "element", TABLE_FAMILY, TABLE, SET, f"{{ {ip} }}"]
    # Fixed argv, no shell, and the only variable part is a validated IPv4Address
    result = subprocess.run(cmd, check=False, timeout=10)  # nosec B603
    if result.returncode != 0:
        print(f"nft failed with exit code {result.returncode}", file=sys.stderr)
        return 1
    print(f"banned {ip}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
