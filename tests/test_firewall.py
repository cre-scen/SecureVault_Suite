"""M3b: the ban-ip helper (runs as root via sudo) and LogSentinel's firewall hook."""

import importlib.util
import os
import subprocess

import pytest

import sentinel
from conftest import REPO_ROOT

HELPER_PATH = os.path.join(REPO_ROOT, "deploy", "firewall", "ban_ip.py")


@pytest.fixture
def ban_ip(monkeypatch, tmp_path):
    spec = importlib.util.spec_from_file_location("ban_ip", HELPER_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    # Never read the real /etc file from tests
    monkeypatch.setattr(mod, "NEVER_BAN_FILE", str(tmp_path / "never-ban"))
    return mod


@pytest.fixture
def nft_calls(ban_ip, monkeypatch):
    calls = []

    def fake_run(cmd, **kw):
        calls.append((cmd, kw))
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr(ban_ip.subprocess, "run", fake_run)
    return calls


# --- Helper: input validation (it runs as root, so it must refuse anything odd) ---

@pytest.mark.parametrize("arg", [
    "",
    "abc",
    "1.2.3.4; rm -rf /",      # shell metacharacters
    "1.2.3.4 } ; flush ruleset ; {",  # nft syntax injection
    "1.2.3.4/24",             # a whole network, not one host
    "1.2.3",
    "1.2.3.4.5",
    "010.1.1.1",              # leading zeros (ambiguous: octal on some parsers)
    "::1",                    # IPv6 is out of scope for the v4 set
    "2001:db8::1",
    "127.0.0.1",              # loopback: would break local services
    "0.0.0.0",
    "255.255.255.255",
    "224.0.0.1",              # multicast
    " 203.0.113.5",           # surrounding whitespace
    "203.0.113.5\n",
])
def test_helper_rejects_anything_that_is_not_one_plain_ipv4_host(ban_ip, nft_calls, arg):
    assert ban_ip.main(["ban-ip", arg]) == 2
    assert nft_calls == []


def test_helper_rejects_wrong_argument_count(ban_ip, nft_calls):
    assert ban_ip.main(["ban-ip"]) == 2
    assert ban_ip.main(["ban-ip", "203.0.113.5", "198.51.100.7"]) == 2
    assert nft_calls == []


def test_helper_bans_a_valid_ip_with_a_fixed_argument_list(ban_ip, nft_calls):
    assert ban_ip.main(["ban-ip", "203.0.113.5"]) == 0
    assert len(nft_calls) == 1
    cmd, kw = nft_calls[0]
    assert cmd == [ban_ip.NFT, "add", "element", "inet", "securevault", "banned_v4", "{ 203.0.113.5 }"]
    assert kw.get("shell") in (None, False)  # never through a shell


def test_helper_refuses_ips_on_the_never_ban_list(ban_ip, nft_calls):
    with open(ban_ip.NEVER_BAN_FILE, "w") as f:
        f.write("# admin laptop\n192.168.0.101\n10.9.0.0/16\n\n")
    assert ban_ip.main(["ban-ip", "192.168.0.101"]) == 3
    assert ban_ip.main(["ban-ip", "10.9.4.4"]) == 3
    assert nft_calls == []
    assert ban_ip.main(["ban-ip", "192.168.0.104"]) == 0  # not protected


def test_helper_reports_nft_failure(ban_ip, monkeypatch):
    monkeypatch.setattr(
        ban_ip.subprocess, "run", lambda cmd, **kw: subprocess.CompletedProcess(cmd, 1)
    )
    assert ban_ip.main(["ban-ip", "203.0.113.5"]) == 1


# --- LogSentinel hook ----------------------------------------------------------

@pytest.fixture
def sentinel_calls(monkeypatch, tmp_path):
    calls = []

    def fake_run(cmd, **kw):
        calls.append((cmd, kw))
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr(sentinel.subprocess, "run", fake_run)
    monkeypatch.setattr(sentinel, "BLOCKLIST_PATH", str(tmp_path / "blocklist.txt"))
    return calls


def test_sentinel_does_not_touch_the_firewall_by_default(sentinel_calls, monkeypatch):
    monkeypatch.delenv("VAULT_FIREWALL_BAN", raising=False)
    sentinel.block_ip("192.168.0.104")
    assert sentinel_calls == []
    with open(sentinel.BLOCKLIST_PATH) as f:
        assert f.read().startswith("192.168.0.104,")


def test_sentinel_pushes_the_ban_through_the_helper_when_enabled(sentinel_calls, monkeypatch):
    monkeypatch.setenv("VAULT_FIREWALL_BAN", "1")
    sentinel.block_ip("192.168.0.104")
    assert len(sentinel_calls) == 1
    cmd, kw = sentinel_calls[0]
    # sudo -n: never prompt; fail instead if the sudoers rule is missing
    assert cmd == ["sudo", "-n", sentinel.BAN_HELPER, "192.168.0.104"]
    assert kw.get("shell") in (None, False)
    assert kw.get("timeout")


@pytest.mark.parametrize("failure", ["nonzero", "missing", "timeout"])
def test_sentinel_keeps_the_app_level_block_if_the_firewall_push_fails(monkeypatch, tmp_path, failure):
    def fake_run(cmd, **kw):
        if failure == "missing":
            raise FileNotFoundError("sudo")
        if failure == "timeout":
            raise subprocess.TimeoutExpired(cmd, kw.get("timeout", 10))
        return subprocess.CompletedProcess(cmd, 1)

    monkeypatch.setattr(sentinel.subprocess, "run", fake_run)
    monkeypatch.setattr(sentinel, "BLOCKLIST_PATH", str(tmp_path / "blocklist.txt"))
    monkeypatch.setenv("VAULT_FIREWALL_BAN", "1")
    sentinel.block_ip("192.168.0.104")  # must not raise
    with open(sentinel.BLOCKLIST_PATH) as f:
        assert f.read().startswith("192.168.0.104,")


# --- API bind address ----------------------------------------------------------

def test_api_binds_to_localhost_unless_vault_host_is_set(app_module, monkeypatch):
    calls = {}
    monkeypatch.setattr(app_module.app, "run", lambda **kw: calls.update(kw))
    monkeypatch.delenv("VAULT_DEBUG", raising=False)
    monkeypatch.delenv("VAULT_HOST", raising=False)
    app_module.run_server()
    assert calls["host"] == "127.0.0.1"

    monkeypatch.setenv("VAULT_HOST", "192.168.0.103")
    app_module.run_server()
    assert calls["host"] == "192.168.0.103"
    assert calls["debug"] is False


def test_debugger_refuses_to_run_on_a_network_address(app_module, monkeypatch):
    monkeypatch.setattr(app_module.app, "run", lambda **kw: pytest.fail("must not start"))
    monkeypatch.setenv("VAULT_DEBUG", "1")
    monkeypatch.setenv("VAULT_HOST", "0.0.0.0")
    with pytest.raises(SystemExit):
        app_module.run_server()
