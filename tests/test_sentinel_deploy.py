"""M3b follow-up: LogSentinel runs as its own unprivileged user, not the admin.

These check the deployment files statically. They can't prove the live box is set
up this way (that's in docs/m3b-firewall-evidence.md), but they stop the files in
the repo from drifting back to running LogSentinel as the admin user, as root, or
with settings that would silently break the firewall push.
"""

import ast
import os
import sys

import pytest

from conftest import REPO_ROOT

FIREWALL_DIR = os.path.join(REPO_ROOT, "deploy", "firewall")
SUDOERS = os.path.join(FIREWALL_DIR, "securevault.sudoers")
UNIT = os.path.join(FIREWALL_DIR, "securevault-sentinel.service")
README = os.path.join(FIREWALL_DIR, "README.md")
SENTINEL = os.path.join(REPO_ROOT, "LogSentinel", "sentinel.py")

SENTINEL_USER = "securevault-sentinel"
HELPER = "/usr/local/sbin/securevault-ban-ip"
LOG_PATH = "/var/log/securevault/app.log"
BLOCKLIST_PATH = "/var/lib/securevault/blocklist.txt"

# Each of these makes systemd set NoNewPrivileges=yes for a non-root service, which
# stops sudo from gaining root, so every firewall ban would fail (and LogSentinel
# would only log "FIREWALL BAN FAILED"). See systemd.exec(5), NoNewPrivileges=.
IMPLIES_NO_NEW_PRIVILEGES = {
    "DynamicUser", "LockPersonality", "MemoryDenyWriteExecute", "PrivateDevices",
    "ProtectClock", "ProtectHostname", "ProtectKernelLogs", "ProtectKernelModules",
    "ProtectKernelTunables", "RestrictAddressFamilies", "RestrictNamespaces",
    "RestrictRealtime", "RestrictSUIDSGID", "SystemCallArchitectures", "SystemCallFilter",
}


def _rules(path):
    with open(path, encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip() and not line.lstrip().startswith("#")]


def _service_section(path):
    """[Service] keys -> list of values (systemd allows repeated keys)."""
    out, section = {}, None
    with open(path, encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith(("#", ";")):
                continue
            if line.startswith("["):
                section = line
                continue
            if section == "[Service]":
                key, _, value = line.partition("=")
                out.setdefault(key.strip(), []).append(value.strip())
    return out


def _environment(service):
    env = {}
    for value in service.get("Environment", []):
        for pair in value.split():
            key, _, val = pair.strip('"').partition("=")
            env[key] = val
    return env


# --- sudoers ------------------------------------------------------------------

def test_sudoers_grants_only_the_helper_and_only_to_the_sentinel_user():
    assert _rules(SUDOERS) == [f"{SENTINEL_USER} ALL=(root) NOPASSWD: {HELPER}"]


def test_sudoers_no_longer_mentions_the_admin_user():
    assert not any("cardinal" in rule for rule in _rules(SUDOERS))


# --- systemd unit -------------------------------------------------------------

@pytest.fixture(scope="module")
def service():
    assert os.path.exists(UNIT), "deploy/firewall/securevault-sentinel.service is missing"
    return _service_section(UNIT)


def test_unit_runs_as_the_sentinel_user_not_root_or_the_admin(service):
    assert service.get("User") == [SENTINEL_USER]
    assert service.get("Group") == ["securevault"]


def test_unit_hides_home_so_the_vault_keys_and_db_are_unreachable(service):
    assert service.get("ProtectHome") == ["yes"]
    assert service.get("ProtectSystem") == ["strict"]
    for path in service.get("ReadWritePaths", []):
        assert "/home" not in path


def test_unit_does_not_block_sudo(service):
    assert service.get("NoNewPrivileges", ["no"]) == ["no"]
    assert IMPLIES_NO_NEW_PRIVILEGES.isdisjoint(service)


def test_unit_runs_the_root_owned_copy_with_isolated_system_python(service):
    (exec_start,) = service["ExecStart"]
    argv = exec_start.split()
    assert argv[0] == "/usr/bin/python3"
    assert "-I" in argv  # ignore PYTHON* env vars and user site-packages
    assert argv[-1] == "/opt/securevault/sentinel.py"


def test_unit_turns_on_the_firewall_push_and_uses_the_shared_paths(service):
    env = _environment(service)
    assert env.get("VAULT_FIREWALL_BAN") == "1"
    assert env.get("VAULT_LOG_PATH") == LOG_PATH
    assert env.get("VAULT_BLOCKLIST_PATH") == BLOCKLIST_PATH
    assert service.get("StateDirectory") == ["securevault"]


def test_readme_starts_the_api_with_the_same_paths_as_the_unit():
    # Coupled paths (CLAUDE.md): if the API and LogSentinel disagree, bans stop working.
    with open(README, encoding="utf-8") as f:
        text = f.read()
    assert f"VAULT_LOG_PATH={LOG_PATH}" in text
    assert f"VAULT_BLOCKLIST_PATH={BLOCKLIST_PATH}" in text


def test_readme_starts_the_api_with_a_umask_that_keeps_the_log_read_only_for_the_group():
    # Ubuntu's default umask (002) would make app.log group-writable, letting
    # LogSentinel's user forge or erase audit lines.
    with open(README, encoding="utf-8") as f:
        text = f.read()
    assert "(umask 027" in text


# --- sentinel.py can run without the venv ---------------------------------------

def test_sentinel_imports_only_the_standard_library():
    # The service runs /usr/bin/python3 -I with no venv, so a third-party import
    # would crash it at start.
    with open(SENTINEL, encoding="utf-8") as f:
        tree = ast.parse(f.read())
    modules = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0:
            modules.add(node.module.split(".")[0])
    assert modules <= set(sys.stdlib_module_names), modules - set(sys.stdlib_module_names)
