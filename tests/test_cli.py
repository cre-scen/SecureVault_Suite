"""M4: vault_cli.py user and key management."""

import logging
import os
import sqlite3

import pytest

import keys
import vault_cli
from conftest import TMP_DIR


def run(capsys, *argv):
    code = vault_cli.main(list(argv))
    out = capsys.readouterr().out
    return code, out


def printed_key(out):
    found = [w for w in out.split() if keys.parse(w)]
    assert len(found) == 1, out
    return found[0]


def test_user_create_prints_a_working_key_once(client, capsys):
    code, out = run(capsys, "user", "create", "carol")
    assert code == 0
    key = printed_key(out)
    assert client.get("/secret/x", headers={"X-API-Key": key}).status_code == 404


def test_user_list_shows_ids_and_status_but_never_secrets_or_hashes(client, alice, capsys, app_module):
    code, out = run(capsys, "user", "list")
    assert code == 0
    assert "alice" in out and alice.key_id in out
    assert alice.secret not in out and keys.hash_secret(alice.secret) not in out
    assert not any(keys.parse(w) for w in out.split())


def test_user_create_rejects_duplicates_and_bad_names(client, alice, capsys):
    assert run(capsys, "user", "create", "alice")[0] != 0
    assert run(capsys, "user", "create", "bad name")[0] != 0


def test_key_issue_gives_a_second_working_key(client, alice, capsys):
    code, out = run(capsys, "key", "issue", "alice")
    assert code == 0
    second = printed_key(out)
    assert second != alice.key
    assert client.get("/secret/x", headers={"X-API-Key": second}).status_code == 404
    assert client.get("/secret/x", headers=alice.headers).status_code == 404


def test_key_revoke_kills_only_that_key(client, alice, capsys):
    _, out = run(capsys, "key", "issue", "alice")
    second = printed_key(out)
    assert run(capsys, "key", "revoke", alice.key_id)[0] == 0
    assert client.get("/secret/x", headers=alice.headers).status_code == 401
    assert client.get("/secret/x", headers={"X-API-Key": second}).status_code == 404


def test_user_disable_stops_all_their_keys(client, alice, bob, capsys):
    assert run(capsys, "user", "disable", "alice")[0] == 0
    assert client.get("/secret/x", headers=alice.headers).status_code == 401
    assert client.get("/secret/x", headers=bob.headers).status_code == 404


def test_unknown_user_or_key_fails_cleanly(client, capsys):
    assert run(capsys, "key", "issue", "nobody")[0] != 0
    assert run(capsys, "key", "revoke", "000000000000")[0] != 0
    assert run(capsys, "key", "unlock", "000000000000")[0] != 0
    assert run(capsys, "user", "disable", "nobody")[0] != 0


def test_cli_actions_are_audited_without_secrets(client, capsys, caplog):
    caplog.set_level(logging.INFO)
    _, out = run(capsys, "user", "create", "dave")
    key = printed_key(out)
    key_id, secret = keys.parse(key)
    run(capsys, "key", "revoke", key_id)
    msgs = [r.getMessage() for r in caplog.records if r.getMessage().startswith("AUDIT ")]
    assert any("action=cli_user_create" in m and "user=dave" in m and f"key={key_id}" in m for m in msgs), msgs
    assert any("action=cli_key_revoke" in m and f"key={key_id}" in m for m in msgs), msgs
    assert not any(secret in m for m in msgs)


def test_migrate_command_upgrades_and_prints_one_key(capsys, app_module, monkeypatch):
    path = os.path.join(TMP_DIR, "cli_v0.db")
    if os.path.exists(path):
        os.remove(path)
    with sqlite3.connect(path) as conn:
        conn.execute("CREATE TABLE secrets (id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, "
                     "secret_data TEXT NOT NULL)")
    monkeypatch.setattr(vault_cli, "DB_PATH", path)
    code, out = run(capsys, "migrate", "--owner", "martin")
    assert code == 0
    printed_key(out)
    code, out = run(capsys, "migrate", "--owner", "martin")
    assert code == 0 and "already" in out.lower()
    assert not any(keys.parse(w) for w in out.split())


@pytest.mark.parametrize("argv", [[], ["user"], ["key"], ["bogus"]])
def test_bad_usage_exits_nonzero(argv, capsys):
    with pytest.raises(SystemExit) as e:
        vault_cli.main(argv)
    assert e.value.code != 0
