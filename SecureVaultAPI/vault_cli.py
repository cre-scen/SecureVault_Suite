"""SecureVault admin CLI (M4): users, API keys and the pre-M4 migration.

    python vault_cli.py migrate --owner NAME
    python vault_cli.py user create NAME | list | disable NAME
    python vault_cli.py key issue NAME | revoke KEY_ID | unlock KEY_ID

It talks to the database directly, so access control is the DB file's
permission: whoever can write test_vault.db can manage users. A new key is
printed exactly once, at creation; only its SHA-256 hash is stored.
"""

import argparse
import logging
import os
import sys
from contextlib import closing
from logging.handlers import RotatingFileHandler

import accounts
import schema

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.getenv("VAULT_DB_PATH") or os.path.join(BASE_DIR, "test_vault.db")
LOG_PATH = os.getenv("VAULT_LOG_PATH") or os.path.join(BASE_DIR, "app.log")

log = logging.getLogger("securevault.cli")


def audit(action, result, user="-", key="-"):
    # Same AUDIT shape as app.py; ip=local marks it as a CLI action
    log.info("AUDIT action=cli_%s result=%s ip=local user=%s key=%s", action, result, user, key)


def _show_key(full_key):
    print(full_key)
    print("[!] Store this key now. It is shown once and can't be recovered.")


def _cmd_migrate(args):
    result = schema.migrate(DB_PATH, args.owner)
    if not result.migrated:
        print(f"[*] Already at schema v{schema.CURRENT_VERSION}; nothing to do.")
        audit("migrate", "no_op", args.owner)
        return
    if result.backup_path:
        print(f"[*] Backup written to {result.backup_path}")
    print(f"[+] Upgraded to schema v{schema.CURRENT_VERSION}; "
          f"{result.secrets_assigned} secret(s) now owned by {args.owner}.")
    if os.getenv("VALID_API_KEY"):
        print("[!] VALID_API_KEY is still set in the environment/.env. It is ignored now; remove it.")
    _show_key(result.key)
    audit("migrate", "ok", args.owner, result.key.split("_")[1])


def _cmd_user_create(conn, args):
    _, full_key = accounts.create_user(conn, args.name)
    _show_key(full_key)
    audit("user_create", "ok", args.name, full_key.split("_")[1])


def _cmd_user_list(conn, args):
    rows = accounts.list_users(conn)
    if not rows:
        print("(no users)")
    for r in rows:
        if r["key_id"] is None:
            status = "no keys"
        elif r["revoked"]:
            status = "revoked"
        elif r["locked_until"]:
            status = "locked"
        else:
            status = "active"
        user = r["name"] + (" (disabled)" if r["disabled"] else "")
        print(f"{user:<28} {r['key_id'] or '-':<14} {status:<8} last used {r['last_used_at'] or 'never'}")
    audit("user_list", "ok")


def _cmd_user_disable(conn, args):
    accounts.disable_user(conn, args.name)
    print(f"[+] {args.name} disabled; all their keys stop working now.")
    audit("user_disable", "ok", args.name)


def _cmd_key_issue(conn, args):
    full_key = accounts.issue_key(conn, args.name)
    _show_key(full_key)
    audit("key_issue", "ok", args.name, full_key.split("_")[1])


def _cmd_key_revoke(conn, args):
    accounts.revoke_key(conn, args.key_id)
    print(f"[+] Key {args.key_id} revoked.")
    audit("key_revoke", "ok", key=args.key_id)


def _cmd_key_unlock(conn, args):
    accounts.unlock_key(conn, args.key_id)
    print(f"[+] Key {args.key_id} unlocked.")
    audit("key_unlock", "ok", key=args.key_id)


def build_parser():
    p = argparse.ArgumentParser(prog="vault_cli.py", description="SecureVault users and API keys")
    sub = p.add_subparsers(dest="command", required=True)

    m = sub.add_parser("migrate", help="upgrade a pre-M4 database and issue the owner's first key")
    m.add_argument("--owner", required=True)
    m.set_defaults(func=_cmd_migrate, needs_db=False)

    user = sub.add_parser("user").add_subparsers(dest="action", required=True)
    c = user.add_parser("create")
    c.add_argument("name")
    c.set_defaults(func=_cmd_user_create)
    user.add_parser("list").set_defaults(func=_cmd_user_list)
    d = user.add_parser("disable")
    d.add_argument("name")
    d.set_defaults(func=_cmd_user_disable)

    key = sub.add_parser("key").add_subparsers(dest="action", required=True)
    i = key.add_parser("issue")
    i.add_argument("name")
    i.set_defaults(func=_cmd_key_issue)
    for action, func in (("revoke", _cmd_key_revoke), ("unlock", _cmd_key_unlock)):
        k = key.add_parser(action)
        k.add_argument("key_id")
        k.set_defaults(func=func)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        if getattr(args, "needs_db", True):
            with closing(accounts.connect(DB_PATH)) as conn:
                schema.init_db(conn)
                args.func(conn, args)
        else:
            args.func(args)
    except (accounts.AccountError, schema.NeedsMigration) as e:
        print(f"[-] {e}", file=sys.stderr)
        audit(args.command + "_" + getattr(args, "action", ""), "error")
        return 1
    return 0


def _setup_file_logging():
    handler = RotatingFileHandler(LOG_PATH, maxBytes=1_000_000, backupCount=3)
    handler.setFormatter(logging.Formatter("%(asctime)s - %(message)s"))
    log.addHandler(handler)
    log.setLevel(logging.INFO)


if __name__ == "__main__":
    _setup_file_logging()
    sys.exit(main())
