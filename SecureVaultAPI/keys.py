"""API key format, parsing and hashing (M4).

A key looks like  sv_<key_id>_<secret>
  key_id: 12 lowercase hex chars. Public: used to look the key up and safe to log.
  secret: 43 chars from secrets.token_urlsafe(32), i.e. 256 random bits. Never stored or logged.

Only SHA-256(secret) is stored. A slow hash (bcrypt/Argon2) protects low-entropy
human passwords; a 256-bit random secret can't be brute-forced, so a slow hash
would only add CPU cost per request (design decision D1).
"""

import hashlib
import hmac
import re
import secrets

PREFIX = "sv_"
_KEY_RE = re.compile(r"sv_([0-9a-f]{12})_([A-Za-z0-9_-]{43})")


def generate():
    """Return (key_id, secret, full_key)."""
    key_id = secrets.token_hex(6)
    secret = secrets.token_urlsafe(32)
    return key_id, secret, f"{PREFIX}{key_id}_{secret}"


def parse(full_key):
    """Return (key_id, secret), or None if full_key isn't exactly in the key format."""
    if not isinstance(full_key, str):
        return None
    match = _KEY_RE.fullmatch(full_key)
    return (match.group(1), match.group(2)) if match else None


def hash_secret(secret):
    return hashlib.sha256(secret.encode()).hexdigest()


def verify(secret, stored_hash):
    """Constant-time comparison of a presented secret against a stored hash."""
    return hmac.compare_digest(hash_secret(secret), stored_hash)
