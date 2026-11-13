"""Security primitives for endpoint agents and the administrator control plane.

Rules enforced here:
- Long-lived secrets are never stored in plaintext: only SHA-256 hashes are
  persisted; verification uses ``hmac.compare_digest`` (constant time).
- Task envelopes for the administrator control plane are signed with
  HMAC-SHA256 (standard library) over a canonical JSON encoding. No custom
  cryptography: HMAC-SHA256 is an established construction.
- Secrets never appear in logs or API examples; functions here raise or
  return booleans instead of echoing secret material.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from typing import Any

MIN_ADMIN_TOKEN_LEN = 16


def generate_token(prefix: str = "na") -> str:
    """Generate a fresh URL-safe secret token. The value is shown exactly
    once to the caller; only its hash is stored."""
    return f"{prefix}_{secrets.token_urlsafe(32)}"


def hash_secret(secret: str) -> str:
    """SHA-256 of the secret, hex-encoded. Deterministic so the stored hash
    can be verified with a constant-time comparison."""
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def secret_matches(secret: str, stored_hash: str) -> bool:
    """Constant-time verification of a secret against its stored hash."""
    if not secret or not stored_hash:
        return False
    return hmac.compare_digest(hash_secret(secret).encode("utf-8"), stored_hash.encode("utf-8"))


def admin_token_configured(raw_token: str | None, hashed_token: str | None) -> bool:
    """True when a usable administrator token is configured.

    Accepts either a plaintext token (ADMIN_API_TOKEN) or its SHA-256 hash
    (ADMIN_API_TOKEN_SHA256). A too-short plaintext token is refused so an
    accidental weak default cannot silently enable the admin control plane.
    """
    if hashed_token and len(hashed_token) >= 32:
        return True
    if raw_token and len(raw_token.strip()) >= MIN_ADMIN_TOKEN_LEN:
        return True
    return False


def verify_admin_token(presented: str, raw_token: str | None, hashed_token: str | None) -> bool:
    if not presented:
        return False
    if hashed_token and len(hashed_token) >= 32:
        return secret_matches(presented, hashed_token.strip())
    if raw_token:
        expected = raw_token.strip()
        if len(expected) < MIN_ADMIN_TOKEN_LEN:
            return False
        # HTTP credentials are untrusted text; compare_digest(str, str)
        # raises TypeError for non-ASCII instead of rejecting the token.
        return hmac.compare_digest(presented.encode("utf-8"), expected.encode("utf-8"))
    return False


def canonical_json(payload: dict[str, Any]) -> bytes:
    """Stable byte encoding used as the HMAC input for task envelopes."""
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str
    ).encode("utf-8")


def sign_task(payload: dict[str, Any], key: str) -> str:
    """HMAC-SHA256 signature over the canonical task payload."""
    return hmac.new(key.encode("utf-8"), canonical_json(payload), hashlib.sha256).hexdigest()


def verify_task_signature(payload: dict[str, Any], key: str, signature: str) -> bool:
    if not key or not signature or not signature.isascii():
        return False
    try:
        expected = sign_task(payload, key)
    except (TypeError, ValueError):
        return False
    return hmac.compare_digest(expected, signature)
