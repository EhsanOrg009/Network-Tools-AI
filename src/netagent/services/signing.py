"""Versioned per-agent HMAC credentials; the new root never leaves the core."""

import hashlib
import hmac
import os
import secrets
import time
from pathlib import Path

DEADLINE_KEY = "task_signing_legacy_deadline_epoch"


def root_path(settings) -> Path:
    return settings.task_signing_v2_key_path or settings.database_path.parent / "task-signing-v2.key"


def server_root(settings) -> bytes:
    path = root_path(settings)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise ValueError("signing root must not be a symlink")
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        pass
    else:
        with os.fdopen(fd, "w") as stream:
            stream.write(secrets.token_hex(32))
            stream.flush()
            os.fsync(stream.fileno())
    if os.name == "posix" and path.stat().st_mode & 0o077:
        raise PermissionError("signing root requires mode 0600")
    value = bytes.fromhex(path.read_text().strip())
    if len(value) != 32:
        raise ValueError("invalid signing root length")
    return value


def key_id(settings) -> str:
    return hashlib.sha256(server_root(settings)).hexdigest()[:16]


def agent_key(settings, agent_id: str) -> str:
    return hmac.new(server_root(settings), f"netagent.admin-task.v2:{agent_id}".encode(), hashlib.sha256).hexdigest()


def initialize(db, settings):
    if not settings.task_signing_key:
        return
    server_root(settings)
    with db.transaction():
        if db.get_meta(DEADLINE_KEY) is None:
            db.set_meta(DEADLINE_KEY, str(time.time() + settings.task_signing_legacy_days * 86400))


def legacy_allowed(db, settings) -> bool:
    if not settings.task_signing_allow_legacy:
        return False
    initialize(db, settings)
    try:
        return time.time() < float(db.get_meta(DEADLINE_KEY) or "0")
    except ValueError:
        return False
