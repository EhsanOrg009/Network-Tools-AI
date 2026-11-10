"""Incremental Suricata EVE JSON reader.

- Reads appended lines only (persistent offset + inode state in SQLite meta).
- Survives malformed / truncated lines without crashing.
- Detects rotation (inode change) and truncation (file shrank).
- Never requires sudo; unreadable files surface as SuricataUnavailable so the
  health endpoint can show the exact problem.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from pydantic import ValidationError

from netagent.database import parse_iso_epoch
from netagent.schemas import ParsedEvent

STATE_KEY = "eve_tailer_state"


class SuricataUnavailable(RuntimeError):
    """Suricata log missing or unreadable; the app keeps operating."""


@dataclass
class TailResult:
    events: list[ParsedEvent] = field(default_factory=list)
    malformed: int = 0
    rotated: bool = False
    truncated_at_end: bool = False
    cursor: dict[str, Any] | None = None
    recovery_warning: str | None = None


def parse_eve_line(line: str) -> tuple[ParsedEvent | None, str | None]:
    """Parse one EVE JSON line.

    Returns (event, None) on success, (None, error_description) on failure.
    Never raises on bad data.
    """
    line = line.strip()
    if not line:
        return None, None
    try:
        payload = json.loads(line)
    except (json.JSONDecodeError, ValueError) as exc:
        return None, f"invalid JSON: {exc.__class__.__name__}"
    if not isinstance(payload, dict):
        return None, "record is not a JSON object"

    alert = payload.get("alert")
    if alert is not None and not isinstance(alert, dict):
        alert = None

    try:
        ev = ParsedEvent(
            ts=payload.get("timestamp"),
            ts_epoch=parse_iso_epoch(payload.get("timestamp")),
            event_type=payload.get("event_type"),
            flow_id=payload.get("flow_id"),
            src_ip=payload.get("src_ip"),
            src_port=payload.get("src_port"),
            dest_ip=payload.get("dest_ip"),
            dest_port=payload.get("dest_port"),
            proto=payload.get("proto"),
            app_proto=payload.get("app_proto"),
            ingress=payload.get("in_iface"),
            alert=alert,
            payload=payload,
        )
    except (ValidationError, TypeError, ValueError, OverflowError) as exc:
        return None, f"invalid event: {exc.__class__.__name__}"
    return ev, None


def dedupe_key_for(raw_line: str) -> str:
    return hashlib.sha256(raw_line.strip().encode("utf-8", "replace")).hexdigest()


class EveTailer:
    """At-least-once reader: poll returns a pending batch until acknowledged.

    The consumer must persist events and cursor together before acknowledging.
    A rotated file is drained first, using its open descriptor or saved inode.
    """

    def __init__(self, path, initial_state=None, state_writer=None,
                 max_lines_per_poll=5000):
        self.path = Path(path)
        self.max_lines_per_poll = max_lines_per_poll
        self._fh = None
        self._inode = None
        self._device = None
        self._offset = 0
        self._state_writer = state_writer
        self._pending = None
        self._committed = None
        self.last_error = None
        self.last_success = None
        self.events_seen = 0
        if initial_state:
            try:
                self._inode = int(initial_state.get("inode", 0)) or None
                self._device = initial_state.get("device")
                self._offset = max(0, int(initial_state.get("offset", 0)))
                self._committed = dict(initial_state)
            except (ValueError, TypeError):
                self._inode, self._offset = None, 0

    def _matches(self, st):
        return st.st_ino == self._inode and (self._device is None or st.st_dev == self._device)

    def _open(self, path, *, resume=False):
        fh = path.open("rb", buffering=0)
        st = os.fstat(fh.fileno())
        offset = self._offset if resume and self._matches(st) and self._offset <= st.st_size else 0
        self.close()
        self._fh = fh
        self._inode, self._device, self._offset = st.st_ino, st.st_dev, offset
        fh.seek(offset)

    def _anchor(self, offset):
        position = self._fh.tell()
        try:
            start = max(0, offset - 128)
            self._fh.seek(start)
            return hashlib.sha256(self._fh.read(offset - start)).hexdigest()
        finally:
            self._fh.seek(position)

    def _recover_rotated_path(self):
        if self._inode is None:
            return None
        for path in self.path.parent.glob(self.path.stem + "*"):
            try:
                if not path.is_symlink() and path.is_file() and self._matches(path.stat()):
                    return path
            except OSError:
                continue
        return None

    def poll(self) -> TailResult:
        if self._pending is not None:
            return self._pending
        result = TailResult()
        try:
            if self._fh is None:
                recovered = self._recover_rotated_path()
                if recovered is not None:
                    self._open(recovered, resume=True)
                else:
                    if self._inode is not None:
                        result.recovery_warning = "persisted EVE inode unavailable; unread rotated bytes cannot be recovered"
                    self._open(self.path)
                    result.rotated = True
            # Read the descriptor we already own, even while the path is
            # temporarily absent during a rename/recreate rotation.
            current = os.fstat(self._fh.fileno())
            changed_anchor = self._matches_state(self._committed) and self._committed.get("anchor") and self._anchor(self._offset) != self._committed["anchor"]
            if current.st_size < self._offset or changed_anchor:
                self._offset = 0
                self._fh.seek(0)
                result.rotated = True
            count = 0
            while count < self.max_lines_per_poll:
                start = self._fh.tell()
                raw = self._fh.readline()
                if not raw:
                    try:
                        latest = self.path.stat()
                    except FileNotFoundError:
                        break
                    if not self._matches(latest) and count == 0:
                        self._open(self.path)
                        result.rotated = True
                        continue
                    break
                if not raw.endswith(b"\n"):
                    self._fh.seek(start)
                    result.truncated_at_end = True
                    break
                self._offset = self._fh.tell()
                count += 1
                event, error = parse_eve_line(raw.decode("utf-8", "replace"))
                if error:
                    result.malformed += 1
                    self.last_error = error
                elif event is not None:
                    result.events.append(event)
            result.cursor = {"inode": self._inode, "device": self._device, "offset": self._offset, "anchor": self._anchor(self._offset)}
            self._pending = result
            return result
        except OSError as exc:
            # No returned batch => rewind to the last durable position on
            # the same descriptor; do not forget an unlinked rotated file.
            if self._fh is not None:
                offset = (self._committed or {}).get("offset", 0) if self._matches_state(self._committed) else 0
                self._fh.seek(offset)
                self._offset = offset
            self.last_error = f"{exc.__class__.__name__}: {exc}"
            raise SuricataUnavailable(self.last_error) from exc

    def _matches_state(self, state):
        return state and state.get("inode") == self._inode and state.get("device", self._device) == self._device

    def acknowledge(self, *, persist=True):
        """Call only after durable event storage; failures retain the batch."""
        if self._pending is None:
            return
        if persist and self._state_writer:
            self._state_writer(self._pending.cursor)
        self._committed = dict(self._pending.cursor)
        self.events_seen += len(self._pending.events)
        self.last_success = datetime.now(timezone.utc).isoformat(timespec="seconds")
        self.last_error = self._pending.recovery_warning
        self._pending = None

    def state(self):
        return dict(self._committed) if self._committed else None

    def close(self):
        if self._fh is not None:
            self._fh.close()
        self._fh = None


def store_event(db, ev: ParsedEvent, raw_json: str) -> int | None:
    """Persist one parsed event (and its alert, if any) into the database.

    Returns the event row id, or None when the event was a duplicate.
    """
    with db.transaction():
        record = {
            "ts": ev.ts,
            "ts_epoch": ev.ts_epoch,
            "event_type": ev.event_type,
            "flow_id": ev.flow_id,
            "src_ip": ev.src_ip,
            "src_port": ev.src_port,
            "dest_ip": ev.dest_ip,
            "dest_port": ev.dest_port,
            "proto": ev.proto,
            "app_proto": ev.app_proto,
            "ingress": ev.ingress,
        }
        event_id = db.insert_event(record, raw_json, dedupe_key_for(raw_json))
        if event_id is None:
            return None
        if ev.alert is not None:
            alert_data = dict(record)
            alert_data.update(
                {
                    "signature": ev.alert.get("signature"),
                    "signature_id": _safe_int(ev.alert.get("signature_id")),
                    "signature_rev": _safe_int(ev.alert.get("revision")),
                    "category": ev.alert.get("category"),
                    "severity": _safe_int(ev.alert.get("severity")),
                    # NOTE: action == "allowed" means Suricata *logged* the alert
                    # while the packet was allowed through. It does NOT mean the
                    # traffic was blocked, and must never be reported as blocked.
                    "action": ev.alert.get("action"),
                    "metadata": ev.alert.get("metadata"),
                }
            )
            db.insert_alert(event_id, alert_data)
        for ip in (ev.src_ip, ev.dest_ip):
            if ip:
                db.upsert_host(ip)
        return event_id


def _safe_int(value) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
