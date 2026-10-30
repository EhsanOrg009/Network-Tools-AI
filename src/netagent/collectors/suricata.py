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
from typing import Callable

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
    return ev, None


def dedupe_key_for(raw_line: str) -> str:
    return hashlib.sha256(raw_line.strip().encode("utf-8", "replace")).hexdigest()


class EveTailer:
    """Incremental tailer for ``eve.json``.

    State (inode + byte offset) can be persisted via ``state_writer`` so
    restarts resume where they left off instead of reprocessing the file.
    """

    def __init__(
        self,
        path: str | os.PathLike[str],
        initial_state: dict[str, int] | None = None,
        state_writer: Callable[[dict[str, int]], None] | None = None,
        max_lines_per_poll: int = 5000,
    ):
        self.path = Path(path)
        self.max_lines_per_poll = max_lines_per_poll
        self._fh = None
        self._inode: int | None = None
        self._offset: int = 0
        self._state_writer = state_writer
        self.last_error: str | None = None
        self.last_success: str | None = None
        self.events_seen: int = 0
        if initial_state:
            try:
                self._inode = int(initial_state.get("inode", 0)) or None
                self._offset = int(initial_state.get("offset", 0))
            except (TypeError, ValueError):
                pass

    # -- internals ----------------------------------------------------------

    def _stat(self) -> os.stat_result:
        try:
            return self.path.stat()
        except OSError as exc:
            self.last_error = f"{exc.__class__.__name__}: {exc.strerror or exc}"
            raise SuricataUnavailable(self.last_error) from exc

    def _open(self, st: os.stat_result, start_at_end: bool) -> None:
        self._close()
        try:
            self._fh = self.path.open("rb")
        except OSError as exc:
            self._fh = None
            self.last_error = f"{exc.__class__.__name__}: {exc.strerror or exc}"
            raise SuricataUnavailable(self.last_error) from exc
        self._inode = st.st_ino
        self._offset = st.st_size if start_at_end else 0
        self._fh.seek(self._offset)

    def _close(self) -> None:
        if self._fh is not None:
            try:
                self._fh.close()
            except OSError:
                pass
        self._fh = None

    # -- public ---------------------------------------------------------------

    def poll(self) -> TailResult:
        """Read newly appended lines. Raises SuricataUnavailable if the file
        cannot be stat-ed or opened; caller decides how to surface it."""
        result = TailResult()
        st = self._stat()

        if self._fh is None:
            # First open: resume stored offset only if the inode still matches.
            # With no prior state, read the existing backlog from the start
            # (dedupe keys protect against reprocessing on restarts).
            resume = self._inode == st.st_ino and self._offset <= st.st_size
            self._open(st, start_at_end=resume and self._offset > 0)
            result.rotated = not resume
        elif st.st_ino != self._inode:
            # Log rotation:Suricata replaced the file.
            self._open(st, start_at_end=False)
            result.rotated = True
        elif st.st_size < self._offset:
            # Truncated in place.
            self._open(st, start_at_end=False)
            result.rotated = True

        assert self._fh is not None
        count = 0
        while count < self.max_lines_per_poll:
            line_start = self._offset
            raw = self._fh.readline()
            if not raw:
                break
            if not raw.endswith(b"\n"):
                # Incomplete line (writer mid-write): rewind and retry later.
                self._fh.seek(line_start)
                result.truncated_at_end = True
                break
            self._offset = self._fh.tell()
            count += 1
            text = raw.decode("utf-8", "replace")
            ev, err = parse_eve_line(text)
            if err:
                result.malformed += 1
                self.last_error = err
                continue
            if ev is not None:
                result.events.append(ev)

        self._persist_state()
        self.last_error = None if not result.malformed else self.last_error
        self.last_success = datetime.now(timezone.utc).isoformat(timespec="seconds")
        self.events_seen += len(result.events)
        return result

    def _persist_state(self) -> None:
        if self._state_writer is None or self._inode is None:
            return
        try:
            self._state_writer({"inode": self._inode, "offset": self._offset})
        except Exception:  # pragma: no cover - state persistence must not break polling
            pass

    def state(self) -> dict[str, int] | None:
        if self._inode is None:
            return None
        return {"inode": self._inode, "offset": self._offset}

    def close(self) -> None:
        self._close()


def store_event(db, ev: ParsedEvent, raw_json: str) -> int | None:
    """Persist one parsed event (and its alert, if any) into the database.

    Returns the event row id, or None when the event was a duplicate.
    """
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
