"""Background Suricata ingest loop.

Only ingests events; it never runs scans or privileged commands. Poll
failures are recorded and surfaced through the health endpoint while the
application keeps running.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from typing import Any

from netagent.collectors.suricata import (
    EveTailer,
    SuricataUnavailable,
    store_event,
)
from netagent.config import Settings
from netagent.database import Database

log = logging.getLogger("netagent.monitor")

META_KEY = "eve_tailer_state"


class Monitor:
    """Owns the tailer + health snapshot for one running application."""

    def __init__(self, db: Database, settings: Settings):
        self.db = db
        self.settings = settings

        state_raw = db.get_meta(META_KEY)
        initial_state = None
        if state_raw:
            try:
                initial_state = json.loads(state_raw)
            except (TypeError, ValueError):
                initial_state = None

        self.tailer = EveTailer(
            settings.suricata_eve_path,
            initial_state=initial_state,
            state_writer=self._persist_state,
        )
        self.last_poll_at: str | None = None
        self.last_error: str | None = None
        self.consecutive_errors: int = 0
        self.events_ingested: int = 0
        self.duplicates_skipped: int = 0
        self.malformed_skipped: int = 0
        self.rotations: int = 0
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    # -- state persistence -----------------------------------------------------

    def _persist_state(self, state: dict[str, int]) -> None:
        try:
            self.db.set_meta(META_KEY, json.dumps(state))
        except Exception:  # pragma: no cover
            pass

    # -- polling ---------------------------------------------------------------

    def poll_once(self) -> dict[str, Any]:
        """One incremental ingest pass; safe to call from tests/CLI too."""
        try:
            result = self.tailer.poll()
        except SuricataUnavailable as exc:
            self.last_error = str(exc)
            self.consecutive_errors += 1
            log.warning("suricata unavailable: %s", exc)
            return {"ok": False, "error": str(exc)}

        ingested = 0
        for ev in result.events:
            raw = json.dumps(ev.payload, ensure_ascii=False, separators=(",", ":"))
            try:
                event_id = store_event(self.db, ev, raw)
            except Exception as exc:  # defensive: one bad event must not stop ingest
                self.last_error = f"store failed: {exc.__class__.__name__}"
                log.exception("failed to store event")
                continue
            if event_id is None:
                self.duplicates_skipped += 1
            else:
                ingested += 1
        self.events_ingested += ingested
        self.malformed_skipped += result.malformed
        if result.rotated:
            self.rotations += 1
            log.info("eve.json rotated; restarted from beginning")
        self.last_poll_at = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        if result.events:
            self.last_error = None
            self.consecutive_errors = 0
        return {
            "ok": True,
            "ingested": ingested,
            "malformed": result.malformed,
            "rotated": result.rotated,
        }

    def _loop(self) -> None:
        interval = max(1.0, float(self.settings.monitor_interval_seconds))
        while not self._stop.is_set():
            try:
                self.poll_once()
            except Exception:  # pragma: no cover - loop must never die
                log.exception("unexpected monitor error")
                self.consecutive_errors += 1
            self._stop.wait(interval)

    def start(self) -> None:
        if self._thread is not None:
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._loop, name="netagent-monitor", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
        self._thread = None
        self.tailer.close()

    # -- health snapshot ---------------------------------------------------------

    def health(self) -> dict[str, Any]:
        try:
            stat_ok = self.settings.suricata_eve_path.exists()
            readable = stat_ok and _readable(self.settings.suricata_eve_path)
        except OSError:
            stat_ok, readable = False, False
        return {
            "suricata": {
                "eve_path": str(self.settings.suricata_eve_path),
                "interface": self.settings.monitor_interface,
                "file_exists": stat_ok,
                "file_readable": readable,
                "last_poll_at": self.last_poll_at,
                "last_error": self.last_error,
                "consecutive_errors": self.consecutive_errors,
                "events_ingested": self.events_ingested,
                "duplicates_skipped": self.duplicates_skipped,
                "malformed_skipped": self.malformed_skipped,
                "rotations": self.rotations,
                "tailer_state": self.tailer.state(),
            },
        }


def _readable(path) -> bool:
    try:
        with open(path, "rb") as fh:
            fh.read(1)
        return True
    except OSError:
        return False
