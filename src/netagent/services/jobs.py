"""In-process background job runner for long investigations.

The API must not block on multi-minute LLM investigations. Jobs run in
daemon threads; state is kept in memory with a bounded history. This is a
single-process design (matching the single-process uvicorn deployment);
jobs are not persisted across restarts.
"""

from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable

MAX_COMPLETED_JOBS = 50


@dataclass
class Job:
    id: str
    kind: str
    created_at: float
    status: str = "queued"  # queued | running | completed | failed
    result: Any = None
    error: str | None = None
    finished_at: float | None = None
    _thread: threading.Thread | None = field(default=None, repr=False)


class JobManager:
    def __init__(self) -> None:
        self._jobs: dict[str, Job] = {}
        self._lock = threading.Lock()

    def submit(self, kind: str, fn: Callable[[], Any]) -> str:
        job = Job(id=uuid.uuid4().hex[:12], kind=kind, created_at=time.time())
        job.status = "queued"

        def _run() -> None:
            job.status = "running"
            try:
                job.result = fn()
                job.status = "completed"
            except Exception as exc:  # surface the precise failure
                job.status = "failed"
                job.error = f"{exc.__class__.__name__}: {exc}"[:300]
            job.finished_at = time.time()

        job._thread = threading.Thread(target=_run, name=f"job-{job.id}", daemon=True)
        with self._lock:
            self._jobs[job.id] = job
            self._prune_locked()
        job._thread.start()
        return job.id

    def get(self, job_id: str) -> dict[str, Any] | None:
        with self._lock:
            job = self._jobs.get(job_id)
        if job is None:
            return None
        return {
            "id": job.id,
            "kind": job.kind,
            "status": job.status,
            "created_at": job.created_at,
            "finished_at": job.finished_at,
            "error": job.error,
            "result": job.result if job.status in ("completed", "failed") else None,
        }

    def _prune_locked(self) -> None:
        done = [j for j in self._jobs.values()
                if j.status in ("completed", "failed") and j._thread is not None
                and not j._thread.is_alive()]
        if len(done) <= MAX_COMPLETED_JOBS:
            return
        done.sort(key=lambda j: j.finished_at or 0)
        for j in done[: len(done) - MAX_COMPLETED_JOBS]:
            self._jobs.pop(j.id, None)
