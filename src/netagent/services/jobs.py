"""Bounded workers with persistent job state and cooperative cancellation."""

import queue
import logging
import sqlite3
import threading
import time
import uuid

from netagent.services.job_control import JobCancelled, JobContext, checkpoint, current_job

log = logging.getLogger(__name__)


class JobQueueFull(RuntimeError):
    pass


class JobManager:
    def __init__(self, db, settings):
        self.db, self.settings = db, settings
        self._queue = queue.Queue(maxsize=settings.job_queue_size)
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._threads = []
        self._contexts = {}
        self._started = False

    def start(self):
        with self._lock:
            if self._started:
                return
            self.db.interrupt_background_jobs()
            self._started = True
            for index in range(self.settings.job_workers):
                self._threads.append(threading.Thread(target=self._worker, name=f"job-worker-{index}", daemon=True))
            self._threads.append(threading.Thread(target=self._deadlines, name="job-deadlines", daemon=True))
            for thread in self._threads:
                thread.start()

    def submit(self, kind, fn):
        with self._lock:
            if self._stop.is_set():
                raise JobQueueFull("job manager is shutting down")
            self.start()
            if self._queue.full():
                raise JobQueueFull("job queue is full")
            job_id = uuid.uuid4().hex
            self.db.create_background_job(job_id, kind, self.settings.job_timeout_seconds)
            self._contexts[job_id] = JobContext(threading.Event())
            self._queue.put_nowait((job_id, fn))
            return job_id

    def get(self, job_id):
        return self.db.get_background_job(job_id)

    def cancel(self, job_id):
        with self._lock:
            job = self.get(job_id)
            if not job:
                return None
            context = self._contexts.get(job_id)
            if context:
                context.cancel.set()
            self.db.update_background_job(job_id, "cancelled", error="cancelled by administrator")
            return self.get(job_id)

    def _persist(self, job_id, status, **kwargs):
        # Keep a completed result in its bounded worker until storage returns;
        # never execute the callable again because persistence failed.
        while True:
            try:
                self.db.update_background_job(job_id, status, **kwargs)
                return True
            except sqlite3.Error:
                log.exception("job persistence unavailable; retaining result")
                if self._stop.wait(1):
                    return False

    def _worker(self):
        while not self._stop.is_set():
            try:
                job_id, fn = self._queue.get(timeout=0.1)
            except queue.Empty:
                continue
            token = None
            try:
                with self._lock:
                    context = self._contexts[job_id]
                    if self.get(job_id)["status"] != "queued":
                        continue
                    context.deadline = time.monotonic() + self.settings.job_timeout_seconds
                    if not self._persist(job_id, "running"):
                        raise JobCancelled("shutdown before durable job claim")
                token = current_job.set(context)
                checkpoint()
                result = fn()
                checkpoint()
                self._persist(job_id, "completed", result=result)
            except JobCancelled as exc:
                self._persist(job_id, "cancelled", error=str(exc))
            except Exception as exc:
                self._persist(job_id, "failed", error=f"{type(exc).__name__}: {exc}"[:500])
            finally:
                if token is not None:
                    current_job.reset(token)
                with self._lock:
                    self._contexts.pop(job_id, None)
                self._queue.task_done()

    def _deadlines(self):
        while not self._stop.wait(0.1):
            with self._lock:
                for job_id, context in self._contexts.items():
                    if time.monotonic() >= context.deadline:
                        try:
                            if self.get(job_id)["status"] == "running":
                                self.db.update_background_job(job_id, "failed", error="JobTimedOut: job deadline exceeded")
                        except sqlite3.Error:
                            log.exception("job deadline persistence unavailable")

    def shutdown(self):
        self._stop.set()
        with self._lock:
            for job_id, context in self._contexts.items():
                context.cancel.set()
                self.db.update_background_job(job_id, "interrupted", error="server shutdown; not rerun")
        deadline = time.monotonic() + self.settings.job_shutdown_seconds
        for thread in self._threads:
            thread.join(timeout=max(0, deadline - time.monotonic()))
        return not any(thread.is_alive() for thread in self._threads)
