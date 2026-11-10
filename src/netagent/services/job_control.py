"""Cooperative cancellation and deadlines shared by bounded job workers."""

import contextvars
import time
from dataclasses import dataclass
from threading import Event


class JobCancelled(RuntimeError):
    pass


class JobTimedOut(RuntimeError):
    pass


@dataclass
class JobContext:
    cancel: Event
    deadline: float = float("inf")


current_job = contextvars.ContextVar("netagent_job", default=None)


def checkpoint():
    context = current_job.get()
    if context:
        if time.monotonic() >= context.deadline:
            raise JobTimedOut("job deadline exceeded")
        if context.cancel.is_set():
            raise JobCancelled("job cancelled")


def bounded_timeout(timeout):
    checkpoint()
    context = current_job.get()
    return min(timeout, max(0.001, context.deadline - time.monotonic())) if context else timeout
