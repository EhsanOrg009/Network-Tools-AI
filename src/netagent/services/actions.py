"""AI action proposals (v11) — the observe-first boundary of autonomy.

The analysis/question engines produce *suggestions* (e.g. "run an
investigation on this host"); this module records them as OBSERVED rows.
Nothing executes automatically: an admin decision (approve/reject) is the
only way forward, every decision is audited. This is the seam where later
phases attach a policy engine and explicit modes (Observe Only → Approval
Required → Controlled Autonomous) without changing the callers.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from typing import Any

from netagent.database import Database

KIND_RUN_INVESTIGATION = "run_investigation"


def propose_investigation(
    db: Database, *,
    alert_id: int | None = None, target_ip: str | None = None,
    rationale: str | None = None, dedupe_key: str | None = None,
    source: str = "ai-analysis", ref_alert_id: int | None = None,
) -> str | None:
    """Propose 'run an investigation' — deduped while OBSERVED."""
    fact = json.dumps(
        {"alert": alert_id, "ip": target_ip}, sort_keys=True
    )
    key = dedupe_key or hashlib.sha256(fact.encode()).hexdigest()[:24]
    action_id = f"actn_{uuid.uuid4().hex[:16]}"
    return db.propose_ai_action(
        action_id=action_id, kind=KIND_RUN_INVESTIGATION,
        rationale=rationale,
        target={
            **({"alert_id": alert_id} if alert_id is not None else {}),
            **({"target_ip": target_ip} if target_ip else {}),
            **({"ref_alert_id": ref_alert_id} if ref_alert_id is not None else {}),
        },
        dedupe_key=key, source=source,
    )
