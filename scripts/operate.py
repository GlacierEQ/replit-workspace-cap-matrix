#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from workspace_cap_matrix import Decision, WorkspaceCapMatrix, WorkspaceCapMatrixRequest


def _grant() -> dict:
    return {
        "grant_id": "workspace-file-write",
        "workspace_id": "ws-demo",
        "principal_id": "agent-demo",
        "capability": "file.write",
        "resource_patterns": ["src/**"],
        "max_units": 5.0,
        "used_units": 1.0,
        "epoch": 7,
        "expires_at": 200.0,
        "revoked": False,
    }


def _action(epoch: int = 7) -> dict:
    return {
        "action_id": "write-main",
        "workspace_id": "ws-demo",
        "principal_id": "agent-demo",
        "capability": "file.write",
        "resource": "src/main.py",
        "cost_units": 2.0,
        "required_epoch": epoch,
    }


def main() -> int:
    engine = WorkspaceCapMatrix()
    dispatch = engine.evaluate(
        WorkspaceCapMatrixRequest(
            "operate-demo",
            {"mode": "dispatch", "now": 100.0, "grants": [_grant()], "action": _action()},
            budget=10.0,
        )
    )
    if dispatch.decision is not Decision.ALLOW:
        print(json.dumps(dispatch.as_dict(), indent=2, sort_keys=True))
        return 2

    persisted = dispatch.metrics["result"]["updated_grants"]
    inspect = engine.evaluate(
        WorkspaceCapMatrixRequest(
            "operate-demo",
            {
                "mode": "inspect",
                "now": 101.0,
                "grants": persisted,
                "workspace_id": "ws-demo",
                "principal_id": "agent-demo",
            },
            budget=10.0,
        )
    )

    revoke = engine.evaluate(
        WorkspaceCapMatrixRequest(
            "operate-demo",
            {"mode": "revoke", "grants": persisted, "grant_id": "workspace-file-write"},
            budget=10.0,
            grant_id="workspace-file-write",
        )
    )
    revoked_matrix = revoke.metrics["result"]["grants"] if revoke.decision is Decision.ALLOW else []

    stale = engine.evaluate(
        WorkspaceCapMatrixRequest(
            "operate-demo",
            {"mode": "dispatch", "now": 102.0, "grants": revoked_matrix, "action": _action(epoch=7)},
            budget=10.0,
        )
    )

    print(
        json.dumps(
            {
                "dispatch": dispatch.as_dict(),
                "inspect": inspect.as_dict(),
                "revoke": revoke.as_dict(),
                "stale_after_revoke": stale.as_dict(),
            },
            indent=2,
            sort_keys=True,
        )
    )

    if inspect.decision is not Decision.ALLOW or inspect.metrics["result"]["active_count"] != 1:
        return 3
    if revoke.decision is not Decision.ALLOW:
        return 4
    if stale.decision is not Decision.REFUSE:
        return 5
    rejected = stale.metrics["result"]["rejected"][0]["reasons"]
    if "grant_epoch_stale" not in rejected or "grant_revoked" not in rejected:
        return 6
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
