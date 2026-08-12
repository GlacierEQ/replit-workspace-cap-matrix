#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from workspace_cap_matrix import Decision, WorkspaceCapMatrix, WorkspaceCapMatrixRequest


def main() -> int:
    matrix = WorkspaceCapMatrix(
        [
            {
                "grant_id": "workspace-read",
                "subject_id": "agent-demo",
                "capability": "file.read",
                "scopes": ["/workspace/src"],
                "max_cost": 0.5,
                "expires_at": 2000,
            },
            {
                "grant_id": "python-shell",
                "subject_id": "agent-demo",
                "capability": "shell.exec",
                "scopes": ["python"],
                "max_cost": 1.0,
                "expires_at": 2000,
            },
        ],
        clock=lambda: 1000,
    )

    allowed = matrix.evaluate(
        WorkspaceCapMatrixRequest(
            subject_id="agent-demo",
            payload={"action": {"capability": "file.read", "resource": "/workspace/src/main.py", "cost": 0.2}},
            budget=0.5,
        )
    )
    escaped = matrix.evaluate(
        WorkspaceCapMatrixRequest(
            subject_id="agent-demo",
            payload={"action": {"capability": "file.read", "resource": "/workspace/src/../../etc/passwd", "cost": 0.2}},
            budget=0.5,
        )
    )
    before_revoke = matrix.evaluate(
        WorkspaceCapMatrixRequest(
            subject_id="agent-demo",
            payload={"action": {"capability": "shell.exec", "resource": "python", "cost": 0.5}},
            budget=1.0,
        )
    )
    matrix.revoke("python-shell")
    after_revoke = matrix.evaluate(
        WorkspaceCapMatrixRequest(
            subject_id="agent-demo",
            payload={"action": {"capability": "shell.exec", "resource": "python", "cost": 0.5}},
            budget=1.0,
        )
    )

    output = {
        "allowed": allowed.as_dict(),
        "path_escape": escaped.as_dict(),
        "before_revoke": before_revoke.as_dict(),
        "after_revoke": after_revoke.as_dict(),
        "active_capabilities": matrix.capabilities("agent-demo"),
    }
    print(json.dumps(output, indent=2, sort_keys=True))

    if allowed.decision is not Decision.ALLOW:
        return 2
    if escaped.decision is not Decision.REFUSE:
        return 3
    if before_revoke.decision is not Decision.ALLOW:
        return 4
    if after_revoke.decision is not Decision.REFUSE:
        return 5
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
