from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

from workspace_cap_matrix import Decision, WorkspaceCapMatrix, WorkspaceCapMatrixRequest

MAX_INPUT_CHARS = 2_000_000


def demo_payload() -> dict[str, Any]:
    return {
        "mode": "dispatch",
        "now": 100.0,
        "grants": [
            {
                "grant_id": "g1",
                "workspace_id": "ws1",
                "principal_id": "agent1",
                "capability": "file.write",
                "resource_patterns": ["src/**"],
                "max_units": 10.0,
                "used_units": 2.0,
                "epoch": 3,
                "expires_at": 200.0,
                "revoked": False,
            }
        ],
        "action": {
            "action_id": "a1",
            "workspace_id": "ws1",
            "principal_id": "agent1",
            "capability": "file.write",
            "resource": "src/main.py",
            "cost_units": 1.0,
            "required_epoch": 3,
        },
    }


def _read_input(path: Path | None) -> str:
    if path is None:
        raw = sys.stdin.read(MAX_INPUT_CHARS + 1)
    else:
        if path.stat().st_size > MAX_INPUT_CHARS * 4:
            raise ValueError("input_too_large")
        raw = path.read_text(encoding="utf-8")
    if len(raw) > MAX_INPUT_CHARS:
        raise ValueError("input_too_large")
    return raw


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Authorize, consume, inspect, or revoke a bounded workspace capability"
    )
    parser.add_argument("--input", type=Path, help="payload JSON; omit for built-in demo")
    parser.add_argument("--subject", default="workspace-demo")
    parser.add_argument("--budget", type=float, default=10.0)
    parser.add_argument("--grant-id")
    parser.add_argument("--not-after", type=float)
    args = parser.parse_args(argv)

    try:
        if args.input:
            decoded = json.loads(_read_input(args.input))
            if not isinstance(decoded, Mapping):
                raise ValueError("payload must be an object")
            payload = dict(decoded)
        else:
            payload = demo_payload()
        receipt = WorkspaceCapMatrix().evaluate(
            WorkspaceCapMatrixRequest(
                subject_id=args.subject,
                payload=payload,
                budget=args.budget,
                grant_id=args.grant_id,
                not_after=args.not_after,
            )
        )
    except Exception as exc:
        print(
            json.dumps(
                {
                    "decision": "REFUSE",
                    "reasons": [f"cli_input_error:{type(exc).__name__}:{exc}"],
                },
                sort_keys=True,
            )
        )
        return 2

    print(json.dumps(receipt.as_dict(), indent=2, sort_keys=True))
    return 0 if receipt.decision is Decision.ALLOW else 2


if __name__ == "__main__":
    raise SystemExit(main())
