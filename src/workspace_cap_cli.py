from __future__ import annotations

import argparse
import json
from pathlib import Path

from workspace_cap_matrix import Decision, WorkspaceCapMatrix, WorkspaceCapMatrixRequest


def demo_payload() -> dict:
    return {"mode":"dispatch","now":100.0,"grants":[{"grant_id":"g1","workspace_id":"ws1","principal_id":"agent1","capability":"file.write","resource_patterns":["src/**"],"max_units":10.0,"used_units":2.0,"epoch":3,"expires_at":200.0,"revoked":False}],"action":{"action_id":"a1","workspace_id":"ws1","principal_id":"agent1","capability":"file.write","resource":"src/main.py","cost_units":1.0,"required_epoch":3}}


def main() -> int:
    p=argparse.ArgumentParser(description="Authorize or revoke a bounded workspace capability")
    p.add_argument("--input",type=Path)
    p.add_argument("--subject",default="workspace-demo")
    args=p.parse_args()
    payload=json.loads(args.input.read_text()) if args.input else demo_payload()
    receipt=WorkspaceCapMatrix().evaluate(WorkspaceCapMatrixRequest(args.subject,payload,1.0))
    print(json.dumps(receipt.as_dict(),indent=2,sort_keys=True))
    return 0 if receipt.decision is Decision.ALLOW else 2

if __name__=="__main__":
    raise SystemExit(main())
