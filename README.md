# Workspace Cap Matrix

A vendor-neutral authorization kernel for agentic coding workspaces.

> Independent GlacierEQ implementation. Not affiliated with, endorsed by, employed by, or deployed at Replit.

## Purpose

Workspace agents routinely cross high-impact boundaries: reading and writing files, starting processes, and opening network connections. Those actions should be authorized by explicit, inspectable capabilities rather than by ambient workspace access.

Workspace Cap Matrix turns grants into deterministic authorization receipts before an executor performs the action.

## Capabilities

- subject-bound capability grants
- scoped filesystem authorization with normalized absolute paths
- path traversal containment
- exact executable authorization for `shell.exec`
- exact host/port, wildcard subdomain, and host-any-port scopes for `net.connect`
- per-request and per-grant action-cost ceilings
- grant expiry
- immediate runtime revocation
- optional explicit grant selection
- deterministic least-privilege grant selection when multiple grants match
- active-capability inspection for a subject
- deterministic authorization receipts suitable for audit logs
- unknown request/action fields fail closed
- batch evaluation for callers planning multiple workspace actions

The library **authorizes declared actions but does not execute them**. Filesystem, shell, and network executors remain separate so authorization can sit directly in front of real runtime machinery without smuggling execution side effects into the policy kernel.

## Install

```bash
python -m pip install .
```

## CLI

Input JSON contains `grants`, optional `revoked`, and one `request`:

```json
{
  "grants": [
    {
      "grant_id": "source-read",
      "subject_id": "agent-1",
      "capability": "file.read",
      "scopes": ["/workspace/src"],
      "max_cost": 0.5
    }
  ],
  "request": {
    "subject_id": "agent-1",
    "budget": 0.5,
    "payload": {
      "action": {
        "capability": "file.read",
        "resource": "/workspace/src/app.py",
        "cost": 0.1
      }
    }
  }
}
```

Run it:

```bash
workspace-cap-matrix --input request.json
```

Exit code is zero only for an allowed action.

## Verify the repository

```bash
python -m pytest -q
python scripts/operate.py
```

The runtime smoke proves an allowed scoped read, refusal of a normalized path escape, an allowed shell capability, and refusal immediately after revocation.

## Integration boundary

A real workspace executor should call `WorkspaceCapMatrix.evaluate()` immediately before the corresponding file, process, or network operation and persist the returned receipt with the executor result. This repository owns authorization semantics, not pretend integrations or provider credentials.
