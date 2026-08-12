# Workspace Cap Matrix

A vendor-neutral capability authority and state-transition engine for agentic coding workspaces.

> Independent GlacierEQ implementation. Not affiliated with, endorsed by, employed by, or deployed at Replit.

## Purpose

Workspace agents routinely cross high-impact boundaries: files, shell commands, processes, secrets, and network egress. Treating workspace access as one giant permission makes revocation, least privilege, usage budgets, and auditability mostly decorative.

Workspace Cap Matrix evaluates normalized actions against explicit grants and returns both an authorization receipt and the **updated grant matrix** that a caller can persist before executing the action.

## Capability model

Each grant is bound to:

- `grant_id`
- `workspace_id`
- `principal_id`
- one capability class: `shell`, `file.read`, `file.write`, `network.egress`, `process.spawn`, or `secret.read`
- capability-specific resource patterns
- maximum and already-used units
- integer grant epoch
- expiry
- revocation state

Each action declares matching workspace/principal/capability identity, one concrete resource, cost units, and the grant epoch it expects.

## Implemented behavior

### Dispatch

A dispatch fails closed on:

- workspace or principal mismatch
- capability mismatch
- stale epoch
- revoked or expired grant
- resource scope mismatch
- insufficient capability budget
- malformed or coerced identity fields
- request expiry
- request-level grant binding mismatch
- evaluation work-budget exhaustion

When a dispatch succeeds it returns:

- selected grant identity and epoch
- usage before/after
- remaining capability units
- `updated_grants` with consumed usage persisted into the returned state
- deterministic `matrix_digest`
- deterministic `authorization_digest`

Persist `updated_grants` before performing the real side effect if capability usage must survive process boundaries.

### Revoke

Revocation sets `revoked=true`, increments the grant epoch, and returns the full updated matrix plus a new matrix digest. A caller still holding the old epoch then fails both the stale-epoch and revoked-grant checks.

### Inspect

`mode="inspect"` returns only currently active grants for a workspace/principal, optionally filtered by capability. Expired, revoked, exhausted, or unrelated grants are excluded.

### Resource semantics

- file resources are relative POSIX workspace paths; absolute paths, traversal components, backslashes, control characters, and globs in concrete action resources are refused
- file grant patterns may contain explicit glob syntax after traversal validation
- network egress resources are concrete `host:port` targets
- network grant patterns may use an exact host/port, `*.example.com:443`, or `api.example.com:*`
- wildcard subdomains do not match the apex domain
- shell/process/secret resources use explicit declared patterns without crossing capability classes

## Library

```python
from workspace_cap_matrix import WorkspaceCapMatrix, WorkspaceCapMatrixRequest

receipt = WorkspaceCapMatrix().evaluate(
    WorkspaceCapMatrixRequest(
        subject_id="job-42",
        budget=10.0,
        payload={
            "mode": "dispatch",
            "now": 100.0,
            "grants": [...],
            "action": {...}
        },
    )
)
```

Batch evaluation is available through `WorkspaceCapMatrix.evaluate_batch()`.

## CLI

Build/install:

```bash
python -m pip install build
python -m build
python -m pip install dist/*.whl
```

Run the built-in demonstration:

```bash
workspace-cap-matrix
```

Evaluate a JSON payload:

```bash
workspace-cap-matrix --input request.json --subject job-42 --budget 10
```

Optional `--grant-id` binds the request to one grant and `--not-after` enforces request expiry against the payload's explicit `now`. CLI input is bounded before JSON parsing and non-object payloads fail closed.

## Verify the repository

```bash
python -m pytest -q
python scripts/operate.py
```

The runtime smoke exercises dispatch, persistence of consumed usage, active-capability inspection, revocation, and rejection of the pre-revocation epoch.

## Integration boundary

This repository authorizes and evolves grant state; it does **not** execute the requested file, shell, process, secret, or network operation. A real workspace adapter should persist the returned matrix state and receipt, then invoke its executor only after an `ALLOW`. That keeps provider credentials and side effects in the system that actually owns them instead of faking an integration here.
