# Workspace Cap Matrix

Independent GlacierEQ portfolio implementation aligned to **Replit** operating themes.

> **Not affiliated.** This repository is not affiliated with, endorsed by, employed by, or deployed at Replit. No proprietary access, production deployment, customer impact, or company partnership is claimed.

## Purpose

Give agentic coding workspaces explicit authority boundaries for shell, file, network, process, and secret operations instead of treating workspace access as one giant yes/no permission.

## Implemented mechanism

`WorkspaceCapMatrix` evaluates actions against revocable, expiring capability grants bound to:

- workspace and principal identity;
- exact capability class;
- glob-scoped resources;
- usage budget;
- grant epoch;
- expiry and revocation state.

Dispatch fails closed on scope mismatch, capability mismatch, stale epoch, revoked/expired grants, out-of-scope resources, and budget exhaustion. Revocation increments the grant epoch and emits a new deterministic matrix digest so stale callers cannot continue using the old authority view.

## Run

```bash
python -m pytest -q
python scripts/operate.py
```

Build/install:

```bash
python -m pip install build
python -m build
python -m pip install dist/*.whl
workspace-cap-matrix
```

## Proof surface

- `src/workspace_cap_matrix.py` — dispatch/revoke authority engine
- `src/workspace_cap_cli.py` — installable execution surface
- `tests/test_workspace_cap_matrix.py` — resource, budget, expiry, epoch, revocation and secret-scope behavior
- `.github/workflows/tests.yml` — tests + cold-start + wheel build/install + installed CLI
- `machine/` — existing Helix control-plane/promotion surfaces remain preserved

## Current boundary

This is a vendor-neutral capability engine over normalized workspace actions. It does not control Replit infrastructure. A further deployment step is an adapter that intercepts real tool calls and persists grant usage/epoch updates across a disposable workspace runtime.
