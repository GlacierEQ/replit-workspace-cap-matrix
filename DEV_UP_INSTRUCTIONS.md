# DEV_UP_INSTRUCTIONS — implementation record

**Repository:** `GlacierEQ/replit-workspace-cap-matrix`  
**Independent company lens:** Replit  
**Innovation:** Workspace Cap Matrix

## Implemented

The scaffold has been replaced by a revocable capability-budget engine. Grants bind workspace, principal, capability, resource patterns, budget, epoch, expiry and revocation state. Dispatch refuses stale epochs, expired/revoked grants, out-of-scope resources, capability mismatch and exhausted budgets. Revocation increments epoch and emits a deterministic matrix digest.

`src/workspace_cap_cli.py` and `scripts/operate.py` execute the mechanism directly. The project is packaged with `workspace-cap-matrix`.

## Verification contract

Behavioral tests cover valid scoped dispatch, resource escape, budget exhaustion, stale epoch, revoked/expired grants, revoke mutation, and distinct secret authority. Existing adversarial coverage remains active.

CI must pass tests, cold-start, wheel build/install and installed CLI execution before Helix promotion evidence is minted.

## Truth boundary

No Replit affiliation, proprietary access, production deployment, customer impact, or company partnership is claimed. A persistent real tool-interception adapter remains a further deployment step.
