from __future__ import annotations

from workspace_cap_matrix import Decision, WorkspaceCapMatrix, WorkspaceCapMatrixRequest


def grant(**overrides):
    base = {"grant_id": "g1", "workspace_id": "ws1", "principal_id": "agent1", "capability": "file.write", "resource_patterns": ["src/**"], "max_units": 10.0, "used_units": 2.0, "epoch": 3, "expires_at": 200.0, "revoked": False}
    base.update(overrides)
    return base


def action(**overrides):
    base = {"action_id": "a1", "workspace_id": "ws1", "principal_id": "agent1", "capability": "file.write", "resource": "src/main.py", "cost_units": 2.0, "required_epoch": 3}
    base.update(overrides)
    return base


def dispatch(grants, act=None, now=100.0):
    return WorkspaceCapMatrix().evaluate(WorkspaceCapMatrixRequest("workspace-a", {"mode": "dispatch", "grants": grants, "action": act or action(), "now": now}, 1.0))


def test_dispatch_authorizes_exact_capability_scope_and_budget() -> None:
    receipt = dispatch([grant()])
    assert receipt.decision is Decision.ALLOW
    result = receipt.metrics["result"]
    assert result["authorized"] is True
    assert result["grant_id"] == "g1"
    assert result["usage_after"] == 4.0
    assert result["remaining_units"] == 6.0


def test_file_write_cannot_escape_resource_pattern() -> None:
    receipt = dispatch([grant()], action(resource=".github/workflows/deploy.yml"))
    assert receipt.decision is Decision.REFUSE
    assert "no_capability_grant_authorizes_action" in receipt.reasons
    assert "resource_out_of_scope" in receipt.metrics["result"]["rejected"][0]["reasons"]


def test_capability_budget_is_hard_limit() -> None:
    receipt = dispatch([grant(used_units=9.0)], action(cost_units=2.0))
    assert receipt.decision is Decision.REFUSE
    assert "capability_budget_exhausted" in receipt.metrics["result"]["rejected"][0]["reasons"]


def test_stale_epoch_after_revoke_cannot_dispatch() -> None:
    receipt = dispatch([grant(epoch=4)], action(required_epoch=3))
    assert receipt.decision is Decision.REFUSE
    assert "grant_epoch_stale" in receipt.metrics["result"]["rejected"][0]["reasons"]


def test_revoked_grant_cannot_dispatch() -> None:
    receipt = dispatch([grant(revoked=True)])
    assert receipt.decision is Decision.REFUSE
    assert "grant_revoked" in receipt.metrics["result"]["rejected"][0]["reasons"]


def test_expired_grant_cannot_dispatch() -> None:
    receipt = dispatch([grant(expires_at=50.0)], now=100.0)
    assert receipt.decision is Decision.REFUSE
    assert "grant_expired" in receipt.metrics["result"]["rejected"][0]["reasons"]


def test_revoke_increments_epoch_and_sets_revoked() -> None:
    receipt = WorkspaceCapMatrix().evaluate(WorkspaceCapMatrixRequest("workspace-a", {"mode": "revoke", "grants": [grant()], "grant_id": "g1"}, 1.0))
    assert receipt.decision is Decision.ALLOW
    updated = receipt.metrics["result"]["grants"][0]
    assert updated["revoked"] is True
    assert updated["epoch"] == 4
    assert len(receipt.metrics["result"]["matrix_digest"]) == 64


def test_secret_read_requires_separate_capability_grant() -> None:
    receipt = dispatch([grant(capability="file.read", resource_patterns=["**"])], action(capability="secret.read", resource="env/OPENAI_API_KEY"))
    assert receipt.decision is Decision.REFUSE
    assert "capability_mismatch" in receipt.metrics["result"]["rejected"][0]["reasons"]
