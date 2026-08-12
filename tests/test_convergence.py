from __future__ import annotations

import json

from workspace_cap_cli import main as cli_main
from workspace_cap_matrix import Decision, WorkspaceCapMatrix, WorkspaceCapMatrixRequest


def grant(**overrides):
    value = {
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
    value.update(overrides)
    return value


def action(**overrides):
    value = {
        "action_id": "a1",
        "workspace_id": "ws1",
        "principal_id": "agent1",
        "capability": "file.write",
        "resource": "src/main.py",
        "cost_units": 2.0,
        "required_epoch": 3,
    }
    value.update(overrides)
    return value


def evaluate(payload: dict, *, budget: float = 10.0, grant_id=None, not_after=None):
    return WorkspaceCapMatrix().evaluate(
        WorkspaceCapMatrixRequest(
            "workspace-a",
            payload,
            budget=budget,
            grant_id=grant_id,
            not_after=not_after,
        )
    )


def test_dispatch_returns_persistable_usage_transition():
    receipt = evaluate({"mode": "dispatch", "now": 100.0, "grants": [grant()], "action": action()})
    assert receipt.decision is Decision.ALLOW
    result = receipt.metrics["result"]
    assert result["usage_before"] == 2.0
    assert result["usage_after"] == 4.0
    assert result["updated_grants"][0]["used_units"] == 4.0
    assert len(result["matrix_digest"]) == 64
    assert len(result["authorization_digest"]) == 64


def test_persisted_usage_transition_exhausts_budget_on_later_dispatch():
    first = evaluate({"mode": "dispatch", "now": 100.0, "grants": [grant(max_units=5.0)], "action": action(cost_units=2.0)})
    assert first.decision is Decision.ALLOW
    persisted = first.metrics["result"]["updated_grants"]
    second = evaluate({"mode": "dispatch", "now": 101.0, "grants": persisted, "action": action(cost_units=2.0)})
    assert second.decision is Decision.REFUSE
    assert "capability_budget_exhausted" in second.metrics["result"]["rejected"][0]["reasons"]


def test_file_scope_rejects_traversal_and_windows_separator():
    traversal = evaluate({"mode": "dispatch", "now": 100.0, "grants": [grant()], "action": action(resource="src/../secrets.txt")})
    assert traversal.decision is Decision.REFUSE
    assert "action_resource_invalid" in traversal.reasons

    windows = evaluate({"mode": "dispatch", "now": 100.0, "grants": [grant()], "action": action(resource=r"src\main.py")})
    assert windows.decision is Decision.REFUSE
    assert "action_resource_invalid" in windows.reasons


def test_network_scope_supports_subdomain_and_port_bounds():
    network_grant = grant(
        capability="network.egress",
        resource_patterns=["*.example.com:443", "api.internal:*"]
    )
    allowed = evaluate(
        {
            "mode": "dispatch",
            "now": 100.0,
            "grants": [network_grant],
            "action": action(
                capability="network.egress",
                resource="api.example.com:443",
            ),
        }
    )
    assert allowed.decision is Decision.ALLOW

    apex = evaluate(
        {
            "mode": "dispatch",
            "now": 100.0,
            "grants": [network_grant],
            "action": action(
                capability="network.egress",
                resource="example.com:443",
            ),
        }
    )
    assert apex.decision is Decision.REFUSE
    assert "resource_out_of_scope" in apex.metrics["result"]["rejected"][0]["reasons"]

    any_port = evaluate(
        {
            "mode": "dispatch",
            "now": 100.0,
            "grants": [network_grant],
            "action": action(
                capability="network.egress",
                resource="api.internal:8443",
            ),
        }
    )
    assert any_port.decision is Decision.ALLOW


def test_request_grant_binding_selects_only_named_grant():
    grants = [grant(grant_id="g1"), grant(grant_id="g2", max_units=20.0)]
    receipt = evaluate(
        {"mode": "dispatch", "now": 100.0, "grants": grants, "action": action()},
        grant_id="g2",
    )
    assert receipt.decision is Decision.ALLOW
    assert receipt.metrics["result"]["grant_id"] == "g2"


def test_request_expiry_refuses_before_authority_use():
    receipt = evaluate(
        {"mode": "dispatch", "now": 100.0, "grants": [grant()], "action": action()},
        not_after=99.0,
    )
    assert receipt.decision is Decision.REFUSE
    assert "request_expired" in receipt.reasons


def test_inspect_returns_only_active_subject_grants():
    grants = [
        grant(grant_id="active"),
        grant(grant_id="revoked", revoked=True),
        grant(grant_id="expired", expires_at=50.0),
        grant(grant_id="other", principal_id="agent2"),
    ]
    receipt = evaluate(
        {
            "mode": "inspect",
            "now": 100.0,
            "grants": grants,
            "workspace_id": "ws1",
            "principal_id": "agent1",
        }
    )
    assert receipt.decision is Decision.ALLOW
    result = receipt.metrics["result"]
    assert result["active_count"] == 1
    assert result["active_grants"][0]["grant_id"] == "active"


def test_batch_evaluation_preserves_deterministic_receipts():
    request = WorkspaceCapMatrixRequest(
        "workspace-a",
        {"mode": "dispatch", "now": 100.0, "grants": [grant()], "action": action()},
        budget=10.0,
    )
    engine = WorkspaceCapMatrix()
    receipts = engine.evaluate_batch([request, request])
    assert len(receipts) == 2
    assert receipts[0] == receipts[1]


def test_evaluation_budget_bounds_grant_scan():
    grants = [grant(grant_id=f"g{i}") for i in range(20)]
    receipt = evaluate(
        {"mode": "dispatch", "now": 100.0, "grants": grants, "action": action()},
        budget=0.3,
    )
    assert receipt.decision is Decision.REFUSE
    assert "evaluation_budget_exceeded" in receipt.reasons


def test_identity_fields_are_strict_not_string_coerced():
    bad = grant(principal_id=123)
    receipt = evaluate({"mode": "dispatch", "now": 100.0, "grants": [bad], "action": action()})
    assert receipt.decision is Decision.REFUSE
    assert "grant_0_principal_id_type_invalid" in receipt.reasons


def test_epoch_must_be_integer_not_truncated_float():
    bad = grant(epoch=3.5)
    receipt = evaluate({"mode": "dispatch", "now": 100.0, "grants": [bad], "action": action()})
    assert receipt.decision is Decision.REFUSE
    assert "grant_0_epoch_invalid" in receipt.reasons


def test_cli_refuses_non_object_payload(tmp_path, capsys):
    path = tmp_path / "request.json"
    path.write_text(json.dumps([["mode", "dispatch"]]), encoding="utf-8")
    code = cli_main(["--input", str(path)])
    output = json.loads(capsys.readouterr().out)
    assert code == 2
    assert output["decision"] == "REFUSE"
    assert "payload must be an object" in output["reasons"][0]
