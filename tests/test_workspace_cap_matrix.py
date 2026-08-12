from workspace_cap_matrix import (
    CapabilityGrant,
    Decision,
    WorkspaceCapMatrix,
    WorkspaceCapMatrixRequest,
)


def request(capability="file.read", resource="/workspace/src/app.py", cost=0.25, budget=1.0, grant_id=None):
    return WorkspaceCapMatrixRequest(
        subject_id="agent-1",
        payload={"action": {"capability": capability, "resource": resource, "cost": cost}},
        budget=budget,
        grant_id=grant_id,
    )


def grant(**overrides):
    values = {
        "grant_id": "g-file-read",
        "subject_id": "agent-1",
        "capability": "file.read",
        "scopes": ["/workspace/src"],
        "max_cost": 0.5,
        "expires_at": 2000,
    }
    values.update(overrides)
    return values


def test_scoped_file_read_is_authorized():
    matrix = WorkspaceCapMatrix([grant()], clock=lambda: 1000)
    receipt = matrix.evaluate(request())
    assert receipt.decision is Decision.ALLOW
    assert receipt.reasons == ("capability_authorized",)
    assert receipt.result["grant"]["grant_id"] == "g-file-read"
    assert receipt.result["action"]["resource"] == "/workspace/src/app.py"
    assert len(receipt.digest) == 64


def test_path_escape_is_out_of_scope_after_normalization():
    matrix = WorkspaceCapMatrix([grant()], clock=lambda: 1000)
    receipt = matrix.evaluate(request(resource="/workspace/src/../../etc/passwd"))
    assert receipt.decision is Decision.REFUSE
    assert "resource_out_of_scope" in receipt.reasons


def test_wrong_subject_is_refused():
    matrix = WorkspaceCapMatrix([grant(subject_id="agent-2")], clock=lambda: 1000)
    receipt = matrix.evaluate(request())
    assert receipt.decision is Decision.REFUSE
    assert "subject_not_granted" in receipt.reasons


def test_expired_grant_is_refused():
    matrix = WorkspaceCapMatrix([grant(expires_at=999)], clock=lambda: 1000)
    receipt = matrix.evaluate(request())
    assert receipt.decision is Decision.REFUSE
    assert "grant_expired" in receipt.reasons


def test_revocation_takes_effect_immediately():
    matrix = WorkspaceCapMatrix([grant()], clock=lambda: 1000)
    assert matrix.evaluate(request()).decision is Decision.ALLOW
    assert matrix.revoke("g-file-read") is True
    receipt = matrix.evaluate(request())
    assert receipt.decision is Decision.REFUSE
    assert "grant_revoked" in receipt.reasons
    assert matrix.capabilities("agent-1") == ()


def test_request_and_grant_budgets_are_both_enforced():
    matrix = WorkspaceCapMatrix([grant(max_cost=0.3)], clock=lambda: 1000)
    over_request = matrix.evaluate(request(cost=0.4, budget=0.2))
    assert over_request.decision is Decision.REFUSE
    assert "request_budget_exceeded" in over_request.reasons

    over_grant = matrix.evaluate(request(cost=0.4, budget=1.0))
    assert over_grant.decision is Decision.REFUSE
    assert "grant_cost_exceeded" in over_grant.reasons


def test_shell_execution_requires_exact_executable_scope():
    matrix = WorkspaceCapMatrix(
        [grant(grant_id="g-shell", capability="shell.exec", scopes=["python"], max_cost=1)],
        clock=lambda: 1000,
    )
    assert matrix.evaluate(request("shell.exec", "python")).decision is Decision.ALLOW
    denied = matrix.evaluate(request("shell.exec", "bash"))
    assert denied.decision is Decision.REFUSE
    assert "resource_out_of_scope" in denied.reasons


def test_network_wildcard_matches_subdomain_not_apex():
    matrix = WorkspaceCapMatrix(
        [grant(grant_id="g-net", capability="net.connect", scopes=["*.example.com"], max_cost=1)],
        clock=lambda: 1000,
    )
    assert matrix.evaluate(request("net.connect", "api.example.com:443")).decision is Decision.ALLOW
    denied = matrix.evaluate(request("net.connect", "example.com:443"))
    assert denied.decision is Decision.REFUSE


def test_selected_grant_is_deterministic_and_least_privileged_by_cost():
    matrix = WorkspaceCapMatrix(
        [
            CapabilityGrant("z-wide", "agent-1", "file.read", ("/workspace",), 1.0, 2000),
            CapabilityGrant("a-narrow", "agent-1", "file.read", ("/workspace/src",), 0.5, 2000),
        ],
        clock=lambda: 1000,
    )
    first = matrix.evaluate(request())
    second = matrix.evaluate(request())
    assert first == second
    assert first.result["grant"]["grant_id"] == "a-narrow"
    assert first.metrics["eligible_grants"] == 2


def test_unknown_action_fields_fail_closed():
    matrix = WorkspaceCapMatrix([grant()], clock=lambda: 1000)
    req = WorkspaceCapMatrixRequest(
        subject_id="agent-1",
        payload={"action": {"capability": "file.read", "resource": "/workspace/src/app.py", "cost": 0.1, "magic": True}},
    )
    receipt = matrix.evaluate(req)
    assert receipt.decision is Decision.REFUSE
    assert any(reason.startswith("action_keys_unknown:") for reason in receipt.reasons)
