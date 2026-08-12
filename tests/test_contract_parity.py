import json

from workspace_cap_matrix import Decision, WorkspaceCapMatrix, WorkspaceCapMatrixRequest, cli


def _grant() -> dict:
    return {
        "grant_id": "g-read",
        "subject_id": "agent-1",
        "capability": "file.read",
        "scopes": ["/workspace/src"],
        "max_cost": 1.0,
    }


def _request() -> WorkspaceCapMatrixRequest:
    return WorkspaceCapMatrixRequest(
        subject_id="agent-1",
        payload={"action": {"capability": "file.read", "resource": "/workspace/src/app.py", "cost": 0.1}},
        budget=1.0,
    )


def test_initial_revoked_ids_are_normalized() -> None:
    matrix = WorkspaceCapMatrix([_grant()], revoked=["  g-read  "], clock=lambda: 1000)
    receipt = matrix.evaluate(_request())
    assert receipt.decision is Decision.REFUSE
    assert "grant_revoked" in receipt.reasons
    assert matrix.capabilities("agent-1") == ()


def test_cli_refuses_list_of_pairs_payload_instead_of_coercing_it(tmp_path, capsys) -> None:
    request_path = tmp_path / "request.json"
    request_path.write_text(
        json.dumps(
            {
                "grants": [_grant()],
                "request": {
                    "subject_id": "agent-1",
                    "budget": 1.0,
                    "payload": [["action", {"capability": "file.read", "resource": "/workspace/src/app.py", "cost": 0.1}]],
                },
            }
        ),
        encoding="utf-8",
    )
    code = cli(["--input", str(request_path)])
    output = json.loads(capsys.readouterr().out)
    assert code == 2
    assert output["decision"] == "REFUSE"
    assert "request payload must be an object" in output["reasons"][0]


def test_cli_requires_revoked_array_of_strings(tmp_path, capsys) -> None:
    request_path = tmp_path / "request.json"
    request_path.write_text(
        json.dumps(
            {
                "grants": [_grant()],
                "revoked": "g-read",
                "request": {
                    "subject_id": "agent-1",
                    "payload": {"action": {"capability": "file.read", "resource": "/workspace/src/app.py", "cost": 0.1}},
                },
            }
        ),
        encoding="utf-8",
    )
    code = cli(["--input", str(request_path)])
    output = json.loads(capsys.readouterr().out)
    assert code == 2
    assert "revoked must be an array of strings" in output["reasons"][0]
