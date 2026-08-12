"""Workspace Capability Matrix.

Authorizes agent workspace actions only through explicit, expiring, revocable
capability grants with resource patterns and usage budgets. A stale grant epoch,
revoked grant, scope mismatch, or exhausted budget fails closed.
"""
from __future__ import annotations

import fnmatch
import hashlib
import json
import math
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


def _digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


class Decision(str, Enum):
    ALLOW = "ALLOW"
    REFUSE = "REFUSE"


@dataclass(frozen=True)
class WorkspaceCapMatrixRequest:
    subject_id: str
    payload: dict[str, Any] = field(default_factory=dict)
    budget: float = 1.0
    grant_id: str | None = None
    not_after: float | None = None


@dataclass(frozen=True)
class WorkspaceCapMatrixReceipt:
    decision: Decision
    reasons: tuple[str, ...]
    digest: str
    metrics: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {"decision": self.decision.value, "reasons": list(self.reasons), "digest": self.digest, "metrics": self.metrics}


class CapabilityError(ValueError):
    pass


class WorkspaceCapMatrix:
    MIN_BUDGET = 0.0
    CAPABILITIES = frozenset({"shell", "file.read", "file.write", "network.egress", "process.spawn", "secret.read"})

    @staticmethod
    def _num(value: Any, label: str, *, minimum: float | None = None) -> float:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise CapabilityError(f"{label}_invalid")
        value = float(value)
        if not math.isfinite(value):
            raise CapabilityError(f"{label}_not_finite")
        if minimum is not None and value < minimum:
            raise CapabilityError(f"{label}_below_minimum")
        return value

    @staticmethod
    def _id(value: Any, label: str) -> str:
        value = str(value or "").strip()
        if not value:
            raise CapabilityError(f"{label}_missing")
        return value

    @classmethod
    def _grant(cls, raw: Any, index: int) -> dict[str, Any]:
        if not isinstance(raw, dict):
            raise CapabilityError(f"grant_{index}_not_object")
        capability = cls._id(raw.get("capability"), f"grant_{index}_capability")
        if capability not in cls.CAPABILITIES:
            raise CapabilityError(f"grant_{index}_capability_unknown:{capability}")
        patterns = raw.get("resource_patterns")
        if not isinstance(patterns, list) or not patterns or any(not str(v).strip() for v in patterns):
            raise CapabilityError(f"grant_{index}_resource_patterns_invalid")
        return {
            "grant_id": cls._id(raw.get("grant_id"), f"grant_{index}_id"),
            "workspace_id": cls._id(raw.get("workspace_id"), f"grant_{index}_workspace_id"),
            "principal_id": cls._id(raw.get("principal_id"), f"grant_{index}_principal_id"),
            "capability": capability,
            "resource_patterns": sorted(set(str(v).strip() for v in patterns)),
            "max_units": cls._num(raw.get("max_units"), f"grant_{index}_max_units", minimum=0),
            "used_units": cls._num(raw.get("used_units", 0.0), f"grant_{index}_used_units", minimum=0),
            "epoch": int(cls._num(raw.get("epoch"), f"grant_{index}_epoch", minimum=1)),
            "expires_at": cls._num(raw.get("expires_at"), f"grant_{index}_expires_at", minimum=0),
            "revoked": bool(raw.get("revoked", False)),
        }

    @classmethod
    def _action(cls, raw: Any) -> dict[str, Any]:
        if not isinstance(raw, dict):
            raise CapabilityError("action_missing")
        capability = cls._id(raw.get("capability"), "action_capability")
        if capability not in cls.CAPABILITIES:
            raise CapabilityError(f"action_capability_unknown:{capability}")
        return {
            "action_id": cls._id(raw.get("action_id"), "action_id"),
            "workspace_id": cls._id(raw.get("workspace_id"), "action_workspace_id"),
            "principal_id": cls._id(raw.get("principal_id"), "action_principal_id"),
            "capability": capability,
            "resource": cls._id(raw.get("resource"), "action_resource"),
            "cost_units": cls._num(raw.get("cost_units", 1.0), "action_cost_units", minimum=0.001),
            "required_epoch": int(cls._num(raw.get("required_epoch"), "action_required_epoch", minimum=1)),
        }

    @staticmethod
    def _matches(resource: str, patterns: list[str]) -> bool:
        return any(fnmatch.fnmatchcase(resource, pattern) for pattern in patterns)

    @classmethod
    def _dispatch(cls, payload: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
        now = cls._num(payload.get("now"), "now", minimum=0)
        raw_grants = payload.get("grants")
        if not isinstance(raw_grants, list) or not raw_grants:
            raise CapabilityError("grants_missing")
        grants = [cls._grant(raw, i) for i, raw in enumerate(raw_grants)]
        if len({g["grant_id"] for g in grants}) != len(grants):
            raise CapabilityError("duplicate_grant_id")
        action = cls._action(payload.get("action"))
        eligible: list[dict[str, Any]] = []
        rejected: list[dict[str, Any]] = []
        for grant in grants:
            why: list[str] = []
            if grant["workspace_id"] != action["workspace_id"]:
                why.append("workspace_mismatch")
            if grant["principal_id"] != action["principal_id"]:
                why.append("principal_mismatch")
            if grant["capability"] != action["capability"]:
                why.append("capability_mismatch")
            if grant["epoch"] != action["required_epoch"]:
                why.append("grant_epoch_stale")
            if grant["revoked"]:
                why.append("grant_revoked")
            if now > grant["expires_at"]:
                why.append("grant_expired")
            if not cls._matches(action["resource"], grant["resource_patterns"]):
                why.append("resource_out_of_scope")
            if grant["used_units"] + action["cost_units"] > grant["max_units"]:
                why.append("capability_budget_exhausted")
            if why:
                rejected.append({"grant_id": grant["grant_id"], "reasons": why})
            else:
                eligible.append(grant)
        if not eligible:
            return {"authorized": False, "action": action, "rejected": rejected}, ["no_capability_grant_authorizes_action"]
        eligible.sort(key=lambda g: (g["expires_at"], g["max_units"] - g["used_units"], g["grant_id"]))
        selected = eligible[0]
        usage_after = selected["used_units"] + action["cost_units"]
        result = {
            "authorized": True,
            "action": action,
            "grant_id": selected["grant_id"],
            "grant_epoch": selected["epoch"],
            "usage_before": selected["used_units"],
            "usage_after": usage_after,
            "remaining_units": round(selected["max_units"] - usage_after, 12),
            "authorization_digest": _digest({"action": action, "grant_id": selected["grant_id"], "usage_after": usage_after}),
            "rejected": rejected,
        }
        return result, []

    @classmethod
    def _revoke(cls, payload: dict[str, Any]) -> dict[str, Any]:
        raw_grants = payload.get("grants")
        if not isinstance(raw_grants, list) or not raw_grants:
            raise CapabilityError("grants_missing")
        grants = [cls._grant(raw, i) for i, raw in enumerate(raw_grants)]
        target = cls._id(payload.get("grant_id"), "revoke_grant_id")
        found = False
        updated: list[dict[str, Any]] = []
        for grant in grants:
            row = dict(grant)
            if grant["grant_id"] == target:
                found = True
                row["revoked"] = True
                row["epoch"] += 1
            updated.append(row)
        if not found:
            raise CapabilityError("revoke_grant_not_found")
        updated.sort(key=lambda g: g["grant_id"])
        return {"grant_id": target, "grants": updated, "matrix_digest": _digest(updated)}

    def evaluate(self, req: WorkspaceCapMatrixRequest) -> WorkspaceCapMatrixReceipt:
        reasons: list[str] = []
        if not str(req.subject_id or "").strip():
            reasons.append("subject_id_missing")
        if isinstance(req.budget, bool) or not isinstance(req.budget, (int, float)) or not math.isfinite(float(req.budget)) or float(req.budget) <= self.MIN_BUDGET:
            reasons.append("budget_non_positive_or_invalid")
        payload = req.payload if isinstance(req.payload, dict) else {}
        if not isinstance(req.payload, dict):
            reasons.append("payload_not_object")
        result: dict[str, Any] | None = None
        try:
            mode = str(payload.get("mode", "dispatch")).lower()
            if mode == "dispatch":
                result, mode_reasons = self._dispatch(payload)
                reasons.extend(mode_reasons)
            elif mode == "revoke":
                result = self._revoke(payload)
            else:
                raise CapabilityError("mode_invalid")
        except CapabilityError as exc:
            reasons.append(str(exc))
        decision = Decision.REFUSE if reasons else Decision.ALLOW
        metrics = {"result": result}
        body = {"subject_id": req.subject_id, "decision": decision.value, "reasons": reasons, "metrics": metrics}
        return WorkspaceCapMatrixReceipt(decision, tuple(reasons or ["workspace_capability_transition_verified"]), _digest(body), metrics)


Mechanism = WorkspaceCapMatrix
