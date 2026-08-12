"""Deterministic capability enforcement for agentic coding workspaces.

The matrix authorizes declared workspace actions. It does not execute shell,
network, or filesystem operations itself. That separation lets callers put this
kernel directly in front of their real executors and test the authorization
boundary independently.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import posixpath
import sys
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Sequence


def _digest(obj: object) -> str:
    payload = json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
        default=str,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class Decision(str, Enum):
    ALLOW = "ALLOW"
    REFUSE = "REFUSE"


@dataclass(frozen=True)
class CapabilityGrant:
    grant_id: str
    subject_id: str
    capability: str
    scopes: tuple[str, ...]
    max_cost: float = 1.0
    expires_at: float | None = None

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> "CapabilityGrant":
        grant_id = str(raw.get("grant_id", "")).strip()
        subject_id = str(raw.get("subject_id", "")).strip()
        capability = str(raw.get("capability", "")).strip().lower()
        scopes_raw = raw.get("scopes", ())
        if not grant_id:
            raise ValueError("grant_id_missing")
        if not subject_id:
            raise ValueError("grant_subject_missing")
        if not capability:
            raise ValueError("grant_capability_missing")
        if not isinstance(scopes_raw, Sequence) or isinstance(scopes_raw, (str, bytes, bytearray)):
            raise ValueError("grant_scopes_invalid")
        scopes = tuple(sorted({str(scope).strip() for scope in scopes_raw if str(scope).strip()}))
        if not scopes:
            raise ValueError("grant_scopes_empty")
        try:
            max_cost = float(raw.get("max_cost", 1.0))
            if not math.isfinite(max_cost) or max_cost <= 0:
                raise ValueError
        except (TypeError, ValueError):
            raise ValueError("grant_max_cost_invalid") from None
        expires_at = raw.get("expires_at")
        if expires_at is not None:
            try:
                expires_at = float(expires_at)
                if not math.isfinite(expires_at):
                    raise ValueError
            except (TypeError, ValueError):
                raise ValueError("grant_expiry_invalid") from None
        return cls(grant_id, subject_id, capability, scopes, max_cost, expires_at)

    def as_dict(self) -> dict[str, Any]:
        return {
            "grant_id": self.grant_id,
            "subject_id": self.subject_id,
            "capability": self.capability,
            "scopes": list(self.scopes),
            "max_cost": self.max_cost,
            "expires_at": self.expires_at,
        }


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
    result: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision.value,
            "reasons": list(self.reasons),
            "digest": self.digest,
            "metrics": self.metrics,
            "result": self.result,
        }


class WorkspaceCapMatrix:
    """Authorize workspace actions against scoped, expiring, revocable grants."""

    ACTION_KEYS = frozenset({"capability", "resource", "cost", "metadata"})

    def __init__(
        self,
        grants: Iterable[CapabilityGrant | Mapping[str, Any]] = (),
        *,
        revoked: Iterable[str] = (),
        clock: Callable[[], float] | None = None,
    ) -> None:
        parsed: list[CapabilityGrant] = []
        seen: set[str] = set()
        for raw in grants:
            grant = raw if isinstance(raw, CapabilityGrant) else CapabilityGrant.from_mapping(raw)
            if grant.grant_id in seen:
                raise ValueError(f"duplicate_grant_id:{grant.grant_id}")
            seen.add(grant.grant_id)
            parsed.append(grant)
        self._grants = tuple(sorted(parsed, key=lambda grant: grant.grant_id))
        if isinstance(revoked, (str, bytes, bytearray)):
            raise ValueError("revoked_ids_invalid")
        self._revoked = {
            normalized
            for grant_id in revoked
            if (normalized := str(grant_id).strip())
        }
        self._clock = clock or time.time

    def revoke(self, grant_id: str) -> bool:
        grant_id = str(grant_id).strip()
        if not grant_id:
            raise ValueError("grant_id_missing")
        existed = any(grant.grant_id == grant_id for grant in self._grants)
        self._revoked.add(grant_id)
        return existed

    def capabilities(self, subject_id: str) -> tuple[dict[str, Any], ...]:
        now = self._clock()
        active = []
        for grant in self._grants:
            if grant.subject_id != subject_id or grant.grant_id in self._revoked:
                continue
            if grant.expires_at is not None and now > grant.expires_at:
                continue
            active.append(grant.as_dict())
        return tuple(active)

    @staticmethod
    def _normalize_file_path(value: str) -> str:
        if not value.startswith("/") or "\x00" in value:
            raise ValueError("file_resource_must_be_absolute")
        normalized = posixpath.normpath(value)
        if not normalized.startswith("/"):
            raise ValueError("file_resource_invalid")
        return normalized

    @classmethod
    def _scope_matches(cls, capability: str, resource: str, scope: str) -> bool:
        if capability.startswith("file."):
            try:
                resource_path = cls._normalize_file_path(resource)
                scope_path = cls._normalize_file_path(scope)
            except ValueError:
                return False
            return resource_path == scope_path or resource_path.startswith(scope_path.rstrip("/") + "/")

        if capability == "net.connect":
            target = resource.lower()
            pattern = scope.lower()
            if pattern == target:
                return True
            if pattern.startswith("*."):
                domain = pattern[2:]
                host = target.rsplit(":", 1)[0]
                return host.endswith("." + domain) and host != domain
            if pattern.endswith(":*"):
                return target.rsplit(":", 1)[0] == pattern[:-2]
            return False

        return resource == scope

    @staticmethod
    def _parse_action(payload: Mapping[str, Any]) -> tuple[dict[str, Any] | None, list[str]]:
        raw = payload.get("action")
        if not isinstance(raw, Mapping):
            return None, ["action_missing"]
        unknown = set(raw) - WorkspaceCapMatrix.ACTION_KEYS
        errors: list[str] = []
        if unknown:
            errors.append("action_keys_unknown:" + ",".join(sorted(unknown)))
        capability = str(raw.get("capability", "")).strip().lower()
        resource = str(raw.get("resource", "")).strip()
        if not capability:
            errors.append("action_capability_missing")
        if not resource:
            errors.append("action_resource_missing")
        try:
            cost = float(raw.get("cost", 1.0))
            if not math.isfinite(cost) or cost <= 0:
                raise ValueError
        except (TypeError, ValueError):
            cost = 0.0
            errors.append("action_cost_invalid")
        metadata = raw.get("metadata", {})
        if not isinstance(metadata, Mapping):
            errors.append("action_metadata_invalid")
            metadata = {}
        if errors:
            return None, errors
        if capability.startswith("file."):
            try:
                resource = WorkspaceCapMatrix._normalize_file_path(resource)
            except ValueError as exc:
                return None, [str(exc)]
        return {
            "capability": capability,
            "resource": resource,
            "cost": cost,
            "metadata": dict(sorted(metadata.items())),
        }, []

    def _receipt(
        self,
        req: WorkspaceCapMatrixRequest,
        decision: Decision,
        reasons: Sequence[str],
        *,
        action: Mapping[str, Any] | None = None,
        selected: CapabilityGrant | None = None,
        eligible_count: int = 0,
    ) -> WorkspaceCapMatrixReceipt:
        unique = tuple(dict.fromkeys(reasons))
        result: dict[str, Any] = {}
        if action is not None:
            result["action"] = dict(action)
        if selected is not None:
            result["grant"] = selected.as_dict()
        metrics = {
            "configured_grants": len(self._grants),
            "revoked_grants": len(self._revoked),
            "eligible_grants": eligible_count,
            "request_budget": req.budget,
        }
        body = {
            "subject_id": req.subject_id,
            "grant_id": req.grant_id,
            "not_after": req.not_after,
            "decision": decision.value,
            "reasons": list(unique),
            "result": result,
            "metrics": metrics,
        }
        return WorkspaceCapMatrixReceipt(decision, unique, _digest(body), metrics, result)

    def evaluate(self, req: WorkspaceCapMatrixRequest) -> WorkspaceCapMatrixReceipt:
        if not isinstance(req, WorkspaceCapMatrixRequest):
            raise TypeError("req must be WorkspaceCapMatrixRequest")

        reasons: list[str] = []
        subject_id = str(req.subject_id or "").strip()
        if not subject_id:
            reasons.append("subject_id_missing")
        try:
            budget = float(req.budget)
            if not math.isfinite(budget) or budget <= 0:
                raise ValueError
        except (TypeError, ValueError):
            budget = 0.0
            reasons.append("budget_non_positive")

        now = self._clock()
        if req.not_after is not None:
            try:
                not_after = float(req.not_after)
                if not math.isfinite(not_after):
                    raise ValueError
                if now > not_after:
                    reasons.append("request_expired")
            except (TypeError, ValueError):
                reasons.append("request_expiry_invalid")

        if not isinstance(req.payload, Mapping):
            return self._receipt(req, Decision.REFUSE, reasons + ["payload_invalid"])
        unknown_payload = set(req.payload) - {"action"}
        if unknown_payload:
            reasons.append("payload_keys_unknown:" + ",".join(sorted(unknown_payload)))

        action, action_errors = self._parse_action(req.payload)
        reasons.extend(action_errors)
        if reasons or action is None:
            return self._receipt(req, Decision.REFUSE, reasons, action=action)

        if action["cost"] > budget:
            return self._receipt(req, Decision.REFUSE, ["request_budget_exceeded"], action=action)

        candidates: list[CapabilityGrant] = []
        rejection_signals: set[str] = set()
        for grant in self._grants:
            if req.grant_id is not None and grant.grant_id != req.grant_id:
                continue
            if grant.subject_id != subject_id:
                rejection_signals.add("subject_not_granted")
                continue
            if grant.capability != action["capability"]:
                rejection_signals.add("capability_not_granted")
                continue
            if grant.grant_id in self._revoked:
                rejection_signals.add("grant_revoked")
                continue
            if grant.expires_at is not None and now > grant.expires_at:
                rejection_signals.add("grant_expired")
                continue
            if action["cost"] > grant.max_cost:
                rejection_signals.add("grant_cost_exceeded")
                continue
            if not any(self._scope_matches(grant.capability, action["resource"], scope) for scope in grant.scopes):
                rejection_signals.add("resource_out_of_scope")
                continue
            candidates.append(grant)

        if not candidates:
            reasons = sorted(rejection_signals) or ["no_matching_grant"]
            return self._receipt(req, Decision.REFUSE, reasons, action=action)

        selected = min(candidates, key=lambda grant: (grant.max_cost, grant.grant_id))
        return self._receipt(
            req,
            Decision.ALLOW,
            ["capability_authorized"],
            action=action,
            selected=selected,
            eligible_count=len(candidates),
        )

    def evaluate_batch(
        self, requests: Iterable[WorkspaceCapMatrixRequest]
    ) -> tuple[WorkspaceCapMatrixReceipt, ...]:
        return tuple(self.evaluate(request) for request in requests)


Mechanism = WorkspaceCapMatrix


def cli(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Authorize a workspace action from JSON.")
    parser.add_argument("--input", "-i", help="JSON file; defaults to stdin")
    args = parser.parse_args(argv)
    try:
        raw = Path(args.input).read_text(encoding="utf-8") if args.input else sys.stdin.read()
        data = json.loads(raw)
        if not isinstance(data, Mapping):
            raise ValueError("input JSON must be an object")
        grants_raw = data.get("grants", [])
        revoked_raw = data.get("revoked", [])
        if not isinstance(grants_raw, list):
            raise ValueError("grants must be an array")
        if not isinstance(revoked_raw, list) or any(not isinstance(item, str) for item in revoked_raw):
            raise ValueError("revoked must be an array of strings")
        matrix = WorkspaceCapMatrix(grants=grants_raw, revoked=revoked_raw)
        request_raw = data.get("request") or {}
        if not isinstance(request_raw, Mapping):
            raise ValueError("request must be an object")
        payload_raw = request_raw.get("payload", {})
        if not isinstance(payload_raw, Mapping):
            raise ValueError("request payload must be an object")
        request = WorkspaceCapMatrixRequest(
            subject_id=str(request_raw.get("subject_id", "")),
            payload=dict(payload_raw),
            budget=request_raw.get("budget", 1.0),
            grant_id=request_raw.get("grant_id"),
            not_after=request_raw.get("not_after"),
        )
        receipt = matrix.evaluate(request)
    except Exception as exc:
        print(json.dumps({"decision": "REFUSE", "reasons": [f"cli_input_error:{type(exc).__name__}:{exc}"]}, sort_keys=True))
        return 2
    print(json.dumps(receipt.as_dict(), indent=2, sort_keys=True))
    return 0 if receipt.decision is Decision.ALLOW else 2
