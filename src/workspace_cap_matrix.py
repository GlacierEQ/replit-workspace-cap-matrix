"""Revocable capability authority for agentic coding workspaces.

The matrix is a deterministic authorization/state-transition kernel. It does
not execute filesystem, shell, process, secret, or network operations itself.
Callers persist the returned updated grant matrix and invoke a real executor
only after an ALLOW receipt.
"""
from __future__ import annotations

import fnmatch
import hashlib
import json
import math
import posixpath
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable, Mapping, Sequence


def _digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
            ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest()


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
        return {
            "decision": self.decision.value,
            "reasons": list(self.reasons),
            "digest": self.digest,
            "metrics": self.metrics,
        }


class CapabilityError(ValueError):
    pass


class WorkspaceCapMatrix:
    """Authorize, consume, revoke, and inspect bounded capability grants."""

    CAPABILITIES = frozenset(
        {"shell", "file.read", "file.write", "network.egress", "process.spawn", "secret.read"}
    )
    MODES = frozenset({"dispatch", "revoke", "inspect"})
    MAX_GRANTS = 256
    MAX_PATTERNS_PER_GRANT = 64
    MAX_TEXT = 4096
    BASE_WORK_UNITS = 0.25
    GRANT_WORK_UNITS = 0.02

    @staticmethod
    def _num(value: Any, label: str, *, minimum: float | None = None) -> float:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise CapabilityError(f"{label}_invalid")
        number = float(value)
        if not math.isfinite(number):
            raise CapabilityError(f"{label}_not_finite")
        if minimum is not None and number < minimum:
            raise CapabilityError(f"{label}_below_minimum")
        return number

    @classmethod
    def _integer(cls, value: Any, label: str, *, minimum: int = 0) -> int:
        if isinstance(value, bool) or not isinstance(value, int):
            raise CapabilityError(f"{label}_invalid")
        if value < minimum:
            raise CapabilityError(f"{label}_below_minimum")
        return value

    @classmethod
    def _text(cls, value: Any, label: str, *, lower: bool = False) -> str:
        if not isinstance(value, str):
            raise CapabilityError(f"{label}_type_invalid")
        text = value.strip()
        if not text:
            raise CapabilityError(f"{label}_missing")
        if len(text) > cls.MAX_TEXT:
            raise CapabilityError(f"{label}_too_long")
        if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in text):
            raise CapabilityError(f"{label}_control_character")
        return text.lower() if lower else text

    @staticmethod
    def _bool(value: Any, label: str) -> bool:
        if not isinstance(value, bool):
            raise CapabilityError(f"{label}_invalid")
        return value

    @classmethod
    def _workspace_path(cls, value: Any, label: str, *, allow_glob: bool = False) -> str:
        path = cls._text(value, label)
        if "\\" in path or path.startswith("/"):
            raise CapabilityError(f"{label}_invalid")
        # Normalize literal path components while retaining glob metacharacters.
        parts = path.split("/")
        if any(part in {"", ".", ".."} for part in parts):
            raise CapabilityError(f"{label}_invalid")
        if not allow_glob and any(char in path for char in "*?["):
            raise CapabilityError(f"{label}_glob_not_allowed")
        normalized = posixpath.normpath(path)
        if normalized in {".", ".."} or normalized.startswith("../"):
            raise CapabilityError(f"{label}_escape")
        return normalized

    @classmethod
    def _network_target(cls, value: Any, label: str, *, allow_glob: bool = False) -> str:
        target = cls._text(value, label, lower=True)
        if "/" in target or "\\" in target or " " in target:
            raise CapabilityError(f"{label}_invalid")
        if target.count(":") != 1:
            raise CapabilityError(f"{label}_host_port_required")
        host, port = target.rsplit(":", 1)
        if not host or not port:
            raise CapabilityError(f"{label}_host_port_required")
        if allow_glob:
            if host.startswith("*."):
                suffix = host[2:]
                if not suffix or "*" in suffix:
                    raise CapabilityError(f"{label}_invalid")
            elif "*" in host:
                raise CapabilityError(f"{label}_invalid")
            if port != "*" and (not port.isdigit() or not 1 <= int(port) <= 65535):
                raise CapabilityError(f"{label}_port_invalid")
        else:
            if "*" in host or "*" in port:
                raise CapabilityError(f"{label}_wildcard_not_allowed")
            if not port.isdigit() or not 1 <= int(port) <= 65535:
                raise CapabilityError(f"{label}_port_invalid")
        return f"{host}:{port}"

    @classmethod
    def _normalize_pattern(cls, capability: str, raw: Any, label: str) -> str:
        if capability.startswith("file."):
            return cls._workspace_path(raw, label, allow_glob=True)
        if capability == "network.egress":
            return cls._network_target(raw, label, allow_glob=True)
        return cls._text(raw, label)

    @classmethod
    def _normalize_resource(cls, capability: str, raw: Any, label: str) -> str:
        if capability.startswith("file."):
            return cls._workspace_path(raw, label, allow_glob=False)
        if capability == "network.egress":
            return cls._network_target(raw, label, allow_glob=False)
        return cls._text(raw, label)

    @classmethod
    def _grant(cls, raw: Any, index: int) -> dict[str, Any]:
        if not isinstance(raw, Mapping):
            raise CapabilityError(f"grant_{index}_not_object")
        capability = cls._text(raw.get("capability"), f"grant_{index}_capability", lower=True)
        if capability not in cls.CAPABILITIES:
            raise CapabilityError(f"grant_{index}_capability_unknown:{capability}")
        patterns_raw = raw.get("resource_patterns")
        if not isinstance(patterns_raw, list) or not patterns_raw:
            raise CapabilityError(f"grant_{index}_resource_patterns_invalid")
        if len(patterns_raw) > cls.MAX_PATTERNS_PER_GRANT:
            raise CapabilityError(f"grant_{index}_resource_patterns_over_limit")
        patterns = sorted(
            {
                cls._normalize_pattern(
                    capability,
                    pattern,
                    f"grant_{index}_resource_pattern_{pattern_index}",
                )
                for pattern_index, pattern in enumerate(patterns_raw)
            }
        )
        max_units = cls._num(raw.get("max_units"), f"grant_{index}_max_units", minimum=0.001)
        used_units = cls._num(raw.get("used_units", 0.0), f"grant_{index}_used_units", minimum=0.0)
        if used_units > max_units:
            raise CapabilityError(f"grant_{index}_used_units_exceed_max")
        return {
            "grant_id": cls._text(raw.get("grant_id"), f"grant_{index}_id"),
            "workspace_id": cls._text(raw.get("workspace_id"), f"grant_{index}_workspace_id"),
            "principal_id": cls._text(raw.get("principal_id"), f"grant_{index}_principal_id"),
            "capability": capability,
            "resource_patterns": patterns,
            "max_units": max_units,
            "used_units": used_units,
            "epoch": cls._integer(raw.get("epoch"), f"grant_{index}_epoch", minimum=1),
            "expires_at": cls._num(raw.get("expires_at"), f"grant_{index}_expires_at", minimum=0.0),
            "revoked": cls._bool(raw.get("revoked", False), f"grant_{index}_revoked"),
        }

    @classmethod
    def _action(cls, raw: Any) -> dict[str, Any]:
        if not isinstance(raw, Mapping):
            raise CapabilityError("action_missing")
        capability = cls._text(raw.get("capability"), "action_capability", lower=True)
        if capability not in cls.CAPABILITIES:
            raise CapabilityError(f"action_capability_unknown:{capability}")
        return {
            "action_id": cls._text(raw.get("action_id"), "action_id"),
            "workspace_id": cls._text(raw.get("workspace_id"), "action_workspace_id"),
            "principal_id": cls._text(raw.get("principal_id"), "action_principal_id"),
            "capability": capability,
            "resource": cls._normalize_resource(capability, raw.get("resource"), "action_resource"),
            "cost_units": cls._num(raw.get("cost_units", 1.0), "action_cost_units", minimum=0.001),
            "required_epoch": cls._integer(raw.get("required_epoch"), "action_required_epoch", minimum=1),
        }

    @classmethod
    def _matches(cls, capability: str, resource: str, pattern: str) -> bool:
        if capability.startswith("file."):
            # Both values have already passed traversal/backslash/absolute checks.
            return fnmatch.fnmatchcase(resource, pattern)
        if capability == "network.egress":
            host, port = resource.rsplit(":", 1)
            pattern_host, pattern_port = pattern.rsplit(":", 1)
            if pattern_host.startswith("*."):
                suffix = pattern_host[2:]
                host_match = host.endswith("." + suffix) and host != suffix
            else:
                host_match = host == pattern_host
            port_match = pattern_port == "*" or port == pattern_port
            return host_match and port_match
        return fnmatch.fnmatchcase(resource, pattern)

    @classmethod
    def _parse_grants(cls, payload: Mapping[str, Any]) -> list[dict[str, Any]]:
        raw_grants = payload.get("grants")
        if not isinstance(raw_grants, list) or not raw_grants:
            raise CapabilityError("grants_missing")
        if len(raw_grants) > cls.MAX_GRANTS:
            raise CapabilityError("grants_over_limit")
        grants = [cls._grant(raw, i) for i, raw in enumerate(raw_grants)]
        if len({grant["grant_id"] for grant in grants}) != len(grants):
            raise CapabilityError("duplicate_grant_id")
        return grants

    @classmethod
    def _work_units(cls, grant_count: int) -> float:
        return cls.BASE_WORK_UNITS + grant_count * cls.GRANT_WORK_UNITS

    @classmethod
    def _dispatch(
        cls,
        payload: Mapping[str, Any],
        *,
        bound_grant_id: str | None = None,
    ) -> tuple[dict[str, Any], list[str], float]:
        now = cls._num(payload.get("now"), "now", minimum=0.0)
        grants = cls._parse_grants(payload)
        action = cls._action(payload.get("action"))
        eligible: list[dict[str, Any]] = []
        rejected: list[dict[str, Any]] = []
        for grant in grants:
            why: list[str] = []
            if bound_grant_id is not None and grant["grant_id"] != bound_grant_id:
                why.append("grant_id_not_bound")
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
            if not any(
                cls._matches(action["capability"], action["resource"], pattern)
                for pattern in grant["resource_patterns"]
            ):
                why.append("resource_out_of_scope")
            if grant["used_units"] + action["cost_units"] > grant["max_units"]:
                why.append("capability_budget_exhausted")
            if why:
                rejected.append({"grant_id": grant["grant_id"], "reasons": why})
            else:
                eligible.append(grant)
        work_units = cls._work_units(len(grants))
        if not eligible:
            return (
                {"authorized": False, "action": action, "grants": grants, "rejected": rejected},
                ["no_capability_grant_authorizes_action"],
                work_units,
            )
        eligible.sort(
            key=lambda grant: (
                grant["expires_at"],
                grant["max_units"] - grant["used_units"],
                grant["grant_id"],
            )
        )
        selected = eligible[0]
        usage_after = selected["used_units"] + action["cost_units"]
        updated_grants: list[dict[str, Any]] = []
        for grant in grants:
            row = dict(grant)
            if row["grant_id"] == selected["grant_id"]:
                row["used_units"] = usage_after
            updated_grants.append(row)
        updated_grants.sort(key=lambda grant: grant["grant_id"])
        matrix_digest = _digest(updated_grants)
        result = {
            "authorized": True,
            "action": action,
            "grant_id": selected["grant_id"],
            "grant_epoch": selected["epoch"],
            "usage_before": selected["used_units"],
            "usage_after": usage_after,
            "remaining_units": round(selected["max_units"] - usage_after, 12),
            "updated_grants": updated_grants,
            "matrix_digest": matrix_digest,
            "authorization_digest": _digest(
                {
                    "action": action,
                    "grant_id": selected["grant_id"],
                    "grant_epoch": selected["epoch"],
                    "usage_after": usage_after,
                    "matrix_digest": matrix_digest,
                }
            ),
            "rejected": rejected,
        }
        return result, [], work_units

    @classmethod
    def _revoke(
        cls,
        payload: Mapping[str, Any],
        *,
        bound_grant_id: str | None = None,
    ) -> tuple[dict[str, Any], float]:
        grants = cls._parse_grants(payload)
        target = cls._text(payload.get("grant_id"), "revoke_grant_id")
        if bound_grant_id is not None and target != bound_grant_id:
            raise CapabilityError("grant_id_binding_mismatch")
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
        updated.sort(key=lambda grant: grant["grant_id"])
        return (
            {
                "grant_id": target,
                "grants": updated,
                "matrix_digest": _digest(updated),
            },
            cls._work_units(len(grants)),
        )

    @classmethod
    def _inspect(cls, payload: Mapping[str, Any]) -> tuple[dict[str, Any], float]:
        now = cls._num(payload.get("now"), "now", minimum=0.0)
        grants = cls._parse_grants(payload)
        workspace_id = cls._text(payload.get("workspace_id"), "inspect_workspace_id")
        principal_id = cls._text(payload.get("principal_id"), "inspect_principal_id")
        capability_raw = payload.get("capability")
        capability: str | None = None
        if capability_raw is not None:
            capability = cls._text(capability_raw, "inspect_capability", lower=True)
            if capability not in cls.CAPABILITIES:
                raise CapabilityError(f"inspect_capability_unknown:{capability}")
        active = [
            grant
            for grant in grants
            if grant["workspace_id"] == workspace_id
            and grant["principal_id"] == principal_id
            and (capability is None or grant["capability"] == capability)
            and not grant["revoked"]
            and now <= grant["expires_at"]
            and grant["used_units"] < grant["max_units"]
        ]
        active.sort(key=lambda grant: (grant["capability"], grant["expires_at"], grant["grant_id"]))
        return (
            {
                "workspace_id": workspace_id,
                "principal_id": principal_id,
                "capability": capability,
                "active_grants": active,
                "active_count": len(active),
                "matrix_digest": _digest(sorted(grants, key=lambda grant: grant["grant_id"])),
            },
            cls._work_units(len(grants)),
        )

    def evaluate(self, req: WorkspaceCapMatrixRequest) -> WorkspaceCapMatrixReceipt:
        if not isinstance(req, WorkspaceCapMatrixRequest):
            raise TypeError("req must be WorkspaceCapMatrixRequest")
        reasons: list[str] = []
        try:
            subject_id = self._text(req.subject_id, "subject_id")
        except CapabilityError as exc:
            subject_id = ""
            reasons.append(str(exc))
        try:
            budget = self._num(req.budget, "budget", minimum=0.001)
        except CapabilityError as exc:
            budget = 0.0
            reasons.append(str(exc))
        if not isinstance(req.payload, Mapping):
            reasons.append("payload_not_object")
            payload: Mapping[str, Any] = {}
        else:
            payload = req.payload

        bound_grant_id: str | None = None
        if req.grant_id is not None:
            try:
                bound_grant_id = self._text(req.grant_id, "grant_id")
            except CapabilityError as exc:
                reasons.append(str(exc))

        if req.not_after is not None:
            try:
                not_after = self._num(req.not_after, "not_after", minimum=0.0)
                if "now" not in payload:
                    reasons.append("not_after_requires_now")
                else:
                    now = self._num(payload.get("now"), "now", minimum=0.0)
                    if now > not_after:
                        reasons.append("request_expired")
            except CapabilityError as exc:
                reasons.append(str(exc))

        result: dict[str, Any] | None = None
        work_units = 0.0
        try:
            mode_raw = payload.get("mode", "dispatch")
            mode = self._text(mode_raw, "mode", lower=True)
            if mode not in self.MODES:
                raise CapabilityError("mode_invalid")
            if mode == "dispatch":
                result, mode_reasons, work_units = self._dispatch(
                    payload, bound_grant_id=bound_grant_id
                )
                reasons.extend(mode_reasons)
            elif mode == "revoke":
                result, work_units = self._revoke(
                    payload, bound_grant_id=bound_grant_id
                )
            else:
                result, work_units = self._inspect(payload)
            if work_units > budget:
                reasons.append("evaluation_budget_exceeded")
        except CapabilityError as exc:
            reasons.append(str(exc))

        decision = Decision.REFUSE if reasons else Decision.ALLOW
        metrics = {
            "result": result,
            "work_units": work_units,
            "budget_units": budget,
        }
        body = {
            "subject_id": subject_id,
            "grant_id": bound_grant_id,
            "not_after": req.not_after,
            "decision": decision.value,
            "reasons": reasons,
            "metrics": metrics,
        }
        success_reason = "workspace_capability_transition_verified"
        return WorkspaceCapMatrixReceipt(
            decision,
            tuple(reasons or [success_reason]),
            _digest(body),
            metrics,
        )

    def evaluate_batch(
        self, requests: Iterable[WorkspaceCapMatrixRequest]
    ) -> tuple[WorkspaceCapMatrixReceipt, ...]:
        return tuple(self.evaluate(request) for request in requests)


Mechanism = WorkspaceCapMatrix
