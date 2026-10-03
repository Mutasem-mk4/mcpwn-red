from __future__ import annotations

from typing import TYPE_CHECKING, Literal

from pydantic import BaseModel, ConfigDict, Field

if TYPE_CHECKING:
    from mcpwn_red.attacks.base import AttackResult


class PolicyRule(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action: Literal["allow", "deny"]
    severity: Literal["critical", "high", "medium", "low"] = "medium"


class AssessmentPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1)
    checks: dict[str, PolicyRule] = Field(min_length=1)


def evaluate_policy(probe: AttackResult, policy: AssessmentPolicy | None) -> AttackResult:
    rule = policy.checks.get(probe.id) if policy else None
    status = probe.status
    recommendation = probe.recommendation
    if status in {"PASS", "FAIL"}:
        if rule is None:
            status = "UNKNOWN"
            recommendation = "Declare an allow/deny rule for this check in --policy."
        elif rule.action == "allow":
            status = "PASS" if probe.status == "FAIL" else "UNKNOWN"
            recommendation = (
                "The policy allows this condition; absence does not prove availability."
            )
        else:
            recommendation = (
                "Review this probe against the declared deny rule; not proof of exploit."
            )
    return probe.model_copy(
        update={
            "status": status,
            "severity": rule.severity if rule else "low",
            "probe_status": probe.status,
            "policy_action": rule.action if rule else None,
            "evidence_kind": "registration" if probe.module == "yaml" else "tool_response",
            "recommendation": recommendation,
        }
    )
