"""Operator-declared AWS compliance policy sealed into snapshot metadata.

Only explicit, scope-bound thresholds are kept. No AWS request is involved and no organization default is
assumed. With no policy supplied, nothing is recorded and policy-dependent checks report UNKNOWN. Malformed
input is rejected before any AWS request is made. A recorded policy is a declaration, never an observed
cloud fact.
"""
from __future__ import annotations

import math
import re

SCOPE = re.compile(r"[0-9]{12}/[a-z]{2}(?:-[a-z]+)+-[0-9]")
MAX_SCOPES = 1000
MAX_FREQUENCY_HOURS = 31 * 24  # AWS Config backup-plan-min-frequency-and-min-retention-check maximum
BASIS = "operator-declared threshold; not an observed cloud fact"


def backup_plan_policy(options):
    """The validated options.compliance_policy.aws_backup_plan declaration, or None when none was supplied."""
    parent = options.get("compliance_policy")
    if parent is None:
        return None
    if not isinstance(parent, dict):
        raise ValueError("compliance_policy must be an object")
    if "aws_backup_plan" not in parent:
        return None
    raw = parent["aws_backup_plan"]
    if not isinstance(raw, dict) or set(raw) != {"applies_to", "required_frequency_hours"}:
        raise ValueError("compliance_policy.aws_backup_plan requires exactly applies_to and required_frequency_hours")
    applies, hours = raw["applies_to"], raw["required_frequency_hours"]
    if (not isinstance(applies, list) or not 0 < len(applies) <= MAX_SCOPES
            or any(type(scope) is not str or not SCOPE.fullmatch(scope) for scope in applies)
            or len(set(applies)) != len(applies)):
        raise ValueError("compliance_policy.aws_backup_plan.applies_to must list unique <account>/<region> scopes")
    if type(hours) not in (int, float) or not math.isfinite(hours) or not 0 < hours <= MAX_FREQUENCY_HOURS:
        raise ValueError("compliance_policy.aws_backup_plan.required_frequency_hours must be a number in (0, 744]")
    return {"status": "collected", "source": "operator-supplied", "basis": BASIS,
            "applies_to": sorted(applies), "required_frequency_hours": hours}


def bind_backup_plan_policy(policy, scopes):
    """Record declared scopes absent from this snapshot; a declaration never widens evaluated coverage."""
    return {**policy, "unmatched_scopes": sorted(set(policy["applies_to"]) - set(scopes))}
