"""Identify response-confirmed ARC Region Switch Lambda action plans."""

from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any

from .aws_arc_ssm_plan import accepted_arc_plan


_LAMBDA = re.compile(
    r"arn:(?:aws|aws-us-gov|aws-cn):lambda:([a-z]{2}(?:-[a-z]+)+-[0-9]):"
    r"[0-9]{12}:function:[A-Za-z0-9_-]{1,64}(?::[A-Za-z0-9$_-]+)?\Z"
)
_RUN_REGIONS = {"activatingRegion", "deactivatingRegion", "activeRegion", "inactiveRegion"}


def _lambda_step(steps: Any, depth: int = 0) -> bool:
    if not isinstance(steps, list) or len(steps) > 100 or depth > 3:
        return False
    for step in steps:
        if not isinstance(step, Mapping):
            continue
        config = step.get("executionBlockConfiguration")
        if not isinstance(config, Mapping):
            continue
        if step.get("executionBlockType") == "CustomActionLambda":
            action = config.get("customActionLambdaConfig")
            if isinstance(action, Mapping) and action.get("regionToRun") in _RUN_REGIONS:
                functions = action.get("lambdas")
                if isinstance(functions, list) and len(functions) == 2:
                    regions = []
                    for item in functions:
                        arn = item.get("arn") if isinstance(item, Mapping) else None
                        match = _LAMBDA.fullmatch(arn) if isinstance(arn, str) else None
                        if match is None:
                            break
                        regions.append(match.group(1))
                    if len(set(regions)) == 2:
                        return True
        nested = config.get("parallelConfig")
        if isinstance(nested, Mapping) and _lambda_step(nested.get("steps"), depth + 1):
            return True
    return False


def normalize_aws_arc_lambda_plan(record: Mapping[str, Any]) -> dict[str, Any] | None:
    """Flag accepted plan writes without copying code, payloads or function ARNs."""
    accepted = accepted_arc_plan(record)
    if accepted is None:
        return None
    result, workflows = accepted
    if not any(isinstance(workflow, Mapping)
               and _lambda_step(workflow.get("steps")) for workflow in workflows):
        return None
    result["request.arc_lambda_action_plan_created" if record["eventName"] == "CreatePlan"
           else "request.arc_lambda_action_plan_updated"] = True
    return result
