"""An exact Scheduler target can add an inline policy to its creator."""
from __future__ import annotations

import hashlib

from . import Grant, Node


def load(model):
    nodes, records = {}, {}
    scopes = {scope for scope in model.snapshot.get("scopes", ())
              if isinstance(scope, str) and "/" in scope}
    for source in model.principals.values():
        if source.kind not in ("aws_user", "aws_role") or source.incomplete:
            continue
        partition = source.id.split(":", 2)[1] if source.id.startswith("arn:") else None
        if partition not in ("aws", "aws-cn", "aws-us-gov"):
            continue
        account = source.scope
        user_suffix = hashlib.sha256(source.id.encode()).hexdigest()[:16]
        new_user_arn = f"arn:{partition}:iam::{account}:user/peaso-scheduler-{user_suffix}"
        if new_user_arn in model.principals:
            continue
        # The claimed new authority is one concrete IAM operation, not every
        # permission of the role that Scheduler assumes.
        if model._check_action(source, "iam:createuser", new_user_arn) is not None:
            continue
        if model._explicit_deny_for_action(source, "iam:createuser", new_user_arn) is not False:
            continue
        gained = model._guardrails(source, "iam:createuser", new_user_arn,
                                  Grant("derived", [{"proposed_inline_policy": source.id}]))
        if gained is None or gained.confidence != "derived":
            continue
        action = "iam:putuserpolicy" if source.kind == "aws_user" else "iam:putrolepolicy"
        for role in model.principals.values():
            if role.kind != "aws_role" or role.scope != account or role.incomplete:
                continue
            passrole = model.check(source, {"action": "iam:PassRole", "request_context":
                                   {"iam:PassedToService": "scheduler.amazonaws.com"}}, role.id)
            if passrole is None or passrole.confidence != "derived":
                continue
            writer = model._check_action(role, action, source.id)
            if writer is None or writer.confidence != "derived":
                continue
            for scope in scopes:
                region_account, region = scope.split("/", 1)
                if region_account != account or not region:
                    continue
                suffix = hashlib.sha256(f"{source.id}:{role.id}:{region}".encode()).hexdigest()[:16]
                schedule_arn = (f"arn:{partition}:scheduler:{region}:{account}:"
                                f"schedule/default/peaso-{suffix}")
                if model._service_trust_for_source_arn(role.id, "scheduler.amazonaws.com", schedule_arn) is not True:
                    continue
                schedule = model._check_action(source, "scheduler:createschedule", schedule_arn)
                if schedule is None or schedule.confidence != "derived":
                    continue
                target_id = f"aws_verified_authority:scheduler-policy:{source.id}:{role.id}:{region}"
                nodes[target_id] = Node(target_id, "aws_verified_authority", "aws", account,
                                        f"iam:CreateUser on {new_user_arn} through {role.id}",
                                        attrs={"account": account, "region": region, "role_arn": role.id,
                                               "schedule_arn": schedule_arn, "source_id": source.id,
                                               "resource_arn": schedule_arn,
                                               "new_user_arn": new_user_arn}, entity=True)
                records[target_id] = {"SourceArn": source.id, "ExecutorRoleArn": role.id,
                                      "ScheduleArn": schedule_arn, "TargetAction": action,
                                      "TargetResource": source.id, "PassRoleGrant": passrole,
                                      "ScheduleGrant": schedule, "PolicyWriteGrant": writer}
    return nodes, records
