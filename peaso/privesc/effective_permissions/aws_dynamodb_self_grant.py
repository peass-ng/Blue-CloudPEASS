"""An IAM user can replace a table policy to grant itself dynamodb:GetItem."""
from __future__ import annotations

import re
from dataclasses import replace

from . import Grant, Node, inventory_status, items

_TABLE = re.compile(r"arn:(aws|aws-cn|aws-us-gov):dynamodb:([^:]+):(\d{12}):table/([^/*?\s]+)")


def load(model):
    from .aws import _resource_principal

    statuses = inventory_status(model.snapshot, "dynamodb_table")
    nodes, records = {}, {}
    for scope, item in items(model.snapshot, "dynamodb_table"):
        if statuses.get(scope) != "collected" or not isinstance(item, dict):
            continue
        detail, policy = item.get("Table"), item.get("ResourcePolicy")
        if (not isinstance(detail, dict) or detail.get("collection_status") != "collected" or
                not isinstance(policy, dict) or policy.get("collection_status") not in ("collected", "empty")):
            continue
        table = detail.get("Table")
        if not isinstance(table, dict):
            continue
        arn = table.get("TableArn")
        match = _TABLE.fullmatch(arn) if isinstance(arn, str) else None
        if (not match or scope != f"{match.group(3)}/{match.group(2)}" or
                item.get("TableName") != match.group(4) or table.get("TableName") != match.group(4) or
                table.get("TableStatus") != "ACTIVE"):
            continue
        # Customer/AWS-managed KMS keys need a separate exact key-policy/grant join.
        sse = table.get("SSEDescription")
        if sse is not None and (not isinstance(sse, dict) or sse.get("SSEType") != "AES256"):
            continue
        existing = model.resource_policies.get(arn)
        if policy.get("collection_status") == "collected" and existing is None:
            continue
        for source in model.principals.values():
            if source.kind != "aws_user" or source.scope != match.group(3) or source.incomplete:
                continue
            writer = model._check_action(source, "dynamodb:putresourcepolicy", arn)
            if writer is None or writer.confidence != "derived":
                continue
            if model._check_action(source, "dynamodb:getitem", arn) is not None:
                continue
            if model._explicit_deny_for_action(source, "dynamodb:getitem", arn) is not False:
                continue
            ctx = model._ctx(source, "dynamodb:getitem", arn)
            blocked = False
            if existing:
                for statement in existing[1]:
                    if not statement.action_matches("dynamodb:getitem") or statement.match(arn, ctx) is False:
                        continue
                    principal_match = _resource_principal(statement, source)
                    if statement.ref.get("not_principal"):
                        if statement.effect == "deny" and source.attrs.get("boundary"):
                            principal_match = "direct"
                        else:
                            principal_match = None if principal_match else "direct"
                    if principal_match is None or model._cond(statement, ctx, statement.effect)[0] is False:
                        continue
                    if statement.effect == "deny" or (statement.effect == "allow" and
                                                       principal_match == "direct"):
                        blocked = True
                        break
            if blocked:
                continue
            # A direct same-account user grant bypasses an implicit boundary deny.
            recipient = (replace(source, attrs={**source.attrs, "boundary": None})
                         if source.attrs.get("boundary") else source)
            hypothetical = model._guardrails(recipient, "dynamodb:getitem", arn,
                                             Grant("derived", [{"proposed_table_policy": arn}]), ctx)
            if hypothetical is None or hypothetical.confidence != "derived":
                continue
            target_id = f"aws_verified_authority:dynamodb-policy:{arn}:{source.id}"
            nodes[target_id] = Node(target_id, "aws_verified_authority", "aws", source.scope,
                                    f"dynamodb:GetItem on {arn}",
                                    attrs={"account": source.scope, "arn": arn, "resource_arn": arn,
                                           "source_id": source.id}, entity=True)
            records[target_id] = {"SourceArn": source.id, "TableArn": arn, "WriterGrant": writer}
    return nodes, records
