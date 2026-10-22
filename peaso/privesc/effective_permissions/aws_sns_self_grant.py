"""An IAM user can replace a topic policy to grant itself sns:Subscribe."""
from __future__ import annotations

import re
from dataclasses import replace

from . import Grant, Node, inventory_status, items

_TOPIC = re.compile(r"arn:(aws|aws-cn|aws-us-gov):sns:([^:]+):(\d{12}):([^:*?\s]+)")


def load(model):
    from .aws import _resource_principal

    statuses = inventory_status(model.snapshot, "sns_topic")
    nodes, records = {}, {}
    for scope, topic in items(model.snapshot, "sns_topic"):
        if statuses.get(scope) != "collected" or not isinstance(topic, dict):
            continue
        detail = topic.get("Attributes")
        if not isinstance(detail, dict) or detail.get("collection_status") != "collected":
            continue
        attrs = detail.get("Attributes")
        if not isinstance(attrs, dict):
            continue
        arn = topic.get("TopicArn")
        match = _TOPIC.fullmatch(arn) if isinstance(arn, str) else None
        if not match or attrs.get("TopicArn", arn) != arn or scope != f"{match.group(3)}/{match.group(2)}":
            continue
        existing = model.resource_policies.get(arn)
        if "Policy" in attrs and existing is None:
            continue
        for source in model.principals.values():
            if source.kind != "aws_user" or source.scope != match.group(3) or source.incomplete:
                continue
            writer = model._check_action(source, "sns:settopicattributes", arn)
            if writer is None or writer.confidence != "derived":
                continue
            if model._check_action(source, "sns:subscribe", arn) is not None:
                continue
            if model._explicit_deny_for_action(source, "sns:subscribe", arn) is not False:
                continue
            ctx = model._ctx(source, "sns:subscribe", arn)
            prior_direct_allow = prior_resource_deny = False
            if existing:
                for statement in existing[1]:
                    if not statement.action_matches("sns:subscribe") or statement.match(arn, ctx) is False:
                        continue
                    principal_match = _resource_principal(statement, source)
                    if statement.ref.get("not_principal"):
                        principal_match = ("direct" if statement.effect == "deny" and source.attrs.get("boundary")
                                           else None if principal_match else "direct")
                    if principal_match is None:
                        continue
                    verdict = model._cond(statement, ctx, statement.effect)[0]
                    if statement.effect == "deny" and verdict is True:
                        prior_resource_deny = True
                    elif statement.effect == "allow" and principal_match == "direct" and verdict is not False:
                        prior_direct_allow = True
            # The old policy is replaced; its Deny does not survive the write.
            if prior_direct_allow and not prior_resource_deny:
                continue
            # An exact resource-policy Allow for a same-account IAM user bypasses
            # an implicit boundary deny; explicit denies were checked above.
            recipient = (replace(source, attrs={**source.attrs, "boundary": None})
                         if source.attrs.get("boundary") else source)
            hypothetical = model._guardrails(recipient, "sns:subscribe", arn,
                                             Grant("derived", [{"proposed_topic_policy": arn}]), ctx)
            if hypothetical is None or hypothetical.confidence != "derived":
                continue
            target_id = f"aws_verified_authority:sns-policy:{arn}:{source.id}"
            nodes[target_id] = Node(target_id, "aws_verified_authority", "aws", source.scope,
                                    f"sns:Subscribe on {arn}",
                                    attrs={"account": source.scope, "arn": arn, "resource_arn": arn,
                                           "source_id": source.id}, entity=True)
            records[target_id] = {"SourceArn": source.id, "TopicArn": arn, "WriterGrant": writer}
    return nodes, records
