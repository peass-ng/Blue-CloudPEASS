"""A same-account IAM user can add a queue policy granting itself ReceiveMessage."""
from __future__ import annotations

import re
from urllib.parse import urlparse

from . import Grant, Node, inventory_status, items

_QUEUE = re.compile(r"arn:(aws|aws-cn|aws-us-gov):sqs:([^:]+):(\d{12}):([^:*?\s]+)")


def load(model):
    from .aws import _resource_principal

    statuses = inventory_status(model.snapshot, "sqs_queue")
    nodes, records = {}, {}
    for scope, queue in items(model.snapshot, "sqs_queue"):
        if statuses.get(scope) != "collected" or not isinstance(queue, dict):
            continue
        detail = queue.get("Attributes")
        if not isinstance(detail, dict) or detail.get("collection_status") != "collected":
            continue
        attrs = detail.get("Attributes")
        if not isinstance(attrs, dict):
            continue
        arn = attrs.get("QueueArn")
        match = _QUEUE.fullmatch(arn) if isinstance(arn, str) else None
        if not match or scope != f"{match.group(3)}/{match.group(2)}":
            continue
        queue_url = urlparse(str(queue.get("QueueUrl") or ""))
        if (queue_url.scheme != "https" or
                queue_url.path != f"/{match.group(3)}/{match.group(4)}" or
                not (queue_url.hostname or "").startswith(f"sqs.{match.group(2)}.") or
                not (queue_url.hostname or "").endswith((".amazonaws.com", ".amazonaws.com.cn"))):
            continue
        # SSE-KMS needs a separate exact Decrypt authorization, including for an AWS-managed key.
        if attrs.get("KmsMasterKeyId") != "":
            continue
        for source in model.principals.values():
            if source.kind != "aws_user" or source.scope != match.group(3) or source.incomplete:
                continue
            if source.attrs.get("boundary"):
                # IAM-user resource grants have special boundary semantics; do not infer through that case here.
                continue
            writer = model._check_action(source, "sqs:setqueueattributes", arn)
            if writer is None or writer.confidence != "derived":
                continue
            if model._check_action(source, "sqs:receivemessage", arn) is not None:
                continue
            if model._explicit_deny_for_action(source, "sqs:receivemessage", arn) is not False:
                continue
            ctx = model._ctx(source, "sqs:receivemessage", arn)
            existing = model.resource_policies.get(arn)
            undecided = False
            if existing:
                for statement in existing[1]:
                    if statement.effect != "deny" or not statement.action_matches("sqs:receivemessage"):
                        continue
                    if statement.match(arn, ctx) is False:
                        continue
                    principal_match = _resource_principal(statement, source)
                    if statement.ref.get("not_principal"):
                        principal_match = None if principal_match else "direct"
                    if principal_match is None or model._cond(statement, ctx, "deny")[0] is False:
                        continue
                    # A matching or unresolved queue-policy Deny can defeat the proposed Allow.
                    undecided = True
                    break
            if undecided:
                continue
            hypothetical = model._guardrails(source, "sqs:receivemessage", arn,
                                            Grant("derived", [{"proposed_queue_policy": arn}]), ctx)
            if hypothetical is None or hypothetical.confidence != "derived":
                continue
            target_id = f"aws_verified_authority:sqs-policy:{arn}:{source.id}"
            nodes[target_id] = Node(target_id, "aws_verified_authority", "aws", source.scope,
                                    f"sqs:ReceiveMessage on {arn}",
                                    attrs={"account": source.scope, "arn": arn, "resource_arn": arn,
                                           "source_id": source.id}, entity=True)
            records[target_id] = {"SourceArn": source.id, "QueueArn": arn,
                                  "WriterGrant": writer, "QueueUrl": queue["QueueUrl"]}
    return nodes, records
