"""Normalize accepted SES receipt-rule routing and activation writes."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any


NAMES = {'CreateReceiptRule', 'UpdateReceiptRule', 'SetActiveReceiptRuleSet'}


def normalize_aws_ses_receipt(record: Mapping[str, Any]) -> dict[str, Any] | None:
    name = record.get('eventName')
    if (record.get('eventSource') != 'ses.amazonaws.com' or name not in NAMES
            or record.get('eventCategory') != 'Management' or record.get('eventType') != 'AwsApiCall'
            or record.get('managementEvent') is not True or record.get('readOnly') is not False):
        return None
    request = record.get('requestParameters')
    if not isinstance(request, Mapping):
        return None
    rule_set = request.get('ruleSetName')
    valid_set = isinstance(rule_set, str) and bool(rule_set)
    failed = bool(record.get('errorCode') or record.get('errorMessage'))
    rule = request.get('rule')
    rule = rule if isinstance(rule, Mapping) else {}
    rule_name = rule.get('name')
    actions = rule.get('actions')
    actions = actions if isinstance(actions, Sequence) and not isinstance(actions, (str, bytes)) else ()
    s3 = next((a.get('s3Action') for a in actions if isinstance(a, Mapping)
               and isinstance(a.get('s3Action'), Mapping)
               and isinstance(a['s3Action'].get('bucketName'), str)
               and a['s3Action']['bucketName']), None)
    catch_all = 'recipients' not in rule or rule.get('recipients') == []
    enabled = rule.get('enabled') is True
    rule_write = valid_set and isinstance(rule_name, str) and bool(rule_name) and not failed
    actor = record.get('userIdentity')
    actor = actor if isinstance(actor, Mapping) else {}
    return {'cloud.provider': 'aws', 'event.source': record.get('eventSource'),
            'event.name': name, 'event.outcome': 'failure' if failed else 'success',
            'event.id': record.get('eventID'), 'event.time': record.get('eventTime'),
            'account.id': record.get('recipientAccountId'), 'actor.id': actor.get('arn'),
            'target.id': f'{rule_set}/{rule_name}' if rule_write else rule_set if valid_set else None,
            'request.ses_receipt_s3_catchall': (name in {'CreateReceiptRule', 'UpdateReceiptRule'}
                                                and rule_write and enabled and catch_all and s3 is not None),
            'request.ses_receipt_scan_disabled': (name in {'CreateReceiptRule', 'UpdateReceiptRule'}
                                                  and rule_write and enabled and rule.get('scanEnabled') is False),
            'request.ses_receipt_rule_set_activated': name == 'SetActiveReceiptRuleSet' and valid_set and not failed}
