"""Recognize a fully covering Deny outside a bounded IP allowlist.

Only exact/all selector coverage and one required NotIpAddress condition are
accepted. More complex Deny interactions remain for the general policy reviewer.
"""
from copy import deepcopy
import json
from .aws_resource_policy_scope import boundary, strings
from .facts import Unavailable


def _covers(deny, allow, *, ignore_case=False):
    denied, allowed = strings(deny), strings(allow)
    return all(any(d == '*' or (d.casefold() == a.casefold() if ignore_case else d == a) for d in denied) for a in allowed)


def normalize(document):
    if isinstance(document, str):
        try:
            document = json.loads(document)
        except ValueError as error:
            try:
                document = json.loads(document.replace('\\"', '"'))
            except ValueError:
                raise Unavailable('malformed JSON resource policy') from error
    if not isinstance(document, dict):
        raise Unavailable('resource policy document is unavailable')
    value = deepcopy(document)
    statements = value.get('Statement')
    if isinstance(statements, dict):
        statements = [statements]
        value['Statement'] = statements
    if not isinstance(statements, list) or any(not isinstance(s, dict) for s in statements):
        raise Unavailable('malformed resource policy statements')
    changed = False
    for allow in statements:
        if allow.get('Effect') != 'Allow' or allow.get('Condition') or 'Action' not in allow or 'Resource' not in allow:
            continue
        for deny in statements:
            if deny.get('Effect') != 'Deny' or deny.get('Principal') not in ('*', {'AWS': '*'}, {'AWS': ['*']}):
                continue
            condition = deny.get('Condition')
            if not isinstance(condition, dict) or len(condition) != 1:
                continue
            operator, block = next(iter(condition.items()))
            if operator.casefold() != 'notipaddress' or not isinstance(block, dict) or len(block) != 1:
                continue
            key, ranges = next(iter(block.items()))
            positive = {'IpAddress': {key: ranges}}
            if key.casefold() != 'aws:sourceip' or not boundary(positive, minimum_ipv6_prefix=1):
                continue
            if 'NotAction' in deny or 'NotResource' in deny or 'Action' not in deny or 'Resource' not in deny:
                continue
            if _covers(deny['Action'], allow['Action'], ignore_case=True) and _covers(deny['Resource'], allow['Resource']):
                allow['Condition'] = positive
                changed = True
                break
    return value, changed
