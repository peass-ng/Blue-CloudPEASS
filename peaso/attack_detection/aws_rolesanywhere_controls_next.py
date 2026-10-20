"""Normalize successful Roles Anywhere changes that can widen certificate access."""

from __future__ import annotations

from collections.abc import Mapping
import json
import re
from typing import Any


NAMES = {'UpdateTrustAnchor', 'UpdateProfile', 'DeleteAttributeMapping', 'PutAttributeMapping'}


def _broad_policy(value: Any) -> bool:
    try:
        policy = json.loads(value) if isinstance(value, str) else value
    except ValueError:
        return False
    if not isinstance(policy, Mapping):
        return False
    statements = policy.get('Statement', [])
    statements = [statements] if isinstance(statements, Mapping) else statements
    if not isinstance(statements, list) or any(isinstance(s, Mapping) and s.get('Effect') == 'Deny' for s in statements):
        return False
    return any(isinstance(s, Mapping) and s.get('Effect') == 'Allow'
               and s.get('Action') == '*' and s.get('Resource') == '*'
               and not s.get('Condition') and 'NotAction' not in s and 'NotResource' not in s
               for s in statements)


def _issuer_cn_removed(mappings: Any) -> bool:
    if not isinstance(mappings, list):
        return False
    issuer = [m for m in mappings if isinstance(m, Mapping) and m.get('certificateField') == 'x509Issuer']
    if not issuer:
        return True
    rules = issuer[0].get('mappingRules')
    return isinstance(rules, list) and all(isinstance(rule, Mapping) and rule.get('specifier') not in {'*', 'CN'} for rule in rules)


def normalize_aws_rolesanywhere_controls(record: Mapping[str, Any]) -> dict[str, Any] | None:
    name = record.get('eventName')
    if (record.get('eventSource') != 'rolesanywhere.amazonaws.com' or name not in NAMES
            or record.get('eventCategory') != 'Management' or record.get('eventType') != 'AwsApiCall'
            or record.get('managementEvent') is not True or record.get('readOnly') is not False):
        return None
    account, request, response = (record.get(k) for k in ('recipientAccountId', 'requestParameters', 'responseElements'))
    if (not isinstance(account, str) or not re.fullmatch(r'\d{12}', account)
            or not isinstance(request, Mapping) or not isinstance(response, Mapping)):
        return None
    failed = bool(record.get('errorCode') or record.get('errorMessage')
                  or response.get('errorCode') or response.get('errorMessage'))
    target = request.get('trustAnchorId') if name == 'UpdateTrustAnchor' else request.get('profileId')
    if not isinstance(target, str) or not target:
        return None
    resource = response.get('trustAnchor') if name == 'UpdateTrustAnchor' else response.get('profile')
    if not isinstance(resource, Mapping) or resource.get('trustAnchorId' if name == 'UpdateTrustAnchor' else 'profileId') != target:
        return None
    source = request.get('source')
    anchor = (name == 'UpdateTrustAnchor' and isinstance(source, Mapping)
              and source.get('sourceType') == 'CERTIFICATE_BUNDLE'
              and isinstance(source.get('sourceData'), Mapping)
              and isinstance(source['sourceData'].get('x509CertificateData'), str)
              and bool(source['sourceData']['x509CertificateData']))
    roles = resource.get('roleArns')
    profile_broad = (name == 'UpdateProfile' and request.get('managedPolicyArns') == []
                     and _broad_policy(request.get('sessionPolicy'))
                     and isinstance(roles, list) and bool(roles)
                     and resource.get('managedPolicyArns') == []
                     and _broad_policy(resource.get('sessionPolicy')))
    field = request.get('certificateField')
    issuer_delete = (name == 'DeleteAttributeMapping' and field == 'x509Issuer'
                     and isinstance(request.get('specifiers'), list)
                     and ('*' in request['specifiers'] or 'CN' in request['specifiers'])
                     and _issuer_cn_removed(resource.get('attributeMappings')))
    issuer_narrow = (name == 'PutAttributeMapping' and field == 'x509Issuer'
                     and _issuer_cn_removed(resource.get('attributeMappings')))
    actor = record.get('userIdentity')
    actor = actor if isinstance(actor, Mapping) else {}
    return {'cloud.provider': 'aws', 'event.source': record.get('eventSource'), 'event.name': name,
            'event.outcome': 'failure' if failed else 'success', 'event.id': record.get('eventID'),
            'event.time': record.get('eventTime'), 'account.id': account,
            'actor.id': actor.get('arn'), 'target.id': target,
            'request.rolesanywhere_anchor_ca_replaced': anchor and not failed,
            'request.rolesanywhere_profile_boundary_broad': profile_broad and not failed,
            'request.rolesanywhere_issuer_cn_deleted': issuer_delete and not failed,
            'request.rolesanywhere_issuer_cn_unmapped': issuer_narrow and not failed}
