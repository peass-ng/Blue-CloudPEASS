"""Signed configuration scans of the full IAM policy universe, not effective access."""
from __future__ import annotations
import json
from collections import Counter
import re
from pathlib import Path
from . import register, result, unknown
from .facts import Unavailable, complete_items, get, list_of_objects, memoized

MODES = {
    'aws.nist.all_iam_policies_no_star_star': 'star',
    'aws.nist.all_managed_policies_no_service_wildcard': 'managed_service',
    'aws_nist_iam_policy_no_star_star': 'star',
    'aws_nist_iam_all_policy_no_service_wild_card': 'service',
    'aws_g6_iam_all_policy_star_star': 'star',
    'aws_g6_iam_all_policy_service_wildcard': 'scoped_service',
}
SPECS = json.loads(Path(__file__).with_suffix('.json').read_text())


def _rows(index, kind, account):
    rows = complete_items(index, kind)
    envelopes = get(index, 'collections', dict)[kind]
    expected = []
    for envelope in envelopes:
        if get(envelope, 'scope', str) != account+'/global' or get(envelope, 'type', str) != kind:
            raise Unavailable('foreign global IAM collection')
        expected.extend(list_of_objects(get(envelope, 'items', list)))
    wrappers = get(index, kind, list)
    encode=lambda value:json.dumps(value,sort_keys=True,separators=(',',':'))
    if Counter(map(encode,expected)) != Counter(map(encode,rows)) or len(wrappers) != len(rows) or any(
            get(w, 'scope', str) != account+'/global' or get(w, 'type', str) != kind for w in wrappers):
        raise Unavailable('IAM wrappers do not match complete native collection')
    return rows


def _statements(document):
    statements = get(document, 'Statement')
    return list_of_objects([statements] if isinstance(statements, dict) else statements)


def _documents(index, managed_only):
    context = get(index, 'context', dict)
    account = get(context, 'Account', str)
    if get(context, 'provider', str) != 'aws' or not re.fullmatch(re.escape(account)+r'/(?:global|[a-z0-9-]+)', get(context,'scope',str)) or not re.fullmatch(r'[0-9]{12}', account):
        raise Unavailable('global IAM account authority missing')
    out, seen = [], set()
    for row in _rows(index, 'iam_managed_policy', account):
        arn = get(row, 'Arn', str)
        if not re.fullmatch(r'arn:(aws|aws-cn|aws-us-gov):iam::(?:'+account+r'|aws):policy/.+', arn) or arn in seen:
            raise Unavailable('foreign or duplicate managed policy')
        seen.add(arn)
        provenance = get(row, '_provenance', dict)
        if (provenance.get('operation') != 'iam:ListPolicies' or provenance.get('managed_scope') != 'All'
                or provenance.get('only_attached') is not False or provenance.get('account_id') != account):
            raise Unavailable('managed policy universe unproven')
        detail = get(row, 'DefaultDocument', dict)
        if get(detail, 'VersionId', str) != get(row, 'DefaultVersionId', str):
            raise Unavailable('default policy version mismatch')
        out.extend((arn, statement) for statement in _statements(get(detail, 'Document', dict)))
    if not managed_only:
        for kind, field in [('iam_user','UserPolicyList'),('iam_group','GroupPolicyList'),('iam_role','RolePolicyList')]:
            for row in _rows(index, kind, account):
                arn = get(row, 'Arn', str)
                if not re.fullmatch(r'arn:(aws|aws-cn|aws-us-gov):iam::'+account+r':'+kind[4:]+r'/.+', arn) or arn in seen:
                    raise Unavailable('foreign or duplicate IAM principal')
                seen.add(arn)
                provenance = get(row, '_provenance', dict)
                if provenance.get('operation') != 'iam:GetAccountAuthorizationDetails' or provenance.get('native_response_complete') is not True:
                    raise Unavailable('inline IAM representation incomplete')
                # User/Group/RolePolicyList are optional in this full native response.
                for policy in list_of_objects(get(row, field, list) if field in row or field in row.get('_coverage',{}) else []):
                    out.extend((arn+'/'+get(policy,'PolicyName',str), statement) for statement in _statements(get(policy,'PolicyDocument',dict)))
    return out


def _strings(value):
    if isinstance(value,str): value=[value]
    if not isinstance(value,list) or not value or any(not isinstance(v,str) or not v for v in value):
        raise Unavailable('malformed IAM action/resource')
    return value


def scan(index, mode):
    documents = memoized(index, ('all_iam_documents', mode == 'managed_service'), lambda: _documents(index, mode == 'managed_service'))
    hits, unresolved = [], False
    for source, statement in documents:
        effect = get(statement, 'Effect', str)
        if effect not in ('Allow','Deny'): raise Unavailable('unknown IAM statement effect')
        if effect == 'Deny': continue
        if 'NotAction' in statement or 'NotResource' in statement:
            unresolved = True
            continue
        actions, resources = _strings(get(statement,'Action')), _strings(get(statement,'Resource'))
        star = any(a in ('*','*:*') for a in actions)
        service = star or any(re.fullmatch(r'[A-Za-z0-9-]+:\*',a) for a in actions)
        if mode == 'scoped_service':
            match = service and any(r.startswith('arn:') and '*' not in r and '?' not in r for r in resources)
        elif mode in ('service','managed_service'):
            match = service and '*' in resources
            if mode == 'service' and service and any(r!='*' and ('*'in r or '?'in r)for r in resources): unresolved=True
        else: match=star and '*' in resources
        if match: hits.append(source)
    if unresolved and not hits: return unknown('NotAction/NotResource or service resource patterns need effective interpretation', matching_policy_sources=sorted(set(hits)))
    return result(bool(hits), matching_policy_sources=sorted(set(hits)), scanned_statements=len(documents),
                  semantics='All available managed default documents and inline configuration; attachment and effective authorization are separate')


for ident, mode in MODES.items():
    spec = SPECS[ident]
    def evaluate(item,index,mode=mode):
        context=get(index,'context',dict)
        if get(item,'scope',str)!=get(context,'scope',str): raise Unavailable('scope target mismatch')
        return scan(index,mode)
    register(ident,'aws','hardening',spec['resource_kind'],spec['title'],spec['severity'],'AC-6',spec['remediation_hint'],
             target='scope',dependencies=['iam_managed_policy']+([] if mode=='managed_service' else ['iam_user','iam_group','iam_role']))(evaluate)

from .fixtures import CASES
CASES.update(json.loads(Path(__file__).with_name('aws_all_policies_fixtures.json').read_text()))
