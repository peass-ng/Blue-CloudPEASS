"""Read an owned regional public ALB's native WAF association; never infer one.

GetWebACLForResource returns the associated WebACL. A successful empty SDK
object does not prove absence; only the operation's explicit nonexistent-item
error is accepted as absent under the bounded inventory contract.
"""
from copy import deepcopy
import re

READ_ACTIONS = {('sts', 'get_caller_identity'), ('wafv2', 'get_web_acl_for_resource')}
SOURCE = 'wafv2:GetWebACLForResource'
PROFILE = 'aws-alb-waf-association-metadata-v1'
ALB = re.compile(r'arn:(?P<partition>aws(?:-[a-z0-9-]+)?):elasticloadbalancing:(?P<region>[a-z0-9-]+):(?P<account>[0-9]{12}):loadbalancer/app/(?P<name>[^/]+)/[A-Za-z0-9]+')
ACL = re.compile(r'arn:(?P<partition>aws(?:-[a-z0-9-]+)?):wafv2:(?P<region>[a-z0-9-]+):(?P<account>[0-9]{12}):regional/webacl/(?P<name>[^/]+)/(?P<id>[^/]+)')


def _unavailable(row, status, code):
    coverage = row.setdefault('_coverage', {})
    if isinstance(coverage, dict):
        coverage['WAFWebACLArn'] = {'status': status, 'code': code}
    row['WAFWebACLArnObservation'] = {'collection_status': status, 'source_operation': SOURCE,
                                    'profile': PROFILE, 'error': {'code': code}}


def enrich(requests, session, region, items):
    output = []
    for original in items:
        row = deepcopy(original)
        # Never retain an old or caller-supplied association through a failed read.
        row.pop('WAFWebACLArn', None)
        row.pop('WAFWebACLArnObservation', None)
        if isinstance(row.get('_coverage'), dict):
            row['_coverage'].pop('WAFWebACLArn', None)
        output.append(row)
        if row.get('Type') != 'application' or row.get('Scheme') != 'internet-facing':
            continue
        arn = row.get('LoadBalancerArn')
        binding = ALB.fullmatch(arn) if isinstance(arn, str) else None
        if (binding is None or binding['region'] != region or
                ('LoadBalancerName' in row and row['LoadBalancerName'] != binding['name'])):
            _unavailable(row, 'malformed', 'alb_waf_resource_identity_invalid')
            continue
        identity = requests.detail(session, 'sts', region, 'get_caller_identity')
        caller_arn = identity.get('Arn')
        if (identity.get('collection_status') != 'collected' or identity.get('Account') != binding['account']
                or not isinstance(caller_arn, str)
                or not caller_arn.startswith('arn:' + binding['partition'] + ':')
                or caller_arn.split(':')[4:5] != [binding['account']]):
            _unavailable(row, identity.get('collection_status') if identity.get('collection_status') not in (None, 'collected') else 'malformed',
                         'alb_waf_caller_binding_unavailable')
            continue
        response = requests.detail(session, 'wafv2', region, 'get_web_acl_for_resource',
                                   ResourceArn=arn, absent=('WAFNonexistentItemException',))
        status = response.get('collection_status')
        absent = (status == 'empty' and response.get('absent') is True and
                  isinstance(response.get('error'), dict) and response['error'].get('code') == 'WAFNonexistentItemException')
        web = response.get('WebACL')
        acl_arn = web.get('ARN') if isinstance(web, dict) else None
        match = ACL.fullmatch(acl_arn) if isinstance(acl_arn, str) else None
        bound = (status == 'collected' and match is not None and
                 all(match[key] == binding[key] for key in ('partition', 'account', 'region'))
                 and web.get('Name') == match['name'] and web.get('Id') == match['id'])
        if not absent and not bound:
            error = response.get('error')
            _unavailable(row, status if status not in (None, 'collected', 'empty') else 'malformed',
                         error.get('code', 'alb_waf_association_unbound') if isinstance(error, dict) else 'alb_waf_association_unbound')
            continue
        row['WAFWebACLArn'] = '' if absent else acl_arn
        row['WAFWebACLArnObservation'] = {'collection_status': 'empty' if absent else 'collected',
            'source_operation': SOURCE, 'profile': PROFILE, 'ResourceArn': arn,
            'account_id': binding['account'], 'region': region,
            **({'absent_code': 'WAFNonexistentItemException'} if absent else {'WebACLArn': acl_arn})}
    return output


ENRICHERS = {'load_balancer_v2': enrich}
