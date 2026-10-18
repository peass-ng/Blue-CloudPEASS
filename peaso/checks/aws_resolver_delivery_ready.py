"""Native Resolver configuration status, independent of configured SIEM routing.

AWS defines FAILED as unable to deliver logs and CREATED as logging queries:
https://docs.aws.amazon.com/Route53/latest/APIReference/API_route53resolver_ResolverQueryLogConfig.html
This check consumes the existing paged read; it makes no cloud requests.
"""
from copy import deepcopy
import re

from . import register, result, unknown
from .facts import Unavailable, get
from .aws_a_facts import complete_items

CHECK_ID = 'aws.route53resolver.query_log_config_delivery_ready'
KIND = 'resolver_query_log_config'


@register(CHECK_ID, 'aws', 'hardening', KIND,
          'Resolver query logging configurations are ready to deliver logs', 'medium', 'AU-12',
          'Repair the configured log destination or its delivery permissions when Resolver reports FAILED.',
          dependencies=[KIND])
def resolver_delivery_ready(item, index):
    context = get(index, 'context', dict)
    if get(context, 'provider', str) != 'aws':
        raise Unavailable('foreign provider')
    scope = get(context, 'scope', str)
    match = re.fullmatch(r'([0-9]{12})/([a-z]{2}(?:-[a-z]+)+-[0-9])', scope)
    if match is None:
        raise Unavailable('regional account authority unavailable')
    account, region = match.groups()
    if 'Account' in context and get(context, 'Account', str) != account:
        raise Unavailable('account authority conflict')
    identifier, arn = get(item, 'Id', str), get(item, 'Arn', str)
    if (not re.fullmatch(r'rqlc-[A-Za-z0-9-]{1,59}', identifier)
            or not re.fullmatch(r'arn:aws(?:-[a-z0-9-]+)?:route53resolver:' + re.escape(region)
                                + ':' + account + ':resolver-query-log-config/' + re.escape(identifier), arn)):
        raise Unavailable('foreign or malformed Resolver configuration')
    rows = complete_items(index, KIND, scope)
    matching = [row for row in rows if get(row, 'Id', str) == identifier]
    if len(matching) != 1 or matching[0] != item:
        raise Unavailable('configuration identity missing or ambiguous')
    state = get(item, 'Status', str)
    if state not in {'CREATING', 'CREATED', 'DELETING', 'FAILED'}:
        raise Unavailable('unrecognized native Resolver status')
    evidence = {'configuration_arn': arn, 'native_status': state,
                'semantics': 'Native Resolver configuration status'}
    if state in {'CREATING', 'DELETING'}:
        return unknown('Resolver configuration is transitioning', **evidence)
    return result(state == 'FAILED', **evidence)


def _fixture(state):
    scope = '123456789012/us-east-1'
    row = {'Id': 'rqlc-example', 'Arn': 'arn:aws:route53resolver:us-east-1:123456789012:resolver-query-log-config/rqlc-example'}
    if state is not None:
        row['Status'] = state
    index = {'context': {'provider': 'aws', 'scope': scope, 'Account': '123456789012'},
             'collections': {KIND: [{'type': KIND, 'scope': scope, 'status': 'collected', 'items': [deepcopy(row)]}]},
             KIND: [{'type': KIND, 'scope': scope, 'data': deepcopy(row)}]}
    return row, index


from .fixtures import CASES
CASES[CHECK_ID] = {}
for _label, _state in [('pass', 'CREATED'), ('fail', 'FAILED'), ('unknown', None)]:
    CASES[CHECK_ID][_label], CASES[CHECK_ID][_label + '_index'] = _fixture(_state)
