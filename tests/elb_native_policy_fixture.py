"""Inert explicitly source-bound Classic ELB SDK-shaped fixtures; never live proof."""
import copy


def bind_policy_sources(row, scope='123456789012/us-east-1', created_at='2026-10-12T00:00:00+00:00', catalog=None):
    row = copy.deepcopy(row)
    policies = row.pop('PolicyDescriptions')
    for p in policies:
        p.pop('PolicyOrigin', None)
        if p['PolicyTypeName'] == 'SSLNegotiationPolicy':
            p['PolicyTypeName'] = 'SSLNegotiationPolicyType'
    names = sorted({name for l in row['ListenerDescriptions'] if l['Listener']['Protocol'] in {'HTTPS','SSL'} for name in l['PolicyNames']})
    account, region = scope.split('/')
    for field, request, rows in [('SSLPolicyDetails', {'LoadBalancerName':row['LoadBalancerName'],'PolicyNames':names}, policies),
                                  ('SSLPolicyCatalog', {}, policies if catalog is None else catalog)]:
        row[field] = {'collection_status':'collected','PolicyDescriptions':copy.deepcopy(rows),
                      '_provenance':{'operation':'elb:DescribeLoadBalancerPolicies','account_id':account,'region':region,
                                     'request':request,'read_only':True,'captured_at':created_at}}
    return row
