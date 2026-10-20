"""Pure consumer of native-bound selected Lambda literal environment evidence."""
from copy import deepcopy
import json
import re
from peaso.secret_scanning import merge_leaks,KINGFISHER_VERSION,TRUFFLEHOG_VERSION
from peaso.collectors.aws_lambda_environment_secret_indicators import (
    KIND,CHECK,MARKER,SCHEMA,MAX_TARGETS,MAX_RESPONSE,MAX_VARIABLES,MAX_ENV_BYTES,MAX_LEAKS,MAX_LOCATIONS,SCOPE)

DECLARATIONS=[{'id':CHECK,'provider':'aws','category':'hardening','kind':KIND,'finding_type':'secrets',
    'severity':'high','requirements':[],'dependencies':['aws_account',KIND],
    'title':'Selected Lambda literal environment variables have no detected secrets',
    'remediation':'Remove exposed credential literals from the selected Lambda environment and rotate confirmed exposed credentials. Prefer scoped runtime identity or secret references.',
    'evidence_sentences':['A likely secret was detected in selected Lambda environment variables.',
        'The value is hidden; offline detection did not validate the credential.']}]


def evaluate(item,index):
    try:
        ctx=index['context'];scope=ctx['scope'];meta=ctx['metadata'];match=SCOPE.fullmatch(scope)
        if ctx['provider']!='aws' or not match or meta[KIND+'_authorized'] is not True:raise ValueError('authorization')
        account,region=match.groups()
        own=[c for c in index['collections'][KIND] if c.get('scope')==scope]
        if len(own)!=1 or own[0].get('status')!='collected' or own[0].get('account_id')!=account:raise ValueError('collection')
        own=own[0];selected=meta[KIND+'_selection'][scope]
        if (not isinstance(selected,list) or not 1<=len(selected)<=MAX_TARGETS or len(set(selected))!=len(selected)
                or any(not isinstance(s,str) or not re.fullmatch(KIND+':[0-9a-f]{64}',s) for s in selected)
                or not isinstance(own.get('items'),list) or len(own['items'])!=len(selected)
                or {i.get('id') for i in own['items']}!=set(selected) or sum(i==item for i in own['items'])!=1):
            raise ValueError('selection')
        parents=[c for c in index['collections']['aws_account'] if c.get('scope')==account+'/global']
        if (len(parents)!=1 or parents[0].get('status')!='collected' or parents[0].get('account_id')!=account
                or parents[0].get('global') is not True or len(parents[0]['items'])!=1):raise ValueError('caller envelope')
        caller=parents[0]['items'][0];known=[p for p in meta['caller_identities'] if p.get('Account')==account]
        if (len(known)!=1 or caller.get('Account')!=account or not isinstance(caller.get('Arn'),str)
                or caller['Arn']!=known[0].get('Arn') or caller.get('UserId')!=known[0].get('UserId')
                or not isinstance(caller.get('UserId'),str) or not 1<=len(caller['UserId'])<=256):raise ValueError('caller')
        ident=item['id'];m=item[MARKER]
        if (set(m)!={'schema','kind','identity','scope','account','region','partition','complete','verification','version','revision','variable_count','bytes','response_bytes','engines','leaks','capture','request'}
                or m['schema']!=SCHEMA or m['kind']!=KIND or m['identity']!=ident or m['scope']!=scope
                or m['account']!=account or m['region']!=region or m['complete'] is not True
                or m['verification']!='not_attempted' or m['version']!='$LATEST'
                or m['capture']!=meta[KIND+'_capture'] or not isinstance(m['capture'],str)
                or not re.fullmatch(r'lambda-environment-capture:[0-9a-f]{32}',m['capture'])
                or not isinstance(m['revision'],str) or not re.fullmatch(r'lambda-revision:[0-9a-f]{64}',m['revision'])
                or not re.fullmatch(r'arn:'+re.escape(m['partition'])+r':(?:iam|sts)::'+account+r':.+',caller['Arn'])
                or m['partition']!=('aws-cn' if region.startswith('cn-') else 'aws-us-gov' if region.startswith('us-gov-') else 'aws')
                or type(m['variable_count']) is not int or not 1<=m['variable_count']<=MAX_VARIABLES
                or type(m['bytes']) is not int or not 1<=m['bytes']<=MAX_ENV_BYTES
                or type(m['response_bytes']) is not int or not m['bytes']<=m['response_bytes']<=MAX_RESPONSE
                or item.get('AccountId')!=account or item.get('Region')!=region):raise ValueError('native marker')
        r=m['request']
        if (set(r)!={'locator','operation','method','scope','identity','status','http_status','native_request'}
                or r['operation']!='lambda:GetFunctionConfiguration' or r['method']!='GET'
                or r['scope']!=scope or r['identity']!=ident or r['status']!='collected'
                or type(r['http_status']) is not int or r['http_status']!=200
                or not isinstance(r['locator'],str) or not re.fullmatch(r'lambda-environment-request:[0-9a-f]{64}',r['locator'])
                or not isinstance(r['native_request'],str) or not re.fullmatch(r'lambda-response:[0-9a-f]{64}',r['native_request'])
                or item['_provenance']!={'scope':scope,'capture':m['capture'],'request_locator':r['locator']}):raise ValueError('read provenance')
        es=m['engines'];versions={'kingfisher':KINGFISHER_VERSION,'trufflehog':TRUFFLEHOG_VERSION}
        if (not isinstance(es,list) or len(es)!=2 or {e.get('engine') for e in es}!=set(versions)
                or any(set(e)!={'engine','version','status'} or e.get('version')!=versions.get(e.get('engine')) or e.get('status')!='complete' for e in es)):
            raise ValueError('engines')
        leaks=m['leaks']
        if (not isinstance(leaks,list) or merge_leaks(leaks)!=leaks or len(leaks)>MAX_LEAKS
                or sum(len(l['locations']) for l in leaks)>MAX_LOCATIONS
                or any(loc['path']!=ident+'.variables' for l in leaks for loc in l['locations'])):raise ValueError('leaks')
        observed=('A likely secret was detected in selected Lambda environment variables. The value is hidden; offline detection did not validate the credential.' if leaks else
            'Both offline detectors completed without detecting a supported secret in selected Lambda environment variables. Coverage is limited to the observed $LATEST literal configuration.')
        return ('FAIL' if leaks else 'PASS'),{'secret_leaks':deepcopy(leaks),'credential_validation':'not_attempted','complete':True,
            'coverage':'selected_observed_literal_environment_only','engines':deepcopy(es),'variable_count':m['variable_count'],
            'observed':observed}
    except (ValueError,TypeError,KeyError,IndexError,AttributeError,OverflowError):
        return 'UNKNOWN',{'observed':'Selected Lambda environment variables were disabled, unreadable, unsupported, incomplete or unbound. Secret absence could not be assessed.'}


def install():
    from pathlib import Path
    from . import CHECKS,register
    from .fixtures import CASES
    if any(c.id==CHECK for c in CHECKS):return
    d=DECLARATIONS[0]
    register(CHECK,'aws','hardening',KIND,d['title'],'high','security_configuration',d['remediation'],dependencies=['aws_account',KIND])(evaluate)
    CASES[CHECK]=json.loads(Path(__file__).with_name('aws_lambda_environment_secret_review_20261020_fixtures.json').read_text()).get(CHECK,{})
