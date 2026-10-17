"""Two private signed Graph credential-age checks using one paged metadata projection."""
from __future__ import annotations
from datetime import datetime, timedelta, timezone
from uuid import UUID
import re

from peaso.checks import register, result, unknown
from peaso.checks.facts import Unavailable, complete_items, get, list_of_objects, memoized

APPLICATION = 'azure.other.entra_app_secret_age_90'
PRINCIPAL = 'azure_directory_user_keyvault_rbac_secret_expiration_set_e2e0e28'
SPEC_SHA256 = {APPLICATION: '09a61ffbd9501a64ab497315966c42954f81de35348edff65bfca0cb4da824fd',
               PRINCIPAL: '6e2e97377d3b2e17d530b469e2c36880945e3455e0a8b3c74781f323552e4c3c'}


def _guid(value):
    if not isinstance(value, str):
        raise Unavailable('missing Graph GUID')
    try:
        guid = UUID(value)
    except ValueError as exc:
        raise Unavailable('malformed Graph GUID') from exc
    if str(guid) != value.casefold() or guid.int == 0:
        raise Unavailable('noncanonical or nil Graph GUID')
    return value.casefold()


def _time(value):
    if not isinstance(value, str):
        raise Unavailable('missing credential timestamp')
    try:
        stamp = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError as exc:
        raise Unavailable('malformed credential timestamp') from exc
    if stamp.tzinfo is None:
        raise Unavailable('credential timestamp lacks timezone')
    return stamp.astimezone(timezone.utc)


def _authority(index):
    ctx = get(index, 'context', dict)
    if get(ctx, 'provider', str) != 'azure':
        raise Unavailable('foreign provider')
    scope = get(ctx, 'scope', str).casefold()
    if not re.fullmatch(r'/tenants/[0-9a-f-]{36}', scope):
        raise Unavailable('verified tenant scope unavailable')
    tenant = _guid(scope.split('/')[-1])
    meta = get(ctx, 'metadata', dict)
    if _guid(get(meta, 'tenant_id', str)) != tenant or get(meta, 'tenant_verified', bool) is not True:
        raise Unavailable('tenant authority unavailable')
    now = _time(get(ctx, 'created_at', str))
    if now > datetime.now(timezone.utc) + timedelta(minutes=5):
        raise Unavailable('snapshot clock ahead of evaluator')
    return scope, tenant, meta, now


def _rows(index, kind):
    scope, tenant, meta, now = _authority(index)
    def build():
        envelopes = get(index, 'collections', dict).get(kind)
        if not isinstance(envelopes, list) or len(envelopes) != 1:
            raise Unavailable('missing or ambiguous Graph inventory: ' + kind)
        env = envelopes[0]
        if not isinstance(env,dict): raise Unavailable('malformed Graph inventory envelope')
        if env.get('type') != kind or env.get('service') != 'Microsoft.Graph' or str(env.get('scope', '')).casefold() != scope or env.get('status') not in ('collected','empty'):
            raise Unavailable('incomplete or foreign Graph inventory: ' + kind)
        proof = get(env, '_provenance', dict)
        if (_guid(get(proof, 'tenant_id', str)) != tenant or proof.get('tenant_verified') is not True or
            proof.get('credential_context_id') != meta.get('credential_context_id') or
            proof.get('customer_context_id') != meta.get('customer_context_id')):
            raise Unavailable('Graph envelope capture binding unavailable')
        rows = list_of_objects(get(env, 'items', list))
        if (env['status']=='empty') != (not rows) or sorted(rows,key=lambda r:r.get('id','')) != sorted(complete_items(index, kind),key=lambda r:r.get('id','')):
            raise Unavailable('Graph inventory/projection contradiction')
        seen=set()
        for row in rows:
            if kind in ('application_scope','service_principal_scope'):
                if row.get('id','').casefold() != scope+('/applicationscope' if kind=='application_scope' else '/serviceprincipalscope') or row.get('parent_scope','').casefold()!=scope:
                    raise Unavailable('foreign application aggregate')
            else:
                rid=_guid(get(row,'id',str))
                if rid in seen: raise Unavailable('duplicate Graph identity')
                seen.add(rid)
            rp=get(row,'_provenance',dict)
            if (_guid(get(rp,'tenant_id',str))!=tenant or rp.get('tenant_verified') is not True or
                rp.get('credential_context_id')!=meta.get('credential_context_id') or
                rp.get('customer_context_id')!=meta.get('customer_context_id')):
                raise Unavailable('Graph row capture binding unavailable')
            if kind not in ('application_scope','service_principal_scope') and (rp.get('endpoint') != ('/v1.0/applications' if kind=='directory_application' else '/v1.0/servicePrincipals') or rp.get('read_only') is not True):
                raise Unavailable('Graph source endpoint unresolved')
        return rows
    return memoized(index, ('azure_graph_age',kind,scope),build), now, meta


def _credential_outcome(row, now, max_days, inclusive, *, limit=None):
    if limit is None:
        try:
            limit = timedelta(days=max_days)
        except OverflowError as exc:
            raise Unavailable('unrepresentable maxCredentialAgeDays') from exc
    aged=[]; uncertain=False; active=0
    for field in ('passwordCredentials','keyCredentials'):
        try: credentials=list_of_objects(get(row,field,list))
        except Unavailable:
            uncertain=True;continue
        seen=set()
        for cred in credentials:
            try:
                key=_guid(get(cred,'keyId',str))
                if key in seen: raise Unavailable('duplicate credential identity')
                seen.add(key)
                start=_time(get(cred,'startDateTime',str));end=_time(get(cred,'endDateTime',str))
                if start>=end: raise Unavailable('invalid credential lifetime')
                if start<=now<end:
                    active+=1
                    if (now - start) >= limit if inclusive else (now - start) > limit:
                        aged.append({'principal_id':row['id'],'key_id':key})
            except Unavailable:
                uncertain=True
    return aged,uncertain,active


@register(APPLICATION,'azure','hardening','application_scope','Active application credentials are younger than 90 days','high','CCC.IAM.CN06.AR01',
          'Rotate active application credentials before their 90-day age threshold.',dependencies=('application_scope','directory_application'))
def application_age(item,index):
    subjects,now,_=_rows(index,'application_scope')
    if len(subjects)!=1 or subjects[0]!=item: raise Unavailable('application aggregate absent or ambiguous')
    rows,_,_=_rows(index,'directory_application')
    if get(item,'member_count',int)!=len(rows): raise Unavailable('aggregate and application inventory disagree')
    proof=get(item,'_provenance',dict)
    if proof.get('source_collection')!='directory_application' or proof.get('read_only') is not True:
        raise Unavailable('application aggregate source unresolved')
    all_aged=[];uncertain=False;active=0
    for row in rows:
        aged,missing,count=_credential_outcome(row,now,90,True)
        all_aged.extend(aged);uncertain|=missing;active+=count
    if all_aged:return result(True,aged_active_credentials=all_aged)
    if uncertain:return unknown('credential active state or date unresolved')
    return result(False,application_count=len(rows),active_credential_count=active)


@register(PRINCIPAL,'azure','hardening','service_principal_scope','Active service principal credentials are within required age','high','CCC.IAM.CN06.AR01',
          'Rotate service-principal password and key credentials within the configured age.',dependencies=('service_principal_scope','directory_service_principal'))
def principal_age(item,index):
    subjects,now,meta=_rows(index,'service_principal_scope')
    if len(subjects)!=1 or subjects[0]!=item: raise Unavailable('service-principal aggregate absent or ambiguous')
    rows,_,_=_rows(index,'directory_service_principal')
    if get(item,'member_count',int)!=len(rows): raise Unavailable('aggregate and principal inventory disagree')
    proof=get(item,'_provenance',dict)
    if proof.get('source_collection')!='directory_service_principal' or proof.get('read_only') is not True:
        raise Unavailable('principal aggregate source unresolved')
    params=meta.get('parameters',{})
    if not isinstance(params,dict): raise Unavailable('malformed credential-age parameters')
    max_days=params.get('maxCredentialAgeDays',90)
    if type(max_days) is not int or max_days<=0: raise Unavailable('invalid maxCredentialAgeDays')
    try:
        limit = timedelta(days=max_days)
    except OverflowError as exc:
        raise Unavailable('unrepresentable maxCredentialAgeDays') from exc
    all_aged=[]; uncertain=False; active=0
    for row in rows:
        aged,missing,count=_credential_outcome(row,now,max_days,False,limit=limit)
        all_aged.extend(aged); uncertain |= missing; active += count
    if all_aged:return result(True,old_active_credentials=all_aged,maxCredentialAgeDays=max_days)
    if uncertain:return unknown('credential active state or date unresolved')
    return result(False,principal_count=len(rows),active_credential_count=active,maxCredentialAgeDays=max_days)
