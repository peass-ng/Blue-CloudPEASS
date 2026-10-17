"""DPS policy-compliance metadata, never DPS keys or encryption runtime proof."""
from __future__ import annotations
import copy
import hashlib
import json
import re
from datetime import datetime, timezone
from urllib.parse import urlencode

ARM='https://management.azure.com'
CHECK='azure.gap.iot_hub_encrypted_with_cmk'
NATIVE_TYPES={'iot_dps','azure_policy_state','azure_policy_assignment_evidence'}
PROVIDER_ACTIONS={'Microsoft.Devices/provisioningServices/read',
 'Microsoft.PolicyInsights/policyStates/queryResults/action',
 'Microsoft.Authorization/policyAssignments/read','Microsoft.Authorization/policyDefinitions/read',
 'Microsoft.Authorization/policyExemptions/read'}
_SEG=r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}'
_SUB=r'/subscriptions/[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}'
_DEF=re.compile(r'(?:/providers|'+_SUB+r'/providers)/Microsoft.Authorization/policyDefinitions/'+_SEG,re.I)


def normalize(options):
    container=options.get('compliance_parameters',{})
    if not isinstance(container,dict):raise ValueError('invalid compliance parameters')
    if 'azure_iot_policy'not in container:return None
    raw=container['azure_iot_policy']
    if (not isinstance(raw,dict)or set(raw)!={'scope','status','assignedDefinitionId','maxPolicyStateAge'}
        or not isinstance(raw['scope'],str)or not re.fullmatch(_SUB,raw['scope'],re.I)
        or raw['status']!='collected'or not isinstance(raw['assignedDefinitionId'],str)
        or not _DEF.fullmatch(raw['assignedDefinitionId'])or type(raw['maxPolicyStateAge'])is not int
        or not 0<raw['maxPolicyStateAge']<=86400):raise ValueError('invalid DPS owner policy')
    definition=raw['assignedDefinitionId']
    if definition.lower().startswith('/subscriptions/')and not definition.lower().startswith(raw['scope'].lower()+'/'):
        raise ValueError('foreign DPS policy definition')
    return copy.deepcopy(raw)


def owner_policy(options,scopes):
    policy=normalize(options)
    if policy and policy['scope'].casefold()in{s.casefold()for s in scopes}:
        return {CHECK:policy}
    return {}


def _id(value,scope,suffix):
    if not isinstance(value,str)or not re.fullmatch(re.escape(scope)+suffix,value,re.I):raise ValueError('foreign or malformed DPS evidence identity')
    return value


def _proof(operation):
    return {'read_only':True,'representation':'full','source_operation':operation}


def _instant(value):
    if not isinstance(value,str):raise ValueError('timestamp unavailable')
    t=datetime.fromisoformat(value.replace('Z','+00:00'))
    if t.utcoffset()is None:raise ValueError('timestamp timezone missing')
    return t.astimezone(timezone.utc)


def _pages(reader,request,url,*,next_key='nextLink'):
    seen=set();rows=[]
    for page in reader.pages(request,url,next_key=next_key):
        for row in page:
            if not isinstance(row,dict):raise ValueError('invalid native page member')
            # Full native page uniqueness is checked before Reader's identity dedup.
            fingerprint=json.dumps(row,sort_keys=True,separators=(',',':'))
            if fingerprint in seen:raise ValueError('duplicate native page member')
            seen.add(fingerprint);rows.append(row)
            if reader.budget.max_items is not None and len(rows)>reader.budget.max_items:
                from .azure import AzureReadError
                raise AzureReadError('resource_limit')
    return rows


def _bundle(reader,request,scope,policy,dps):
    from .azure import AzureReadError
    if not policy or policy['scope'].casefold()!=scope.casefold():raise AzureReadError('dps_owner_policy_missing')
    definition_id=policy['assignedDefinitionId']
    # Only this reviewed definition and DPS resources are queried; no triggerEvaluation.
    query=urlencode({'api-version':'2024-10-01','$filter':"(resourceType eq 'Microsoft.Devices/provisioningServices' or resourceType eq '/Microsoft.Devices/provisioningServices') and policyDefinitionId eq '"+definition_id+"'"})
    def post(url,*,body=None,audience=ARM):return request(url,body={},audience=audience)
    raw_states=_pages(reader,post,ARM+scope+'/providers/Microsoft.PolicyInsights/policyStates/latest/queryResults?'+query,next_key='@odata.nextLink')
    states=[];assignment_ids=set();state_keys=set()
    for raw in raw_states:
        if raw.get('subscriptionId',scope.rsplit('/',1)[-1]).casefold()!=scope.rsplit('/',1)[-1].casefold()or str(raw.get('resourceType','Microsoft.Devices/provisioningServices')).lstrip('/').casefold()!='microsoft.devices/provisioningservices':raise ValueError('foreign policy state subscription/type')
        rid=_id(raw.get('resourceId'),scope,r'/resourceGroups/'+_SEG+r'/providers/Microsoft.Devices/provisioningServices/'+_SEG)
        if rid.casefold()not in dps:raise ValueError('policy state belongs to uninventoried DPS')
        if str(raw.get('policyDefinitionId','')).casefold()!=definition_id.casefold():raise ValueError('foreign policy definition state')
        aid=_id(raw.get('policyAssignmentId'),scope,r'(?:/resourceGroups/'+_SEG+r')?/providers/Microsoft.Authorization/policyAssignments/'+_SEG)
        key=(rid.casefold(),aid.casefold(),raw.get('timestamp'))
        if key in state_keys:raise ValueError('duplicate policy state identity')
        state_keys.add(key);assignment_ids.add(aid)
        _instant(raw.get('timestamp'))
        state={k:copy.deepcopy(raw[k])for k in ('resourceId','policyDefinitionId','policyAssignmentId','timestamp','complianceState')if k in raw}
        state.update(id='dps-policy-state/'+hashlib.sha256(json.dumps(key).encode()).hexdigest(),scope_id=scope,_provenance=_proof('policyStates/latest/queryResults'))
        states.append(state)
    if not assignment_ids:return states,[]
    definition=reader.call(request,ARM+definition_id+'?api-version=2023-04-01')
    if not isinstance(definition,dict)or str(definition.get('id','')).casefold()!=definition_id.casefold()or str(definition.get('type','')).casefold()!='microsoft.authorization/policydefinitions':raise ValueError('foreign policy definition GET')
    dp=definition.get('properties',{});rule=dp.get('policyRule',{});effect=rule.get('then',{}).get('effect')
    definitions=dp.get('parameters',{})
    if not isinstance(definitions,dict)or set(definitions)-{'effect'}:raise AzureReadError('dps_definition_parameters_unsupported')
    if effect not in ('Audit','Deny','Disabled',"[parameters('effect')]"):raise AzureReadError('dps_effect_unsupported')
    if definitions:
        param=definitions['effect']
        if not isinstance(param,dict)or param.get('type')!='String':raise ValueError('DPS effect parameter type unresolved')
    # Subscription listing includes ancestor and child exemption scopes; none omitted by filter.
    exemptions=_pages(reader,request,ARM+scope+'/providers/Microsoft.Authorization/policyExemptions?api-version=2022-07-01-preview')
    now=datetime.now(timezone.utc);assignments=[];seen_exemptions=set()
    for aid in sorted(assignment_ids):
        raw=reader.call(request,ARM+aid+'?api-version=2023-04-01')
        if not isinstance(raw,dict)or str(raw.get('id','')).casefold()!=aid.casefold()or str(raw.get('type','')).casefold()!='microsoft.authorization/policyassignments':raise ValueError('foreign assignment GET')
        props=raw.get('properties',{})
        if not isinstance(props,dict)or str(props.get('policyDefinitionId','')).casefold()!=definition_id.casefold():raise ValueError('assignment definition mismatch')
        if any(props.get(k)not in(None,[])for k in('notScopes','resourceSelectors','overrides')):raise AzureReadError('dps_assignment_selectors_unsupported')
        assigned_scope=props.get('scope')
        _id(assigned_scope,scope,r'(?:/resourceGroups/'+_SEG+r')?')
        if aid.casefold()!=assigned_scope.casefold()+'/providers/microsoft.authorization/policyassignments/'+aid.rsplit('/',1)[-1].casefold():raise ValueError('assignment parent scope mismatch')
        parameters=props.get('parameters',{})
        if not isinstance(parameters,dict)or set(parameters)!=set(definitions):raise AzureReadError('dps_explicit_effect_parameters_required')
        for name,value in parameters.items():
            if not isinstance(value,dict)or set(value)!={'value'}or value['value']not in('Audit','Deny','Disabled'):raise ValueError('effect parameter malformed')
            allowed=definitions[name].get('allowedValues')
            if allowed is not None and(not isinstance(allowed,list)or value['value']not in allowed):raise ValueError('effect parameter violates definition')
        resolved=parameters['effect']['value']if effect=="[parameters('effect')]"else effect
        if 'effect'in parameters and parameters['effect']['value']!=resolved:raise ValueError('assignment effect conflicts with definition')
        for observed in raw_states:
            if str(observed.get('policyAssignmentId','')).casefold()!=aid.casefold():continue
            if 'policyAssignmentScope'in observed and str(observed['policyAssignmentScope']).casefold()!=assigned_scope.casefold():raise ValueError('policy state assignment scope changed')
            if 'policyDefinitionAction'in observed and str(observed['policyDefinitionAction']).casefold()!=resolved.casefold():raise ValueError('policy state effect changed')
            if 'policyAssignmentParameters'in observed:
                prior=observed['policyAssignmentParameters']
                if isinstance(prior,str):prior=json.loads(prior)
                if prior!=parameters:raise ValueError('policy state assignment parameters changed')
            if 'policyDefinitionVersion'in observed and observed['policyDefinitionVersion']!=dp.get('version'):raise ValueError('policy state definition version changed')
            for authority in(raw,definition):
                system=authority.get('systemData',{})
                if not isinstance(system,dict):raise ValueError('native authority timestamps malformed')
                changed=system.get('lastModifiedAt')
                if changed is not None and _instant(changed)>_instant(observed['timestamp']):raise ValueError('policy state predates current authority')
        projected=[]
        for exemption in exemptions:
            ep=exemption.get('properties',{})
            if not isinstance(ep,dict)or not isinstance(ep.get('policyAssignmentId'),str):raise ValueError('exemption assignment unavailable')
            if ep['policyAssignmentId'].casefold()!=aid.casefold():continue
            if str(exemption.get('type','')).casefold()!='microsoft.authorization/policyexemptions':raise ValueError('exemption native type mismatch')
            eid=exemption.get('id');marker='/providers/microsoft.authorization/policyexemptions/'
            if not isinstance(eid,str)or marker not in eid.casefold():raise ValueError('exemption identity malformed')
            source=eid[:eid.casefold().rfind(marker)]
            _id(source,scope,r'(?:/resourceGroups/'+_SEG+r'(?:/providers/'+_SEG+r'/'+_SEG+r'/'+_SEG+r')?)?')
            _id(eid,source,r'/providers/Microsoft.Authorization/policyExemptions/'+_SEG)
            if eid.casefold()in seen_exemptions:raise ValueError('duplicate native exemption')
            seen_exemptions.add(eid.casefold())
            if ep.get('policyDefinitionReferenceIds')not in(None,[])or ep.get('resourceSelectors')not in(None,[]):raise AzureReadError('dps_exemption_selectors_unsupported')
            if ep.get('exemptionCategory')not in('Waiver','Mitigated'):raise ValueError('exemption category unresolved')
            expires=ep.get('expiresOn');active=expires is None or _instant(expires)>now
            # Native exemption scope is subscription/RG/resource. Project an exact
            # applicability join to each real inventoried DPS it contains; never
            # relabel the exemption scope itself as a DPS resource identity.
            for target in sorted(dps):
                if target==source.casefold()or target.startswith(source.casefold().rstrip('/')+'/'):
                    projected.append({'id':eid,'resourceId':target,'policyAssignmentId':aid,'active':active,
                                      '_provenance':{**_proof('policyExemptions:LIST'),'native_exemption_scope':source,'applicability_basis':'exact native ancestor-scope to inventoried DPS join'}})
        mode=props.get('enforcementMode')
        if mode not in('Default','DoNotEnforce'):raise ValueError('enforcement mode unavailable')
        definition_fact={'id':definition_id,'properties':{'policyRule':{'then':{'effect':effect}}},'_provenance':_proof('policyDefinitions:GET')}
        assignment={'id':aid,'properties':{'policyDefinitionId':props['policyDefinitionId'],'scope':assigned_scope,'enforcementMode':mode,'parameters':copy.deepcopy(parameters)},'effectiveEffect':resolved,'effectiveParameters':copy.deepcopy(parameters),'parametersVerified':True,'definition':definition_fact,'active':True,'exemptions':projected,'_coverage':{'exemptions':{'status':'collected'if projected else'empty'}},'_provenance':{**_proof('policyAssignments:GET'),'active_basis':'current successful native GET; no lifecycle or runtime claim'}}
        assignments.append(assignment)
    return states,assignments


def collect(reader,request,scopes,wanted,options):
    if not NATIVE_TYPES.intersection(wanted):return
    policy=normalize(options)
    derived=set(wanted)&{'azure_policy_state','azure_policy_assignment_evidence'}
    for scope in scopes:
        def inventory(scope=scope):
            seen=set()
            for raw in _pages(reader,request,ARM+scope+'/providers/Microsoft.Devices/provisioningServices?api-version=2022-12-12'):
                rid=_id(raw.get('id'),scope,r'/resourceGroups/'+_SEG+r'/providers/Microsoft.Devices/provisioningServices/'+_SEG)
                if raw.get('type','').casefold()!='microsoft.devices/provisioningservices'or rid.casefold()in seen:raise ValueError('DPS type or identity conflict')
                seen.add(rid.casefold())
                yield [{'id':rid,'name':raw.get('name'),'type':raw['type'],'_provenance':_proof('provisioningServices:LIST')}]
        reader.run([('iot_dps',scope,'Microsoft.Devices',inventory)])
        if not derived:continue
        parent=next(c for c in reversed(reader.collections)if c['type']=='iot_dps'and c['scope']==scope)
        try:
            if parent['status']not in('collected','empty'):
                from .azure import AzureReadError
                raise AzureReadError('dps_inventory_incomplete')
            state,assignment=_bundle(reader,request,scope,policy,{r['id'].casefold()for r in parent['items']})if parent['items']else([],[])
            for kind,rows in(('azure_policy_state',state),('azure_policy_assignment_evidence',assignment)):
                if kind not in derived:continue
                reader.run([(kind,scope,'Microsoft.PolicyInsights'if kind=='azure_policy_state'else'Microsoft.Authorization',lambda rows=rows:iter([rows]))])
        except Exception as exc:
            for kind in sorted(derived):reader.unavailable(kind,scope,'Microsoft.PolicyInsights',exc)
