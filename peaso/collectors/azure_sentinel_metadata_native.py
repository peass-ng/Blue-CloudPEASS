"""Sentinel onboarding and incident metadata; never attest response procedures."""
import re

ARM='https://management.azure.com'
KIND='sentinel_workspace'
VERSION='2025-09-01'
_WORKSPACE=re.compile(r'/subscriptions/[0-9a-f-]{36}/resourceGroups/[^/?#%\s]+/providers/Microsoft\.OperationalInsights/workspaces/[^/?#%\s]+',re.I)


def collect(reader,request,scopes,wanted):
    if KIND not in wanted:return
    from .azure import AzureReadError
    for scope in scopes:
        def fetch(scope=scope):
            seen=set()
            def workspaces():
                cached=[c for c in reader.collections if c['type']=='log_analytics_workspace'and c['scope'].casefold()==scope.casefold()]
                if cached:
                    if len(cached)!=1 or cached[0]['status']not in('collected','empty'):
                        raise AzureReadError('sentinel_workspace_universe_unavailable')
                    yield cached[0]['items']
                else:
                    yield from reader.pages(request,ARM+scope+'/providers/Microsoft.OperationalInsights/workspaces?api-version=2023-09-01')
            def children(parent,tail):
                path=parent+'/providers/Microsoft.SecurityInsights/'+tail;ids=set()
                for page in reader.pages(request,ARM+path+'?api-version='+VERSION):
                    for item in page:
                        rid=item.get('id')
                        if (not isinstance(rid,str)or not rid.casefold().startswith(path.casefold()+'/')
                            or not rid[len(path)+1:]or '/'in rid[len(path)+1:]or any(c in rid for c in '?#%')or rid.rsplit('/',1)[-1]in('.','..')or rid.casefold()in ids):
                            raise ValueError('invalid or duplicate Sentinel native child identity')
                        ids.add(rid.casefold())
                        if reader.budget.max_items is not None and len(ids)>reader.budget.max_items:raise AzureReadError('resource_limit')
                        yield item
            for page in workspaces():
                for workspace in page:
                    rid=workspace.get('id')
                    if not isinstance(rid,str)or not _WORKSPACE.fullmatch(rid)or not rid.casefold().startswith(scope.casefold()+'/')or rid.casefold()in seen:
                        raise ValueError('invalid or duplicate Sentinel workspace scope')
                    seen.add(rid.casefold())
                    if reader.budget.max_items is not None and len(seen)>reader.budget.max_items:raise AzureReadError('resource_limit')
                    onboarding=list(children(rid,'onboardingStates'))
                    if not onboarding:continue
                    if len(onboarding)!=1 or onboarding[0]['id'].rsplit('/',1)[-1].casefold()!='default':
                        raise ValueError('Sentinel default onboarding identity unavailable')
                    incidents=[];incident_state='collected';incident_error=None
                    try:
                        for item in children(rid,'incidents'):
                            props=item.get('properties')
                            if not isinstance(props,dict):raise ValueError('Sentinel incident metadata missing')
                            if 'type' in item and (not isinstance(item['type'],str) or item['type'].casefold()!='microsoft.securityinsights/incidents'):
                                raise ValueError('Sentinel incident native type contradicts URI')
                            # Free-form titles/descriptions/labels, users, entities,
                            # incident URLs, evidence payloads and comments omitted.
                            incidents.append({'id':item['id'],'type':'Microsoft.SecurityInsights/incidents','properties':{k:props[k]for k in('status','classification','classificationReason','severity','createdTimeUtc','lastModifiedTimeUtc')if k in props},
                                '_provenance':{'read_only':True,'source_operation':'securityinsights.incidents.list',
                                    'api_version':VERSION,'workspace_id':rid,
                                    'type_source':'native_field' if 'type' in item else 'validated_incidents_list_uri'}})
                    except Exception as exc:
                        if not incidents:raise
                        from .azure import _safe_error
                        incident_state='partial';incident_error=_safe_error(exc)[1]
                    yield [{'id':rid,'incidents':incidents,'_coverage':{'incidents':{'status':incident_state if incidents else'empty',**({'error':incident_error}if incident_error else{})}},
                        '_provenance':{'read_only':True,'source_operation':'workspaces.list+securityinsights.onboardingStates.list+securityinsights.incidents.list',
                            'onboarding_id':onboarding[0]['id'],'process_evidence':'not_collected'}}]
        reader.run([(KIND,scope,'Microsoft.SecurityInsights',fetch)])
