"""Compare native assessment-definition severity with an explicit owner mapping."""
import re

ARM='https://management.azure.com'
KIND='assessment_metadata'
_NAME=re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}')
_SEVERITIES={'Low','Medium','High'}


def _policy(options,scope):
    from peaso.azure_sw32_policy import normalize_sw32
    outer=options.get('compliance_policy');raw=outer.get('sw32')if isinstance(outer,dict)else None
    try:return normalize_sw32(raw,expected_scope=scope)
    except ValueError:return None


def collect(reader,request,scopes,wanted,options):
    if KIND not in wanted:return
    from .azure import AzureReadError
    for scope in scopes:
        policy=_policy(options,scope)
        if policy is not None:reader.native_sw32_policy=policy
        def fetch(scope=scope):
            seen=set()
            for page in reader.pages(request,ARM+scope+'/providers/Microsoft.Security/assessmentMetadata?api-version=2020-01-01'):
                output=[]
                for item in page:
                    name=item.get('name');rid=item.get('id')
                    if not isinstance(name,str)or not _NAME.fullmatch(name)or name.casefold()in seen:
                        raise ValueError('invalid or duplicate assessment definition name')
                    allowed=('/providers/Microsoft.Security/assessmentMetadata/'+name,scope+'/providers/Microsoft.Security/assessmentMetadata/'+name)
                    if not isinstance(rid,str)or rid.casefold()not in {r.casefold()for r in allowed}:
                        raise ValueError('foreign assessment metadata identity')
                    seen.add(name.casefold())
                    if reader.budget.max_items is not None and len(seen)>reader.budget.max_items:raise AzureReadError('resource_limit')
                    props=item.get('properties')
                    if not isinstance(props,dict):raise ValueError('assessment metadata properties unavailable')
                    output.append({'id':rid,'name':name,'properties':{k:props[k]for k in('severity',)if k in props},
                        '_provenance':{'read_only':True,'source_operation':'assessmentMetadata.listBySubscription'}})
                yield output
        before=len(reader.collections);reader.run([(KIND,scope,'Microsoft.Security',fetch)])
        metadata=reader.collections[before:]
        if len(metadata)!=1 or metadata[0]['status']not in('collected','empty'):continue
        assessments=[c for c in reader.collections if c['type']=='security_assessment'and c['scope'].casefold()==scope.casefold()]
        if len(assessments)!=1 or assessments[0]['status']not in('collected','empty'):continue
        criteria=policy.get('vulnerability_severity_criteria')if policy else None
        if criteria is None:continue
        by_name={r['name']:r for r in metadata[0]['items']};active=[];valid=True
        for row in assessments[0]['items']:
            rid=row.get('id');name=row.get('name');props=row.get('properties')
            if (not isinstance(rid,str)or not rid.casefold().startswith(scope.casefold()+'/')
                or not isinstance(name,str)or not _NAME.fullmatch(name)
                or not rid.casefold().endswith('/providers/microsoft.security/assessments/'+name.casefold())
                or not isinstance(props,dict)or not isinstance(props.get('status'),dict)):
                valid=False;break
            state=props['status'].get('code')
            if state=='NotApplicable':continue
            meta=by_name.get(name)
            if state not in('Healthy','Unhealthy')or meta is None or not isinstance(meta['properties'].get('severity'),str)or meta['properties'].get('severity')not in _SEVERITIES or name not in criteria['expectedSeverityByAssessmentName']:
                valid=False;break
            active.append((row,meta))
        if not valid:continue
        reader.native_sw32_policy['vulnerability_severity_criteria']['finding_coverage_complete']=True
        for row,meta in active:
            row['severity_criteria_evidence']={'criteria_version':criteria['version'],
                'assigned_severity_matches_criteria':meta['properties']['severity']==criteria['expectedSeverityByAssessmentName'][row['name']],
                '_provenance':{'read_only':True,'source_operation':'assessmentMetadata.listBySubscription+ownerSeverityMapping.compare',
                    'semantics':'native assessment-definition severity compared with explicitly approved static definition mapping',
                    'assessment_id':row['id'],'metadata_id':meta['id']}}
