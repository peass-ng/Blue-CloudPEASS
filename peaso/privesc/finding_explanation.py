"""Reviewed, exact-technique interpretations of recorded privilege-path findings.

This presents the model's source, targets and confidence. It never runs the
technique, expands its target set or promotes conditional access to achieved access.
"""
import json
from pathlib import Path
from functools import lru_cache

REVIEWED = json.loads(Path(__file__).with_suffix('.json').read_text())


def _text(value, maximum=500):
    return isinstance(value,str) and bool(value.strip()) and len(value)<=maximum and all(ord(c)>=32 for c in value)


@lru_cache(maxsize=1)
def _catalog_entries():
    from . import catalog
    return {entry['id']:entry for entry in catalog()['entries']}


def evidence_summary(finding):
    if not isinstance(finding,dict):return None
    cid,provider,e=finding.get('check_id'),finding.get('provider'),finding.get('evidence')
    if not isinstance(cid,str) or not isinstance(e,dict):return None
    if cid not in REVIEWED and cid!='admin-equivalent':return None
    if provider not in ('aws','gcp','azure','k8s'):return None
    technique,source,targets=e.get('technique'),e.get('source'),e.get('targets')
    if not isinstance(technique,dict) or technique.get('id')!=cid:return None
    if not isinstance(source,dict) or not _text(source.get('id')) or not _text(source.get('label')):return None
    if not isinstance(targets,list) or not targets or any(not isinstance(t,dict) or not _text(t.get('id')) for t in targets):return None
    count=e.get('target_count');confidence=e.get('confidence');status=finding.get('status')
    if type(count)is not int or count<0 or not isinstance(confidence,str):return None
    if count<len(targets) and not (confidence=='unknown' and count==0 and all(t.get('underlying_count')==0 for t in targets)):return None
    if {'derived':'FAIL','conditional':'MANUAL','unknown':'UNKNOWN'}.get(confidence)!=status:return None
    conditions=e.get('conditions',[]);blockers=e.get('blockers_not_evaluated',[])
    if not isinstance(conditions,list) or any(not _text(c) for c in conditions):return None
    if not isinstance(blockers,list) or any(not (_text(b) or isinstance(b,dict) and _text(b.get('id')) and _text(b.get('constraint'))) for b in blockers):return None
    if cid=='admin-equivalent':
        meaning={'derived':'These grants already represent administrative control; they do not show a new escalation or actual use.','conditional':'These grants may provide administrative control if their remaining conditions are satisfied.','unknown':'Missing evidence prevents confirming administrative control.'}[confidence]
    else:
        entry=_catalog_entries().get(cid)
        if not entry or entry['provider']!=provider or technique.get('source')!=entry['source']:return None
        meaning=REVIEWED[cid]['purpose']
    name=source['label']
    if count==0:
        target='unresolved targets'
    elif count==1 and len(targets)==1 and _text(targets[0].get('label')):
        target=targets[0]['label']
    else:
        target=f'{count} recorded targets'
    if confidence=='unknown':
        return _bounded_text(name,target,count,targets,meaning,' No operation was attempted.',unknown=True)
    if not e.get('granting_statements') and not e.get('granting_permissions'):return None
    if any(not isinstance(e.get(field,[]),list) for field in ('granting_statements','granting_permissions')):return None
    refs=e.get('granting_statements',[])+[p.get('grant',{}) for p in e.get('granting_permissions',[]) if isinstance(p,dict)]
    if any(isinstance(ref,dict) and ref.get('effect',ref.get('Effect','Allow'))!='Allow' for ref in refs):return None
    limit=' Conditions or guardrails remain; execution was not tested.' if conditions or blockers or confidence=='conditional' else ' Execution was not tested.'
    return _bounded_text(name,target,count,targets,meaning,limit,administrative=cid=='admin-equivalent' and confidence=='derived')


_TARGET_LABELS={
    'aws_role':'role','aws_user':'IAM user','aws_group':'IAM group','aws_account_admin':'account administrator',
    'gcp_service_account':'service account','gcp_scope_owner':'scope owner','gcp_credential_identity':'credential identity',
    'azure_identity':'Azure identity','azure_principal':'Azure principal','azure_scope_owner':'scope owner',
    'azure_role':'Azure role','k8s_serviceaccount':'service account','k8s_service_account':'service account',
    'k8s_cluster_admin':'cluster administrator','k8s_node':'node','k8s_user':'Kubernetes user',
}


def _bounded_text(name,target,count,targets,meaning,limit,*,unknown=False,administrative=False):
    def render(actor,destination):
        if unknown:
            return f'The scan lacks required facts for {actor}’s path to {destination}. '+meaning+limit
        if administrative:return f'{actor} has administrative grants covering {destination}. '+meaning+limit
        return f'The scan found a possible path from {actor} to {destination}. '+meaning+limit
    text=render(name,target)
    if len(text)<=240:return text
    # Use complete structural references instead of clipping an ARN, email or
    # aggregate label. Full identifiers remain in the unmodified raw evidence.
    kind=targets[0].get('type') if len(targets)==1 else None
    noun=_TARGET_LABELS.get(kind,'target')
    target='unresolved targets' if count==0 else f'{count} recorded '+(noun if count==1 else 'targets')
    text=render(name,target)
    if len(text)<=240:return text
    text=render('source identity',target)
    if len(text)<=240:return text
    prefix='The source path lacks required facts. ' if unknown else 'The source has a modeled privilege path. '
    return prefix+meaning+limit
