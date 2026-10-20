"""Brief observations of exact reviewed ConfigMap declarations, never node state."""
import json
from functools import lru_cache
from pathlib import Path

@lru_cache(maxsize=1)
def rules():
    return json.loads(Path(__file__).with_suffix('.json').read_text())

def observation(finding):
    if not isinstance(finding,dict) or finding.get('provider')!='k8s':return None
    row=rules().get(finding.get('check_id'));e=finding.get('evidence');status=finding.get('status')
    if row is None or not isinstance(e,dict):return None
    if status == 'UNKNOWN':
        copy=json.loads(Path(__file__).with_name('k8s_kubelet_declaration_unknown_observed_20261020.json').read_text())
        if set(e)=={'observed'} and e['observed']==copy['empty_native']:return copy['empty_brief']
        if (set(e)=={'observed','scope','raw_content_retained'}
                and e['observed']==copy['unknown_native']
                and e['scope']=='native_named_configmap_declaration_only' and e['raw_content_retained'] is False):
            return copy['unknown_brief']
        return None
    if status not in ('PASS','FAIL'):return None
    if (e.get('scope')!='native_named_configmap_declaration_only' or e.get('raw_content_retained') is not False
            or e.get('field')!=row['field'] or e.get('observed')!=row[status]):return None
    return row[status]
