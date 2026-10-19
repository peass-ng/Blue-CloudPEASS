"""Refresh finding copy without rewriting an archived security assessment.

The presentation transform is pure. The caller supplies reviewed metadata and retains
all immutable report artifacts. Matching prose criteria permit copy refresh;
known evaluator corrections additionally require a source-bound fingerprint.
"""
from copy import deepcopy
import hashlib
import re
from functools import lru_cache
from pathlib import Path

VERSION='archived-finding-presentation-v1'
CRITERIA_FIELDS=('evaluated','pass_when','fail_when','not_applicable_when')
PRESENTATION_FIELDS=('description','rationale','remediation','remediation_details','evidence_summary','evidence_summary_format','guidance_refresh')
CORRECTED_CHECK_IDS=frozenset({
    'gcp.claude.kms_key.rotation_100_days',
    'gcp.claude.gke.binary_authorization',
    'gcp.claude.gke.release_channel',
    'gcp.ports.cloudfunction_function_no_ingress_settings_allow_all',
    'aws.cb.lightsail.ssh_rdp_http_world_closed',
    'aws.cb.lightsail.ssh_restricted',
    'aws.cb.lightsail.rdp_restricted',
    *('k8s.ports.'+kind+'.container_argument_kubelet_terminated_pod_gc_threshold_configured'
      for kind in ('cronjob','daemonset','deployment','job','pod','podtemplate','replicaset','replicationcontroller','statefulset')),
})
_HEX=re.compile(r'[0-9a-f]{64}\Z')


def criteria_contract(metadata):
    """Return exact stored criteria, respecting the report's None omission.

    The report encoder omits not_applicable_when=None. Three substantive fields
    must exist; no missing PASS/FAIL text is guessed from today's catalog.
    """
    if not isinstance(metadata,dict):return None
    evaluated=metadata.get('evaluated')
    if not isinstance(evaluated,list) or not evaluated or any(not isinstance(x,str) or not x.strip() for x in evaluated):return None
    if any(not isinstance(metadata.get(key),str) or not metadata[key].strip() for key in ('pass_when','fail_when')):return None
    applicability=metadata.get('not_applicable_when')
    if applicability is not None and (not isinstance(applicability,str) or not applicability.strip()):return None
    return {key:deepcopy(metadata.get(key)) for key in CRITERIA_FIELDS}


_CHECKS_ROOT=Path(__file__).resolve().parent/'checks'


@lru_cache(maxsize=1)
def evaluator_contract_fingerprint():
    """Conservatively bind all native check source bytes and relative paths.

    Cached once per process; production source is immutable. Any check-source
    change invalidates proof for a corrected historical evaluator. No runtime
    cache, cloud state, credentials or generated validation artifacts are read.
    """
    digest=hashlib.sha256()
    paths=sorted(_CHECKS_ROOT.glob('*.py'),key=lambda p:p.name)
    if not paths:
        raise ValueError('Native check source is unavailable for evaluation fingerprint')
    for path in paths:
        relative=path.relative_to(_CHECKS_ROOT).as_posix().encode()
        data=path.read_bytes()
        digest.update(len(relative).to_bytes(8,'big'));digest.update(relative)
        digest.update(len(data).to_bytes(8,'big'));digest.update(data)
    return digest.hexdigest()


def _approved_text(template):
    if not isinstance(template,dict) or template.get('review_status')!='approved':return None
    if not isinstance(template.get('summary'),str) or not template['summary'].strip():return None
    steps=template.get('steps')
    if not isinstance(steps,list) or not steps or any(not isinstance(x,str) or not x.strip() for x in steps):return None
    caveats=template.get('caveats',[])
    references=template.get('references',[])
    if not isinstance(caveats,list) or any(not isinstance(x,str) or not x.strip() for x in caveats):return None
    if not isinstance(references,list) or any(not isinstance(x,dict) or not isinstance(x.get('url'),str) or not x['url'].startswith(('https://','http://')) for x in references):return None
    return {key:deepcopy(template[key]) for key in ('review_status','summary','steps','caveats','references') if key in template}


def refresh_finding_presentation(finding,current_description,current_template,*,archived_template=None,
                                 archived_evaluator_contract=None,current_evaluator_contract=None):
    """Return (copied finding, allow_current_evidence_summary).

    Evidence, verdict, severity, identifiers and evaluation-version fields are
    never recomputed. A known correction cannot inherit today's explanation
    merely because generic historical criteria happened to remain unchanged.
    New live-catalog mutation commands are never added to archived results.
    """
    if not isinstance(finding,dict):raise TypeError('finding must be a dictionary')
    output=deepcopy(finding)
    archived=criteria_contract(finding);current=criteria_contract(current_description)
    status='current_text';reason='matching_archived_criteria'
    compatible=archived is not None and current is not None and archived==current
    if not compatible:
        status='historical_definition'
        reason='criteria_unavailable' if archived is None or current is None else 'criteria_changed'
    cid=finding.get('check_id')
    if compatible and cid in CORRECTED_CHECK_IDS:
        archived_proof=archived_evaluator_contract if archived_evaluator_contract is not None else finding.get('clarity_evaluation_contract')
        proven=(isinstance(archived_proof,str) and _HEX.fullmatch(archived_proof) is not None
                and isinstance(current_evaluator_contract,str) and _HEX.fullmatch(current_evaluator_contract) is not None
                and archived_proof==current_evaluator_contract)
        if not proven:
            compatible=False;status='historical_definition';reason='corrected_evaluator_unbound'
    marker={'version':VERSION,'status':status,'basis':reason,'allow_summary':bool(compatible)}
    if not compatible:
        marker['message']='This archived result uses an earlier or unverified check definition. Run a new assessment to apply the current definition.'
        output['guidance_refresh']=marker
        return output,False
    description=current_description.get('description')
    if isinstance(description,str) and description.strip():
        output['description']=description;output['rationale']=description
    text=_approved_text(current_template)
    if text is not None:
        existing=finding.get('remediation_details')
        if not isinstance(existing,dict):existing=archived_template
        details=deepcopy(existing) if isinstance(existing,dict) else {'cli':[]}
        details.update(text)
        output['remediation']=text['summary'];output['remediation_details']=details
    output['guidance_refresh']=marker
    return output,True
