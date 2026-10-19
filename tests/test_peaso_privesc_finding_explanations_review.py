"""All technique contracts use reviewed, bounded prose without changing verdicts."""
from copy import deepcopy
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from peaso.privesc import catalog, analyze
from peaso.privesc.graph import GraphBuilder
from peaso.privesc.effective_permissions import Grant, Node
from peaso.privesc.finding_explanation import REVIEWED, evidence_summary

ENTRIES=catalog()['entries']
ROOT=Path(__file__).resolve().parents[1]


def projected(entry,confidence='derived'):
    source=Node('source-id','user',entry['provider'],'scope','alice')
    target={'id':'target-id','label':'reviewed-target','type':entry['target']['kind'],'kind':'principal','scope':'scope','underlying_count':0 if confidence=='unknown' else 1}
    grant=Grant(confidence,[{'policy':'reviewed-policy','statement':0,'effect':'Allow'}],
                ['runtime_condition_not_evaluated'] if confidence=='conditional' else ['target_inventory_missing'] if confidence=='unknown' else [])
    return GraphBuilder(SimpleNamespace(provider=entry['provider']))._finding(
        'finding',entry['id'],entry['title'],source,entry['service'],entry['severity'],'',grant,[target],
        0 if confidence=='unknown' else 1,entry,entry.get('blockers',[]),edge_ids=['edge-id'])


def test_browser_line_measurement_fixture_matches_current_projectors():
    rows=[]
    for entry in ENTRIES:
        for confidence in ['derived','conditional','unknown']:
            finding=projected(entry,confidence)
            rows.append(dict(id=entry['id'],provider=entry['provider'],status=finding['status'],summary=evidence_summary(finding)))
    for row in json.loads((ROOT/'docs/evidence-reviews/analysis.json').read_text())['checks'].values():
        for example in row['examples']:
            rows.append(dict(id=row['check_id'],provider=row['provider'],status=example['status'],summary=example['example']))
    assert json.loads((ROOT/'tests/fixtures/shared_evidence_review.json').read_text())==rows


def test_every_catalog_technique_and_generated_admin_check_has_review_ledger():
    ledger=json.loads((ROOT/'docs/evidence-reviews/privesc.json').read_text())
    assert len(ENTRIES)==633
    assert set(REVIEWED)=={e['id'] for e in ENTRIES}
    assert set(ledger['checks'])==set(REVIEWED)|{'admin-equivalent'}
    assert ledger['by_provider']=={'aws':165,'gcp':238,'azure':158,'k8s':72}
    for entry in ENTRIES:
        row=ledger['checks'][entry['id']]
        assert row['conditions_retained']==[c['id'] for c in entry.get('conditions',[])]
        assert row['blockers_retained']==entry.get('blockers',[])
        assert row['target_kind']==entry['target']['kind']
        assert row['review_status']=='source_reviewed'


@pytest.mark.parametrize('entry',ENTRIES,ids=lambda e:e['id'])
@pytest.mark.parametrize('confidence',['derived','conditional','unknown'])
def test_every_technique_status_has_brief_source_bound_explanation(entry,confidence):
    finding=projected(entry,confidence);before=deepcopy(finding)
    text=evidence_summary(finding)
    assert text and 'alice' in text and REVIEWED[entry['id']]['purpose'] in text
    assert len(text)<=240,text
    assert 'execution was not tested' in text.lower() or 'No operation was attempted' in text
    if confidence=='unknown':assert 'required facts' in text.lower()
    if entry.get('blockers') and confidence!='unknown':assert 'guardrails remain' in text
    assert finding==before


@pytest.mark.parametrize('change',[
    lambda f:f.update(provider='other'),
    lambda f:f['evidence']['technique'].update(id='different-id'),
    lambda f:f['evidence']['technique'].update(source='wrong-source'),
    lambda f:f['evidence'].update(source={}),
    lambda f:f['evidence'].update(targets=[]),
    lambda f:f['evidence'].update(target_count=True),
    lambda f:f['evidence'].update(target_count=0),
    lambda f:f['evidence'].update(granting_statements=[],granting_permissions=[]),
    lambda f:f['evidence']['granting_statements'][0].update(effect='Deny'),
    lambda f:f['evidence'].update(conditions=[False]),
    lambda f:f['evidence'].update(confidence='derived') or f.update(status='UNKNOWN'),
])
def test_false_malformed_or_mismatched_projection_cannot_create_a_path_claim(change):
    finding=projected(ENTRIES[0]);change(finding)
    assert evidence_summary(finding)is None


def test_aggregate_targets_are_counted_without_dumping_or_truncating_identifiers():
    finding=projected(ENTRIES[0]);finding['evidence']['target_count']=42
    finding['evidence']['targets']=[{'id':'aggregate-id','label':'recorded target aggregate','kind':'aggregate'}]
    assert '42 recorded targets' in evidence_summary(finding)


@pytest.mark.parametrize('provider',['aws','gcp','azure','k8s'])
def test_real_native_snapshot_paths_preserve_conditions_and_source_identity(provider):
    # Reuse native integration producers, rather than mirroring permission evaluation.
    from test_peaso_privesc_integration import privesc_snapshot
    from test_peaso_privesc import gcp_snapshot,gcp_sa,SA1,k8s_snapshot,azure_snapshot,WRITER_ROLE,SUB
    if provider=='aws':snapshot=privesc_snapshot()
    elif provider=='gcp':snapshot=gcp_snapshot([{'role':'roles/iam.serviceAccountTokenCreator','members':['user:alice@example.com']}],[gcp_sa(SA1)])
    elif provider=='azure':snapshot=azure_snapshot([('u-alice',SUB,WRITER_ROLE)])
    else:snapshot=k8s_snapshot()
    result=analyze(snapshot,include_unknown=True)
    assert result['findings'],provider
    for finding in result['findings']:
        original=deepcopy(finding);text=evidence_summary(finding)
        assert text,(provider,finding)
        assert finding['evidence']['source']['label'] in text
        assert finding==original


@pytest.mark.parametrize('confidence',['derived','conditional','unknown'])
def test_long_complete_identity_labels_use_structural_references_without_clipping(confidence):
    finding=projected(next(e for e in ENTRIES if e['id']=='gcp-gkehub-memberships-setiampolicy-membership-self-grant'),confidence)
    source='source-'+('a'*450)
    target='arn:aws:iam::111111111111:role/'+('b'*450)
    finding['evidence']['source']['label']=source
    finding['evidence']['targets'][0]['label']=target
    before=deepcopy(finding)
    text=evidence_summary(finding)
    assert len(text)<=240
    assert 'source' in text
    assert source not in text and target not in text
    assert '...' not in text and '…' not in text
    assert finding==before
