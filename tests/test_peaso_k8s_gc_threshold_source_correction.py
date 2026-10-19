"""Nine exact historical IDs now bind the GC flag to its real component."""
from copy import deepcopy
import hashlib
import inspect
import json
from pathlib import Path
import pytest
from peaso.checks import CHECKS
from peaso.checks.fixtures import CASES, nest
from peaso.checks.facts import get
from peaso.checks.k8s_ports_components import SPECS
from peaso.checks.k8s_ports_workloads import KIND_PATHS
from peaso.checks.k8s_gc_threshold_source_correction import ROWS, CURRENT_SPEC, PRIOR_SPEC, _digest, description, remediation

PACK = Path(__file__).resolve().parents[1] / 'peaso/rulepacks'


@pytest.fixture(scope='module')
def original_sources():
    descriptions = json.loads((PACK/'check_descriptions.json').read_text())['checks']
    templates = {}
    for path in PACK.glob('remediation*.json'):
        values = json.loads(path.read_text())
        if not isinstance(values, dict):
            continue
        for cid, value in values.items():
            if cid in ROWS and _digest(value) == ROWS[cid]['remediation_base_sha256']:
                templates[cid] = value
    return descriptions, templates


def test_exact_nine_stable_ids_and_corrected_spec():
    assert len(ROWS) == 9
    assert SPECS['container_argument_kubelet_terminated_pod_gc_threshold_configured'] == CURRENT_SPEC
    assert PRIOR_SPEC[0] == 'kubelet' and CURRENT_SPEC[0] == 'kube-controller-manager'
    assert CURRENT_SPEC[1:] == PRIOR_SPEC[1:]


@pytest.mark.parametrize('cid', sorted(ROWS))
def test_manager_threshold_values_and_kubelet_exclusion(cid):
    check = next(c for c in CHECKS if c.id == cid)
    binding = inspect.getclosurevars(inspect.unwrap(check.evaluate)).nonlocals
    assert binding['kind'] == check.kind and binding['spec'] == CURRENT_SPEC
    for value, expected in [('1','PASS'),('12500','PASS'),('0','FAIL'),('-1','UNKNOWN'),('bad','UNKNOWN')]:
        item = deepcopy(CASES[cid]['pass'])
        config = get(item, KIND_PATHS[check.kind], dict)['containers'][0]['_component_config']
        config['flags']['terminated-pod-gc-threshold'] = value
        assert check.evaluate(item,{})[0] == expected
    config['component'] = 'kubelet'
    assert check.evaluate(item,{})[0] == 'NOT_APPLICABLE'
    config['component'] = 'kube-controller-manager'
    config['flags'].clear()
    assert check.evaluate(item,{})[0] == 'UNKNOWN'


@pytest.mark.parametrize('cid', sorted(ROWS))
def test_raw_read_only_projection_identifies_manager(cid):
    from peaso.collectors.k8s import _native
    check = next(c for c in CHECKS if c.id == cid)
    raw = nest(KIND_PATHS[check.kind], {'containers':[{'name':'manager','command':['kube-controller-manager','--terminated-pod-gc-threshold=0']}]})
    raw['metadata']={'name':'manager','namespace':'apps'}
    projected = _native(raw, check.kind, 'fixture', '*', True)
    assert check.evaluate(projected,{})[0] == 'FAIL'
    assert 'kube-controller-manager' in check.title


@pytest.mark.parametrize('cid', sorted(ROWS))
def test_historical_metadata_preserved_and_erratum_explicit(cid, original_sources):
    old = original_sources[0][cid]
    new = description(cid, old)
    assert old['evaluated'] == new['evaluated']
    assert new['source_correction']['status']=='source_erratum_successor'
    assert new['source_correction']['prior_description_sha256']==_digest(old)
    assert new['source_correction']['upstream_sql_sha256']
    assert new['source_correction']['upstream_source_url'].startswith('https://github.com/turbot/')
    assert 'kube-controller-manager' in new['description'] and 'zero' in new['fail_when']
    original = original_sources[1][cid]
    rem = remediation(cid, original)
    assert rem['cli']==[] and not rem.get('iac')
    assert rem['field_binding']['component']==['kube-controller-manager']
    assert rem['references'][0]['url'].endswith('/kube-controller-manager/')
    assert '12500 already enables' in rem['caveats'][0]
    for apply, baseline in [(description, old),(remediation,original)]:
        altered=deepcopy(baseline);altered['unexpected_change']=True
        with pytest.raises(ValueError,match='source base changed'):
            apply(cid,altered)


def test_immutable_upstream_bug_receipt_distinguishes_three_copy_paste_queries():
    for cid,row in ROWS.items():
        source = row['provenance']
        assert source['immutable_upstream_commit']=='0c3811217525256c41d97ea0d67312f420bd814a'
        assert source['immutable_upstream_commit'] in source['immutable_upstream_query_url']
        assert len(source['upstream_query_block_sha256'])==64
        assert 'not literal upstream SQL parity' in source['source_relationship']
        if cid.split('.')[2] in {'cronjob','daemonset','podtemplate'}:
            assert source['upstream_inspected_flag']=='read-only-port'
            assert source['additional_upstream_erratum']
        else:
            assert source['upstream_inspected_flag']=='terminated-pod-gc-threshold'


@pytest.mark.parametrize('cid', sorted(ROWS))
def test_corrected_observed_evidence_and_guarded_risk(cid):
    from peaso.checks.k8s_gc_threshold_source_correction import evidence_summary,severity_review
    check=next(c for c in CHECKS if c.id==cid)
    status,evidence=check.evaluate(deepcopy(CASES[cid]['fail']),{})
    finding={'provider':'k8s','check_id':cid,'status':status,'evidence':evidence}
    assert 'threshold 0' in evidence_summary(finding)
    assert severity_review(cid,check.severity)=='medium'
    finding['status']='UNKNOWN'
    assert evidence_summary(finding) is None
