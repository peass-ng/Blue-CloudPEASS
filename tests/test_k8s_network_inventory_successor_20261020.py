"""Standalone proposal tests; no package init, hooks, cloud or filesystem spoof."""
from copy import deepcopy
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / 'peaso/checks/k8s_network_inventory_successor_20261020.py'
spec = importlib.util.spec_from_file_location('_network_successor_proposal_test', PATH)
proposal = importlib.util.module_from_spec(spec)
spec.loader.exec_module(proposal)
from tests.aws_k8s_current_native_inputs_20261020 import network_test_successor
proposal = network_test_successor(proposal)


def inputs():
    reviewed = proposal.receipt(ROOT)
    old = proposal.exact_old_json(ROOT, reviewed)
    new = (ROOT / proposal.NEW_JSON).read_bytes()
    kinds = proposal.native_kinds(ROOT, reviewed)
    return reviewed, old, new, kinds


def bundle():
    return proposal.read_json(gzip.decompress((ROOT / proposal.BUNDLE).read_bytes()))


def test_exact_original_bytes_and_current_candidate_are_proven():
    reviewed, old, new, kinds = inputs()
    assert len(old) == 4078
    assert hashlib.sha256(old).hexdigest() == proposal.OLD_SHA256
    assert old == (ROOT / proposal.OLD_JSON).read_bytes()
    assert len(reviewed['old_resources']) == 37
    assert len(reviewed['approved_additions']) == 28
    merged, routes = proposal.validate_delta(old, new, reviewed, kinds)
    assert len(merged) == 65 and len(routes) == 41
    assert proposal.validate(ROOT)['static_runtime119'] == 119


def test_current_matcher_and_runtime_metadata_match_original_guard():
    reviewed, _, _, _ = inputs()
    module = proposal.load_network(ROOT)
    accepted = proposal.read_json((ROOT / proposal.WORKBENCH).read_bytes())
    proposal.executing(module.match, accepted['network_matcher'], module, ROOT)
    assert module.RESOURCES == accepted['network_resources']
    assert module.BY_ENDPOINT == proposal.endpoints(module.RESOURCES)


@pytest.mark.parametrize('kind', ['Pod', 'ConfigMap', 'Deployment', 'DaemonSet', 'StatefulSet',
    'ReplicaSet', 'Job', 'CronJob', 'ReplicationController', 'PodTemplate'])
def test_every_supported_selected_kind_get_and_list_route_is_disjoint(kind):
    reviewed, old, new, kinds = inputs()
    merged, _ = proposal.validate_delta(old, new, reviewed, kinds)
    module = proposal.load_network(ROOT)
    for namespace in ('a', 'review', 'a' * 63):
        for name in ('x', 'selected-name', 'a.b'):
            version, plural, _ = kinds[kind]
            prefix = '/api/v1' if version == 'v1' else '/apis/' + version
            for path in (prefix + '/' + plural, prefix + '/namespaces/' + namespace + '/' + plural,
                         prefix + '/namespaces/' + namespace + '/' + plural + '/' + name):
                assert module.match(path) is None
    assert not set(proposal.endpoints(merged)) & {('apps', 'deployments'), ('batch', 'jobs')}


def test_selected_log_native_pod_and_log_routes_are_disjoint():
    module = proposal.load_network(ROOT)
    for namespace in ('a', 'review', 'a' * 63):
        for pod in ('x', 'selected-name', 'a.b'):
            path = '/api/v1/namespaces/' + namespace + '/pods/' + pod
            assert module.match(path) is None and module.match(path + '/log') is None
            assert module.match(path + '/log?container=app&follow=false') is None


@pytest.mark.parametrize('mutate', [
    lambda d: d.update(unapproved_network_kind=[['evil.example'], 'extraresources', True]),
    lambda d: d.pop('istio_gateway'),
    lambda d: d['istio_gateway'].__setitem__(1, 'deployments'),
    lambda d: d['istio_gateway'].__setitem__(2, False)])
def test_old_entries_or_bytes_cannot_change(mutate):
    reviewed, old, new, kinds = inputs()
    value = json.loads(old)
    mutate(value)
    changed = (json.dumps(value, indent=2) + '\n').encode()
    with pytest.raises(ValueError, match='network_json_digest'):
        proposal.validate_delta(changed, new, reviewed, kinds)


@pytest.mark.parametrize('mutate', [
    lambda d: d.update(unapproved=[['evil.example'], 'extras', True]),
    lambda d: d.pop('openshift_route'),
    lambda d: d['openshift_route'].__setitem__(1, 'secrets'),
    lambda d: d['openshift_route'].__setitem__(2, False),
    lambda d: d.update(istio_gateway=[['networking.istio.io'], 'gateways', True])])
def test_new_extra_changed_removed_or_shadowing_entries_reject(mutate):
    reviewed, old, new, kinds = inputs()
    value = json.loads(new)
    mutate(value)
    changed = (json.dumps(value, indent=2) + '\n').encode()
    with pytest.raises(ValueError, match='network_json_digest'):
        proposal.validate_delta(old, changed, reviewed, kinds)
    # Even an input-provided digest cannot approve a different entry set.
    reviewed['new_json_sha256'] = proposal.digest(changed)
    with pytest.raises(ValueError, match='network_exact_entries'):
        proposal.validate_delta(old, changed, reviewed, kinds)


@pytest.mark.parametrize('group,plural', [('apps', 'deployments'), ('apps', 'daemonsets'),
    ('apps', 'statefulsets'), ('apps', 'replicasets'), ('batch', 'jobs'), ('batch', 'cronjobs')])
def test_structural_overlap_rejects_arbitrary_namespace_routes(group, plural):
    reviewed, old, new, kinds = inputs()
    resources = dict(reviewed['old_resources'], **reviewed['approved_additions'])
    resources['hostile_endpoint'] = [[group], plural, True]
    with pytest.raises(ValueError, match='selected_route_overlap'):
        proposal.assert_disjoint(resources, kinds)


def test_duplicate_group_plural_and_duplicate_json_keys_reject():
    with pytest.raises(ValueError, match='duplicate_endpoint'):
        proposal.endpoints({'first': [['a.example'], 'routes', True], 'second': [['a.example'], 'routes', False]})
    with pytest.raises(ValueError, match='duplicate_json_key'):
        proposal.read_json(b'{"kind":1,"kind":2}')


@pytest.mark.parametrize('mutate', ['resources', 'map', 'code', 'function', 'defaults'])
def test_current_loaded_matcher_or_metadata_replacement_rejects(mutate):
    module = proposal.load_network(ROOT)
    if mutate == 'resources':
        module.RESOURCES['unapproved'] = [['evil.example'], 'extras', True]
    elif mutate == 'map':
        module.BY_ENDPOINT[('apps', 'deployments')] = 'hostile'
    elif mutate == 'code':
        module.match.__code__ = (lambda path: None).__code__
    elif mutate == 'function':
        module.match = lambda path: None
    else:
        module.match.__defaults__ = ('/apis/apps/v1/deployments',)
    with pytest.raises(ValueError):
        proposal.validate(ROOT, module)


def test_archived_helpers_and_receipts_are_exact_and_candidates_change_zero_functions():
    reviewed, _, _, _ = inputs()
    packaged = bundle()
    result = proposal.validate_candidates(packaged, reviewed)
    assert result == {'existing_files_proposed': 4, 'changed_function_definitions': 0,
                      'registry_edits': 0, 'dataflow_runtime_receipt_edits': 0}
    for name, row in packaged['predecessors'].items():
        assert bytes.fromhex(row['hex']) == (ROOT / name).read_bytes()


@pytest.mark.parametrize('edit', ['extra_file', 'old_source', 'function', 'old_network_entry',
    'unapproved_source', 'runtime_manifest', 'transitive_predecessor'])
def test_candidate_rejects_every_non_whitelisted_edit(edit):
    reviewed, _, _, _ = inputs()
    packaged = bundle()
    wb = proposal.WORKBENCH
    df = 'peaso/checks/gcp_dataflow_batch_shared_hook_successor_20261020.json'
    if edit == 'extra_file':
        packaged['candidates']['peaso/checks/__init__.py'] = {'sha256': '0' * 64, 'hex': ''}
    else:
        name = wb
        if edit == 'old_source':
            packaged['predecessors'][wb]['hex'] += '20'
        elif edit == 'function':
            name = wb[:-5] + '.py'
            raw = bytes.fromhex(packaged['candidates'][name]['hex']).replace(b'return receipt', b'return {}', 1)
        else:
            if edit == 'transitive_predecessor':
                name = df
            data = json.loads(bytes.fromhex(packaged['candidates'][name]['hex']))
            if edit == 'old_network_entry':
                data['network_resources']['istio_gateway'][2] = False
            elif edit == 'unapproved_source':
                data['sources']['peaso/engine.py'] = 'a' * 64
            elif edit == 'runtime_manifest':
                data['successor_functions'].pop('install')
            else:
                data['accepted_receipt_sha256'] = 'a' * 64
            raw = (json.dumps(data, indent=2) + '\n').encode()
        if edit != 'old_source':
            packaged['candidates'][name] = {'sha256': proposal.digest(raw), 'hex': raw.hex()}
    with pytest.raises(ValueError):
        proposal.validate_candidates(packaged, reviewed)


def test_all119_original_rows_remain_exact_and_original_live_guard_passes():
    reviewed, _, _, _ = inputs()
    assert proposal.static_runtime119(ROOT, reviewed) == 119
    tampered = deepcopy(reviewed)
    tampered['runtime119'].pop(next(iter(tampered['runtime119'])))
    with pytest.raises(ValueError, match='runtime119_manifest'):
        proposal.static_runtime119(ROOT, tampered)
    # The original entrypoint rejects a successor alias; keep that rejection.
    with pytest.raises(ValueError, match='production_shared_identity'):
        proposal.validate_live(ROOT)
    from tests.aws_k8s_current_native_inputs_20261020 import validate_current_network
    result = validate_current_network(proposal, ROOT)
    assert result['live_runtime119'] == 'passed_current_guard_preserving_all119_rows'
    assert result['imported_identity_pairs'] == 18
    assert result['isolated_route_entries'] == 28 and result['existing_edits_needed'] == 0
    assert result['registry_changed'] is False


def test_historical_four_file_candidate_rejects_now_isolated_network_state():
    reviewed, _, _, _ = inputs()
    with pytest.raises(ValueError, match='stale_network_candidate'):
        proposal.candidate_applicable(ROOT, reviewed)
    assert proposal.validate(ROOT)['historical_candidate_applicability'] == 'rejected_stale_network_candidate'
