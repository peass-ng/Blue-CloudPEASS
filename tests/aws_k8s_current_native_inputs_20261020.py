"""Finite current native witnesses; preserve historical registration/proof inputs."""
from copy import deepcopy
import importlib
from peaso import checks


def case_state(value):
    """Snapshot both opaque owner identity and every mutable assertion field."""
    from peaso import azure_function_package_index_20261020 as owner
    if type(value) in (owner._Admitted, owner._Assertions):
        return ('owner_admission', type(value), id(value), case_state(value.snapshot),
                case_state(value.expected), case_state(value.scope))
    if isinstance(value, dict):
        return {key: case_state(member) for key, member in value.items()}
    if isinstance(value, list):
        return [case_state(member) for member in value]
    if isinstance(value, tuple):
        return tuple(case_state(member) for member in value)
    return deepcopy(value)


def annotation_current_cases(check_id, historical):
    from peaso.checks import k8s_annotation_native_admission_20261020 as admission
    if check_id not in admission.IDS:
        return historical
    receipt, native = admission._reviewed_inputs()
    import hashlib, json
    assert hashlib.sha256(json.dumps(historical, sort_keys=True).encode()).hexdigest() == receipt['historical_case_sha256'][check_id]
    result = deepcopy(historical)
    result.update(deepcopy(native[check_id]))
    return result


def validate_current_network(proposal, root):
    """Retain all 119 historical rows and run their admitted current entrypoint."""
    reviewed = proposal.receipt(root)
    result = proposal.validate(root)
    from peaso.checks import gcp_dataflow_batch_source_runtime_admission_20261020 as admission
    from peaso.checks import gcp_dataflow_batch_shared_hook_successor_20261020 as historical
    from peaso.collectors import k8s_network_extensions as network
    from peaso.collectors import k8s_network_route_extensions as route
    from peaso.collectors import k8s_network_catalog as catalog
    shared = checks.aws_workload_command_shared_successor_20261020
    assert admission.shared is shared and shared is not historical
    shared.reviewed_delta(root)
    accepted, _, _ = admission.reviewed_inputs(root)
    assert accepted['runtime_functions'] == reviewed['runtime119']
    assert len(admission._bindings()) == 18
    assert all(actual is expected for actual, expected in admission._bindings())
    proposal.validate(root, network)
    proposal.executing(route.match, reviewed['isolated_route_matcher'], route, root)
    assert route.RESOURCES == reviewed['approved_additions']
    assert route.BY_ENDPOINT == proposal.endpoints(route.RESOURCES)
    assert route.project is network.project and route.re is proposal.re
    for path in proposal.assert_disjoint(dict(network.RESOURCES, **route.RESOURCES), proposal.native_kinds(root, reviewed)):
        assert route.match(path) is None and not catalog.allowed_path(path)
    for kind, (groups, plural, _) in route.RESOURCES.items():
        for group in groups:
            for middle in ('/', '/namespaces/review/'):
                path = '/apis/' + group + '/v1' + middle + plural
                assert route.match(path) == kind and catalog.allowed_path(path)
    result.update(live_runtime119='passed_current_guard_preserving_all119_rows',
                  imported_identity_pairs=18, isolated_route_entries=len(route.RESOURCES), existing_edits_needed=0)
    return result


def selected_content_pairs(provider):
    """Explicit admitted provider modules; no default metadata kind is inferred."""
    if provider == 'k8s':
        modules = ('k8s_literal_secret_indicators', 'k8s_selected_log_sample_secret_indicators',
                   'k8s_selected_metadata_runtime_20261020')
        profiles = ()
    else:
        assert provider == 'azure'
        modules = ('azure_app_settings_secret_indicators', 'azure_acr_image_secret_indicators',
                   'azure_selected_configuration_secret_indicators', 'azure_selected_storage_secret_indicators',
                   'azure_devops_selected_content_secret_indicators', 'azure_ml_selected_job_secret_indicators',
                   'azure_databricks_notebook_secret_indicators', 'azure_function_package_integration_20261020')
        profiles = ('azure_selected_declaration_secret_indicators', 'azure_selected_log_sample_secret_indicators',
                    'azure_ml_selected_asset_secret_indicators')
    pairs = [(module.CHECK, module.KIND) for name in modules
             for module in (importlib.import_module('peaso.collectors.' + name),)]
    for name in profiles:
        module = importlib.import_module('peaso.collectors.' + name)
        pairs.extend((profile['check'], profile['kind']) for profile in module.PROFILES.values())
    assert len({cid for cid, _ in pairs}) == len(pairs)
    registry = {check.id: check for check in checks.CHECKS}
    assert all(registry[cid].kind == kind and registry[cid].provider == provider for cid, kind in pairs)
    return pairs


def assert_modern_psp_native_applicability(check_id, monkeypatch):
    """Actual discovery/version HTTP proof replaces an unbound old PSP DTO."""
    from tests import test_k8s_annotation_psp_closure_20261020 as native
    statuses, _, pool, _ = native.execute(monkeypatch, check_id, modern=True, install=False)
    assert statuses == ['NOT_APPLICABLE']
    assert len(pool.calls) == 2
    assert all('podsecuritypolicies' not in str(call) for call in pool.calls)


TEST_PREDECESSORS_SHA256 = 'd76f19635759ed3a7d443c773c58d5c1aca36c8223b03b4ead4d18a45bf08798'
TEST_PREDECESSORS = 'tests/fixtures/aws_k8s_residual_test_predecessors_20261020.json.gz'
OWNED_TESTS = frozenset('tests/' + name + '.py' for name in (
    'test_aws_content_scan_selection_review', 'test_peaso_collectors_aws',
    'test_k8s_selected_log_sample_secret_review_20261020',
    'test_k8s_selected_metadata_secret_review_20261020',
    'test_k8s_kubelet_configmap_production_20261020',
    'test_peaso_checks_claude_gcp_k8s_behavior',
    'test_k8s_selected_log_sample_production_20261020',
    'test_k8s_network_inventory_successor_20261020',
    'test_cross_cloud_secret_surface_audit_20261020'))


def exact_test_predecessor(root, name, current=None):
    """Reverse a sealed finite test-only delta to the original exact byte pin."""
    import gzip, hashlib, json
    raw = (root / TEST_PREDECESSORS).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == TEST_PREDECESSORS_SHA256
    receipt = json.loads(gzip.decompress(raw))
    assert receipt['schema'] == 1 and receipt['commit'] == '332f1f4825ab5ec17305f60dc85e6d2bffe99f6b'
    assert set(receipt['files']) == OWNED_TESTS and name in OWNED_TESTS
    row = receipt['files'][name]
    raw = (root / name).read_bytes() if current is None else current
    assert hashlib.sha256(raw).hexdigest() == row['after_sha256'] and len(raw) == row['after_size']
    restored = raw
    for before, after in row['exact_replacements']:
        old, new = bytes.fromhex(before), bytes.fromhex(after)
        assert new and restored.count(new) == 1
        restored = restored.replace(new, old, 1)
    assert restored == bytes.fromhex(row['before_hex'])
    assert hashlib.sha256(restored).hexdigest() == row['before_sha256']
    return restored


def network_test_successor(historical):
    """Explicit test-source successor; keep the original proposal object intact.

    All historical helper function code and receipt rows stay unchanged. Only
    the receipt's one owned test-file source input gets an exact sealed reverse
    transformation; other source bindings still use their original normalization.
    """
    import types
    namespace = dict(vars(historical))

    def current_receipt(root):
        raw = historical.under(root, historical.RECEIPT).read_bytes()
        assert historical.digest(raw) == historical.RECEIPT_SHA256
        reviewed = historical.read_json(raw)
        for name, row in reviewed['sources'].items():
            data = historical.under(root, name).read_bytes()
            if name == 'tests/test_k8s_network_inventory_successor_20261020.py':
                data = exact_test_predecessor(root, name, data)
            if row['normalization'] == 'receipt_self':
                data = historical.normalized_self(data)
            else:
                assert row['normalization'] == 'none'
            if historical.digest(data) != row['sha256']:
                raise ValueError('proposal_source:' + name)
        return reviewed

    # Clone only this standalone test proposal, never canonical runtime modules.
    # The original function objects and their globals remain untouched.
    for name, fn in vars(historical).items():
        if isinstance(fn, types.FunctionType) and fn.__globals__ is vars(historical):
            clone = types.FunctionType(fn.__code__, namespace, fn.__name__, fn.__defaults__, fn.__closure__)
            clone.__kwdefaults__ = fn.__kwdefaults__
            namespace[name] = clone
    namespace['receipt'] = current_receipt
    namespace['historical'] = historical
    return types.SimpleNamespace(**namespace)
