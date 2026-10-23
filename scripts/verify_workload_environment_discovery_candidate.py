"""Isolated synthetic smoke for the unadmitted workload discovery candidate.

Run directly. This imports leaf readers without package initialization; it does
not replace the repository's source admission or registered-check test gate.
"""
import importlib
import json
from copy import deepcopy
from pathlib import Path
import sys
import threading
import types

ROOT = Path(__file__).resolve().parents[1]
package = types.ModuleType('peaso')
package.__path__ = [str(ROOT / 'peaso')]
sys.modules['peaso'] = package
collectors = types.ModuleType('peaso.collectors')
collectors.__path__ = [str(ROOT / 'peaso' / 'collectors')]
sys.modules['peaso.collectors'] = collectors
from peaso.collectors import workload_environment_discovery as discovery
from peaso.collectors import aws_lambda_environment_secret_indicators as source
from peaso.secret_scanning import _fingerprint

ACCOUNT = '123456789012'
REGION = 'us-east-1'
SCOPE = ACCOUNT + '/' + REGION
ARN = 'arn:aws:lambda:' + REGION + ':' + ACCOUNT + ':function:test'
TOKEN = 'ghp_' + '7mQ2zR9wL4cV8nK1sF6aH3jP5uD0xB2yE9rT'
CALLER = {'Account': ACCOUNT, 'Arn': 'arn:aws:iam::' + ACCOUNT + ':user/reviewer'}

aws_stub = types.ModuleType('peaso.collectors.aws')
class ReadResult:
    def __init__(self, items, status='collected', error=None):
        self.items, self.status, self.error = items, status, error
class ReadFailure(Exception):
    def __init__(self, status, code):
        super().__init__(code)
        self.status, self.code = status, code
aws_stub.ReadResult, aws_stub.ReadFailure = ReadResult, ReadFailure
sys.modules['peaso.collectors.aws'] = aws_stub


def native(value, *, truncated=False, arn=ARN):
    result = {'FunctionArn': arn, 'FunctionName': arn.rsplit(':', 1)[1], 'Version': '$LATEST',
        'RevisionId': '11111111-1111-4111-8111-111111111111', 'State': 'Active',
        'LastUpdateStatus': 'Successful', 'Environment': {'Variables': {'Mode': value}},
        'ResponseMetadata': {'HTTPStatusCode': 200,
            'RequestId': '22222222-2222-4222-8222-222222222222'}}
    if truncated:
        result['NextMarker'] = 'more'
    return result


def fake_detector(payload, path, timeout, **kwargs):
    leaks = []
    if TOKEN.encode() in payload:
        leaks.append({'fingerprint': _fingerprint(TOKEN),
            'detectors': [{'engine': 'kingfisher', 'rule': 'github-pat'},
                          {'engine': 'trufflehog', 'rule': 'github-pat'}],
            'locations': [{'path': path, 'line': 1}]})
    return {'complete': True, 'engines': [
        {'engine': 'kingfisher', 'status': 'complete', 'version': '1.4.0'},
        {'engine': 'trufflehog', 'status': 'complete', 'version': '3.92.5'}],
        'leaks': leaks}
source.scan_content = fake_detector

class Requests:
    def __init__(self, response):
        self.response = response
        self.calls = 0
        self._lock = threading.RLock()
        self.content_secret_scans = True
        self.content_secret_scan_kinds = {source.KIND}
        self.automatic_workload_environment_active = False
        self.automatic_workload_environment_issues = {}
    def check_deadline(self):
        pass
    def call(self, session, service, region, operation, **kwargs):
        assert (service, region, operation) == ('lambda', REGION, 'get_function_configuration')
        assert kwargs == {'_metadata_profile': source.PROFILE, 'FunctionName': ARN}
        self.calls += 1
        if self.response is None:
            raise ReadFailure('not_collected', 'native_unavailable')
        if isinstance(self.response, Exception):
            raise self.response
        return source.project_response(self.response, service, operation,
            {'FunctionName': ARN}, request_context=(self, session), region=region)


def exercise(response):
    rows = [{'type': 'lambda_function', 'scope': SCOPE, 'status': 'collected',
        'items': [{'FunctionArn': ARN}]}]
    plan = discovery.aws_lambda(rows)
    assert plan.complete and plan.targets == (ARN,)
    requests = Requests(response)
    options = {'content_secret_scans': True, '_content_secret_scan_kinds': [source.KIND],
        source.OPTION: list(plan.targets)}
    source.initialize(requests, options, [SCOPE])
    result = source.collect_selected(requests, object(), REGION, CALLER, options, [SCOPE])
    assert requests.calls == 1 and len(result.items) == 1
    return result.items[0][source.MARKER]

positive = exercise(native(TOKEN))
assert positive['complete'] and len(positive['leaks']) == 1
assert TOKEN not in json.dumps(positive)
clean = exercise(native('ready'))
assert clean['complete'] and clean['leaks'] == []
denied = exercise(None)
assert not denied['complete'] and denied['leaks'] == []
truncated = exercise(native(TOKEN, truncated=True))
assert not truncated['complete'] and truncated['leaks'] == []

many = [{'type': 'lambda_function', 'scope': SCOPE, 'status': 'collected',
    'items': [{'FunctionArn': ARN[:-4] + str(i)} for i in range(9)]}]
limited = discovery.aws_lambda(many)
assert limited.discovered == 9 and len(limited.targets) == 9 and limited.complete
assert [len(batch) for batch in discovery.batches(limited.targets, 8)] == [8, 1]
partial = discovery.aws_lambda([{'type': 'lambda_function', 'scope': SCOPE,
    'status': 'partial', 'items': [{'FunctionArn': ARN}]}])
assert not partial.complete and partial.reason == 'source_inventory_incomplete'
missing_scope = discovery.aws_lambda(many, expected_scopes=[SCOPE, ACCOUNT + '/us-west-2'])
assert not missing_scope.complete and missing_scope.reason == 'source_inventory_unavailable'

many_32 = [{'type': 'lambda_function', 'scope': SCOPE, 'status': 'collected',
    'items': [{'FunctionArn': ARN[:-4] + f'{i:02d}'} for i in range(32)]}]
plan_32 = discovery.aws_lambda(many_32)
assert plan_32.complete and plan_32.discovered == 32
assert [len(batch) for batch in discovery.batches(plan_32.targets, source.MAX_TARGETS)] == [8, 8, 8, 8]
class BatchRequests(Requests):
    def call(self, session, service, region, operation, **kwargs):
        arn = kwargs['FunctionName']
        assert (service, region, operation, kwargs['_metadata_profile']) == (
            'lambda', REGION, 'get_function_configuration', source.PROFILE)
        self.calls += 1
        return source.project_response(native('ready', arn=arn), service, operation,
            {'FunctionName': arn}, request_context=(self, session), region=region)
batch_requests = BatchRequests(None)
batch_rows = []
batch_collections_32 = []
batch_receipts_32 = []
for batch in discovery.batches(plan_32.targets, source.MAX_TARGETS):
    batch_options = {'content_secret_scans': True, '_content_secret_scan_kinds': [source.KIND],
        source.OPTION: list(batch)}
    source.initialize(batch_requests, batch_options, [SCOPE])
    batch_result = source.collect_selected(batch_requests, object(), REGION, CALLER,
        batch_options, [SCOPE])
    assert batch_result.status == 'collected' and len(batch_result.items) == 8
    batch_rows.extend(batch_result.items)
    batch_id = source.KIND + ':' + str(len(batch_receipts_32) + 1)
    batch_collections_32.append({'type': source.KIND, 'scope': SCOPE,
        'service': 'lambda', 'status': batch_result.status, 'items': [
            {**row, 'AccountId': ACCOUNT, 'Region': REGION} for row in batch_result.items],
        'account_id': ACCOUNT, 'global': False, 'automatic_batch': batch_id})
    batch_receipts_32.append({'id': batch_id, 'scope': SCOPE,
        'metadata': deepcopy(batch_requests.lambda_environment_metadata)})
assert batch_requests.calls == 32 and len({row['id'] for row in batch_rows}) == 32
discovery.fold_collections(batch_collections_32, source.KIND, batch_receipts_32)
assert len(batch_collections_32) == 1 and len(batch_collections_32[0]['items']) == 32
print('PASS: 32 Lambda native targets routed in four 8-target bounded batches, exactly 32 calls')

from peaso.collectors import azure_app_settings_secret_indicators as azure_settings
from peaso.collectors import azure_selected_configuration_secret_indicators as azure_config
subscription = '/subscriptions/11111111-1111-1111-1111-111111111111'
site = subscription + '/resourceGroups/review/providers/Microsoft.Web/sites/test'
aci = subscription + '/resourceGroups/review/providers/Microsoft.ContainerInstance/containerGroups/test'
app = subscription + '/resourceGroups/review/providers/Microsoft.App/containerApps/test'
azure_rows = [
    {'type': 'app_service', 'scope': subscription, 'status': 'collected', 'items': [{'id': site}]},
    {'type': 'app_service_slot', 'scope': subscription, 'status': 'empty', 'items': []},
    {'type': 'container_group', 'scope': subscription, 'status': 'collected', 'items': [{'id': aci}]},
    {'type': 'container_app', 'scope': subscription, 'status': 'collected', 'items': [{'id': app}]},
]
assert discovery.azure_settings(azure_rows).targets == (site,)
assert len(discovery.azure_containers(azure_rows).targets) == 2
assert not discovery.azure_containers(azure_rows[:-1]).complete

cluster = 'test-cluster'
rows = [{'type': kind, 'scope': 'team', 'status': 'empty', 'items': []} for kind in
    ('pod', 'deployment', 'daemonset', 'statefulset', 'replicaset', 'job', 'cronjob',
     'replicationcontroller', 'podtemplate')]
rows[0]['status'] = 'collected'
rows[0]['items'] = [{'metadata': {'name': 'test', 'namespace': 'team'},
    'provenance': {'cluster_id': cluster, 'evidence': 'read-only list'}}]
assert discovery.k8s_workloads(rows, cluster).targets[0]['kind'] == 'Pod'
rows[0]['status'] = 'partial'
assert not discovery.k8s_workloads(rows, cluster).complete
print('PASS: Lambda native positive/clean/denied/truncated, 1 call each; deterministic 8+1 batching; Azure and K8s native target planning')

# Exercise the real fixed-origin ARM reader with synthetic wire responses.
import io
import time
azure_settings.scan_content = fake_detector
class ArmResponse:
    def __init__(self, value, status=200):
        self.raw = json.dumps(value).encode()
        self.stream = io.BytesIO(self.raw)
        self.status = status
        self.headers = {'Content-Type': 'application/json', 'Content-Length': str(len(self.raw))}
    def getheader(self, key):
        return self.headers.get(key)
    def read(self, size):
        return self.stream.read(size)
    def close(self):
        pass
class ArmTransport:
    def token(self, audience):
        assert audience == 'https://management.azure.com'
        return 'synthetic-token'
class ArmReader:
    def __init__(self):
        self.calls = 0
        self.app_setting_secret_redactions = set()
    def check_cancelled(self):
        pass
    def call(self, function, *args):
        self.calls += 1
        return function(*args)


def arm_case(value, *, denied=False, truncated=False):
    native_site = {'id': site, 'type': 'Microsoft.Web/sites', 'properties': {}}
    settings = {'id': site + '/config/appsettings', 'name': 'appsettings',
        'type': 'Microsoft.Web/sites/config', 'properties': {
            'Mode': value,
            'VaultRef': '@Microsoft.KeyVault(VaultName=review-vault;SecretName=token)'}}
    if truncated:
        settings['nextLink'] = 'forbidden-continuation'
    responses = [ArmResponse(native_site, 403 if denied else 200), ArmResponse(settings)]
    seen = []
    class Connection:
        sock = None
        def __init__(self, host, timeout):
            assert host == 'management.azure.com' and 0 < timeout <= 10
        def set_debuglevel(self, level):
            assert level == 0
        def request(self, method, route, body=None, headers=None):
            expected = (('GET', site + '?api-version=2025-03-01') if not seen else
                        ('POST', site + '/config/appsettings/list?api-version=2025-03-01'))
            assert (method, route) == expected
            assert body is None and headers['Accept-Encoding'] == 'identity'
            seen.append((method, route))
        def getresponse(self):
            return responses[len(seen) - 1]
        def close(self):
            pass
    original = azure_settings.http.client.HTTPSConnection
    azure_settings.http.client.HTTPSConnection = Connection
    try:
        reader = ArmReader()
        receipts = []
        result = azure_settings._scan(reader, ArmTransport(), site, subscription,
            {'deadline': time.monotonic() + 60, 'bytes': 0}, receipts)
        arm_case.last_item, arm_case.last_receipts = result, receipts
    finally:
        azure_settings.http.client.HTTPSConnection = original
    return result[azure_settings.MARKER], reader.calls, seen

arm_positive, calls, routes = arm_case(TOKEN)
assert arm_positive['complete'] and len(arm_positive['leaks']) == 1
assert arm_positive['reference_count'] == 1 and calls == 2 and len(routes) == 2
assert TOKEN not in json.dumps(arm_positive)
arm_clean, calls, routes = arm_case('ready')
assert arm_clean['complete'] and arm_clean['leaks'] == [] and calls == 2
arm_denied, calls, routes = arm_case('ready', denied=True)
arm_denied_item, arm_denied_receipts = deepcopy(arm_case.last_item), deepcopy(arm_case.last_receipts)
assert not arm_denied['complete'] and calls == 1
arm_truncated, calls, routes = arm_case(TOKEN, truncated=True)
assert not arm_truncated['complete'] and calls == 2
print('PASS: Azure ARM positive/clean/denied/truncated with exact 2/2/1/2 native calls; Key Vault reference skipped')

from peaso.collectors import k8s_literal_secret_indicators as k8s_source
k8s_source.scan_content = fake_detector
k8s_stub = types.ModuleType('peaso.collectors.k8s')
class BoundedPool:
    pass
k8s_stub._BoundedPool = BoundedPool
sys.modules['peaso.collectors.k8s'] = k8s_stub
k8s_target = {'cluster_id': cluster, 'namespace': 'team', 'kind': 'Pod', 'name': 'test'}
class K8sReader:
    def __init__(self):
        self.budget = types.SimpleNamespace(max_items=None)
        self.total = 0
        self.collections = []
    def check_cancelled(self):
        pass

def pod(value, *, unstable=False):
    result = {'apiVersion': 'v1', 'kind': 'Pod',
        'metadata': {'name': 'test', 'namespace': 'team', 'uid': 'test-uid',
                     'resourceVersion': '2' if unstable else '1'},
        'spec': {'containers': [{'name': 'main', 'env': [
            {'name': 'LITERAL', 'value': value},
            {'name': 'REFERENCE', 'valueFrom': {'secretKeyRef': {'name': 'vault', 'key': 'token'}}}]}]}}
    return result

def k8s_case(value, *, denied=False, unstable=False):
    calls = []
    original = k8s_source._read
    def read(reader, api, target, state):
        assert target == k8s_target
        calls.append(target)
        if denied:
            raise k8s_source.Incomplete('native_get_denied')
        return pod(value, unstable=unstable and len(calls) == 2), 200
    k8s_source._read = read
    try:
        reader = K8sReader()
        options = {'content_secret_scans': True, '_content_secret_scan_kinds': [k8s_source.KIND],
                   k8s_source.OPTION: [k8s_target]}
        metadata, matches = k8s_source.collect(reader, object(), options, ['team'], cluster)
        k8s_case.last_item = reader.collections[0]['items'][0]
        k8s_case.last_metadata = metadata
    finally:
        k8s_source._read = original
    return reader.collections[0]['items'][0][k8s_source.MARKER], len(calls)

k8s_positive, calls = k8s_case(TOKEN)
assert k8s_positive['complete'] and len(k8s_positive['leaks']) == 1
assert k8s_positive['reference_count'] == 1 and calls == 2
assert TOKEN not in json.dumps(k8s_positive)
k8s_clean, calls = k8s_case('ready')
assert k8s_clean['complete'] and k8s_clean['leaks'] == [] and calls == 2
k8s_denied, calls = k8s_case('ready', denied=True)
k8s_denied_item, k8s_denied_metadata = deepcopy(k8s_case.last_item), deepcopy(k8s_case.last_metadata)
assert not k8s_denied['complete'] and calls == 1
k8s_changed, calls = k8s_case(TOKEN, unstable=True)
assert not k8s_changed['complete'] and calls == 2
print('PASS: Kubernetes native positive/clean/denied/changed with exact 2/2/1/2 reads; SecretKeyRef not dereferenced')

from peaso.collectors import aws_selected_configuration_secret_indicators as ecs_source
ecs_arn = 'arn:aws:ecs:' + REGION + ':' + ACCOUNT + ':task-definition/review:3'
ecs_inventory = [{'type': 'ecs_task_definition', 'scope': SCOPE, 'status': 'collected',
    'items': [{'taskDefinitionArn': ecs_arn}]}]
ecs_plan = discovery.aws_ecs(ecs_inventory)
assert ecs_plan.complete and ecs_plan.discovered == 1
svc, op, arguments = ecs_source.route(ecs_plan.targets[0])
assert (svc, op, arguments) == ('ecs', 'describe_task_definition', {'taskDefinition': ecs_arn})
surface, account, region, partition, _ = ecs_source.parse(ecs_plan.targets[0])
info = {'surface': surface, 'account': account, 'region': region, 'partition': partition}
def task(value, *, revision=3):
    return {'taskDefinition': {'taskDefinitionArn': ecs_arn, 'status': 'ACTIVE',
        'family': 'review', 'revision': revision,
        'containerDefinitions': [{'name': 'main',
            'environment': [{'name': 'TOKEN', 'value': value}],
            'secrets': [{'name': 'REFERENCE', 'valueFrom': 'arn:aws:secretsmanager:' + REGION + ':' + ACCOUNT + ':secret:review'}]}]}}
payload, count = ecs_source.extract(task(TOKEN), svc, op, arguments, info)
assert TOKEN.encode() in payload and b'secretsmanager' not in payload and count == 1
payload, count = ecs_source.extract(task('ready'), svc, op, arguments, info)
assert TOKEN.encode() not in payload and count == 1
try:
    ecs_source.extract(task(TOKEN, revision=4), svc, op, arguments, info)
    raise AssertionError('foreign revision accepted')
except ValueError:
    pass
assert not discovery.aws_ecs([{'type': 'ecs_task_definition', 'scope': SCOPE,
    'status': 'partial', 'items': [{'taskDefinitionArn': ecs_arn}]}]).complete
print('PASS: ECS exact DescribeTaskDefinition routing and positive/clean/foreign-revision extraction; secret reference skipped')

native_config = [
    ('ecs_task_definition', {'taskDefinitionArn': ecs_arn}),
    ('codebuild_project', {'name': 'review'}),
    ('batch_job_definition', {'jobDefinitionArn':
        'arn:aws:batch:' + REGION + ':' + ACCOUNT + ':job-definition/review:3'}),
    ('amplify_app', {'appArn': 'arn:aws:amplify:' + REGION + ':' + ACCOUNT + ':apps/abc123'}),
    ('glue_job', {'Name': 'review'}),
]
configuration_plan = discovery.aws_configuration([
    {'type': kind, 'scope': SCOPE, 'status': 'collected', 'items': [row]}
    for kind, row in native_config], [SCOPE])
assert configuration_plan.complete and configuration_plan.discovered == 5
assert {t['surface'] for t in configuration_plan.targets} == {
    'ecs_environment', 'codebuild_environment', 'batch_environment',
    'amplify_environment', 'glue_job_arguments'}
assert {(svc, op) for svc, op, _ in (ecs_source.route(t)
    for t in configuration_plan.targets)} == {
    ('ecs', 'describe_task_definition'), ('codebuild', 'batch_get_projects'),
    ('batch', 'describe_job_definitions'), ('amplify', 'get_app'),
    ('glue', 'get_job')}
assert [len(b) for b in discovery.batches(configuration_plan.targets * 4, 16)] == [16, 4]
print('PASS: five native AWS workload surface IDs map to existing selected routes; 16+4 batching')

# Automatic-only issue sidecar: typed IAM denial and bounded unsupported/no-env
# states survive without adding fields to the historically pinned native marker.
checks_stub = types.ModuleType('peaso.checks')
checks_stub.__path__ = [str(ROOT / 'peaso' / 'checks')]
sys.modules['peaso.checks'] = checks_stub
auto_adapter = importlib.import_module('peaso.checks.automatic_workload_batch')

def automatic_leaf(module, item, index):
    check_id = next(check_id for check_id, (kind, _) in auto_adapter.AUTO_CHECKS.items()
                    if kind == module.KIND)
    prepared = auto_adapter.prepare(index, check_id)
    return auto_adapter.evaluate_prepared(item, index, module.evaluate, prepared)

lambda_check = importlib.import_module('peaso.checks.aws_lambda_environment_secret_review_20261020')
fixtures = next(iter(json.loads((ROOT / 'peaso' / 'checks' /
    'aws_lambda_environment_secret_review_20261020_fixtures.json').read_text()).values()))
index_32 = deepcopy(fixtures['pass_index'])
index_32['collections'][source.KIND] = batch_collections_32
index_32['context']['metadata']['automatic_workload_environment_batches'] = {
    source.KIND: batch_receipts_32}
index_32['context']['metadata']['automatic_workload_environment_coverage'] = {
    source.KIND: {'complete': True, 'discovered': 32, 'inspected': 32}}
prepared_32 = auto_adapter.prepare(index_32, lambda_check.CHECK)
assert all(auto_adapter.evaluate_prepared(row, index_32, lambda_check.evaluate, prepared_32)[0] == 'PASS'
    for row in batch_collections_32[0]['items'])
print('PASS: all 32 native Lambda rows evaluate PASS from four real per-batch captures in one folded collection')

# Execute the actual nested AWS append body with bounded empty reads. Its
# automatic batches must never reach a checkpoint callback before folding.
import ast
aws_tree = ast.parse((ROOT / 'peaso/collectors/aws.py').read_text())
collect_node = next(node for node in aws_tree.body if isinstance(node, ast.FunctionDef) and node.name == 'collect')
append_node = next(node for node in collect_node.body if isinstance(node, ast.FunctionDef) and node.name == 'append')
assert isinstance(append_node.body[0], ast.Nonlocal) and append_node.body[0].names == ['total_items']
append_node.body[0] = ast.Global(names=['total_items'])
checkpoint_events, emitted = [], []
namespace = {'__package__': 'peaso.collectors', 'total_items': 0,
    'collections': emitted, 'collection_callback': checkpoint_events.append,
    'auto_lambda_environment': True, 'auto_ecs_environment': True,
    'aws_lambda_environment_secret_indicators': source,
    'aws_selected_configuration_secret_indicators': ecs_source,
    'GLOBAL_TYPES': set(), 'progress_callback': None, 'progress_total': None,
    'emit_progress': lambda *args, **kwargs: None}
exec(compile(ast.fix_missing_locations(ast.Module(body=[append_node], type_ignores=[])),
    str(ROOT / 'peaso/collectors/aws.py'), 'exec'), namespace)
for number in range(4):
    namespace['append'](source.KIND, SCOPE, 'lambda', ReadResult([], 'empty'))
    namespace['append'](ecs_source.KIND, SCOPE, 'ecs', ReadResult([], 'empty'))
assert len(emitted) == 8 and checkpoint_events == []
namespace['append']('ordinary_inventory', SCOPE, 'aws', ReadResult([], 'empty'))
assert len(checkpoint_events) == 1 and checkpoint_events[0]['type'] == 'ordinary_inventory'
print('PASS: actual AWS append body defers four Lambda and four ECS raw batch callbacks while ordinary inventory settles')

def auto_leaf(response, *, detector=None):
    previous = source.scan_content
    if detector is not None:
        source.scan_content = detector
    try:
        reader = Requests(response)
        reader.automatic_workload_environment_active = True
        options = {'content_secret_scans': True, '_content_secret_scan_kinds': [source.KIND],
            source.OPTION: [ARN]}
        source.initialize(reader, options, [SCOPE])
        caller = {**CALLER, 'UserId': 'AIDAREVIEWER'}
        read = source.collect_selected(reader, object(), REGION, caller, options, [SCOPE])
        assert reader.calls == 1 and len(read.items) == 1
        row = {**read.items[0], 'AccountId': ACCOUNT, 'Region': REGION}
        index = deepcopy(fixtures['pass_index'])
        index['collections'][source.KIND][0]['items'] = [row]
        index['context']['metadata'].update(reader.lambda_environment_metadata)
        index['context']['metadata']['automatic_workload_environment_batches'] = {
            source.KIND: [{'id': source.KIND + ':1', 'scope': SCOPE,
                'metadata': deepcopy(reader.lambda_environment_metadata),
                'ids': [row['id']], 'status': read.status, 'error': read.error,
                'issues': deepcopy(reader.automatic_workload_environment_issues)}]}
        index['context']['metadata']['automatic_workload_environment_coverage'] = {
            source.KIND: {'complete': row[source.MARKER]['complete']}}
        auto_leaf.last_row = row
        result = automatic_leaf(lambda_check, row, index)
        return result, reader.automatic_workload_environment_issues
    finally:
        source.scan_content = previous

status, issues = auto_leaf(native(TOKEN))
assert status[0] == 'FAIL' and not issues
status, issues = auto_leaf(native('ready'))
assert status[0] == 'PASS' and not issues
status, issues = auto_leaf(ReadFailure('denied', 'AccessDeniedException'))
assert status[0] == 'DENIED' and status[1]['reason'] == 'access_denied'
assert status[1]['operation'] == 'lambda:GetFunctionConfiguration'
assert status[1]['provider_code'] == 'AccessDeniedException'
assert discovery.target_coverage([ARN], source.identity,
    [{'type': source.KIND, 'items': [auto_leaf.last_row]}], source.KIND,
    source.MARKER, issues)[0]['status'] == 'denied'
assert TOKEN not in json.dumps(status) and len(issues) == 1
no_env = native('ready')
no_env['Environment']['Variables'] = {}
status, issues = auto_leaf(no_env)
assert status[0] == 'UNKNOWN' and status[1]['reason'] == 'environment_no_literals'
missing_env = native('ready')
del missing_env['Environment']
status, issues = auto_leaf(missing_env)
assert status[0] == 'UNKNOWN' and status[1]['reason'] == 'environment_unavailable'
errored_env = native('ready')
errored_env['Environment'] = {'Error': {'ErrorCode': 'ServiceException', 'Message': 'private detail'}}
status, issues = auto_leaf(errored_env)
assert status[0] == 'UNKNOWN' and status[1]['reason'] == 'environment_error'
assert 'private detail' not in json.dumps(status) and 'private detail' not in json.dumps(issues)
empty_values = native('')
status, issues = auto_leaf(empty_values)
assert status[0] == 'UNKNOWN' and status[1]['reason'] == 'environment_empty'
unsupported = native('ready', truncated=True)
status, issues = auto_leaf(unsupported)
assert status[0] == 'UNKNOWN' and status[1]['reason'] == 'native_identity_or_partial'

def detector_failure(payload, path, timeout, **kwargs):
    return {'complete': False, 'engines': [
        {'engine': 'kingfisher', 'status': 'complete', 'version': '1.4.0'},
        {'engine': 'trufflehog', 'status': 'unavailable', 'version': '3.92.5'}], 'leaks': []}
status, issues = auto_leaf(native('ready'), detector=detector_failure)
assert status[0] == 'UNKNOWN' and status[1]['reason'] == 'scanner_incomplete'
assert status[1]['failed_detectors'] == ['trufflehog'] and 'TruffleHog' in status[1]['observed']
assert not issues
assert discovery.target_coverage([ARN], source.identity,
    [{'type': source.KIND, 'items': [auto_leaf.last_row]}], source.KIND,
    source.MARKER)[0]['status'] == 'scanner_incomplete'
print('PASS: real Lambda leaf native positive/clean/AccessDenied/zero-vars/missing-env/env-error/empty-values/unsupported/TruffleHog-unavailable branches with one bounded call each')

config_check = importlib.import_module('peaso.checks.aws_selected_configuration_secret_review_20261020')
config_cases = next(iter(json.loads((ROOT / 'peaso' / 'checks' /
    'aws_selected_configuration_secret_review_20261020_fixtures.json').read_text()).values()))
class ConfigRequests(Requests):
    def call(self, session, service, region, operation, **kwargs):
        assert (service, operation, region) == ('ecs', 'describe_task_definition', REGION)
        self.calls += 1
        raise ReadFailure('denied', 'AccessDeniedException')
config_reader = ConfigRequests(None)
config_reader.automatic_workload_environment_active = True
config_options = {'content_secret_scans': True,
    '_content_secret_scan_kinds': [ecs_source.KIND], ecs_source.OPTION: list(ecs_plan.targets)}
ecs_source.initialize(config_reader, config_options, [SCOPE])
config_read = ecs_source.collect_selected(config_reader, object(), REGION,
    {**CALLER, 'UserId': 'AIDAREVIEWER'}, config_options, [SCOPE])
assert config_reader.calls == 1 and len(config_read.items) == 1
config_row = {**config_read.items[0], 'AccountId': ACCOUNT, 'Region': REGION}
config_index = deepcopy(config_cases['pass_index'])
config_index['collections'][ecs_source.KIND][0]['items'] = [config_row]
config_index['context']['metadata'].update(config_reader.configuration_content_metadata)
config_index['context']['metadata']['automatic_workload_environment_batches'] = {
    ecs_source.KIND: [{'id': ecs_source.KIND + ':1', 'scope': SCOPE,
        'metadata': deepcopy(config_reader.configuration_content_metadata),
        'ids': [config_row['id']], 'status': config_read.status, 'error': config_read.error,
        'issues': deepcopy(config_reader.automatic_workload_environment_issues)}]}
config_index['context']['metadata']['automatic_workload_environment_coverage'] = {
    ecs_source.KIND: {'complete': False}}
config_status, config_evidence = automatic_leaf(config_check, config_row, config_index)
assert config_status == 'DENIED' and config_evidence['reason'] == 'access_denied'
assert config_evidence['operation'] == 'ecs:DescribeTaskDefinition'
assert config_evidence['provider_code'] == 'AccessDeniedException'
config_coverage = discovery.target_coverage(ecs_plan.targets, ecs_source.identity,
    [{'type': ecs_source.KIND, 'items': [config_row]}], ecs_source.KIND,
    ecs_source.MARKER, config_reader.automatic_workload_environment_issues)
assert config_coverage == [{'id': config_row['id'], 'status': 'denied',
    'reason': 'AccessDeniedException', 'operation': 'ecs:DescribeTaskDefinition'}]
print('PASS: ECS selected configuration typed AccessDenied maps to exact ecs:DescribeTaskDefinition DENIED with one native call')

azure_check = importlib.import_module('peaso.checks.azure_app_settings_secret_review_20261020')
azure_cases = next(iter(json.loads((ROOT / 'peaso' / 'checks' /
    'azure_app_settings_secret_review_20261020_fixtures.json').read_text()).values()))
azure_index = deepcopy(azure_cases['pass_index'])
azure_own = azure_index['collections'][azure_settings.KIND][0]
for key in ('credential_context_id', 'customer_context_id'):
    arm_denied_item['_provenance'][key] = azure_own['items'][0]['_provenance'][key]
azure_own['items'] = [arm_denied_item]
azure_selection = azure_settings.selection_metadata({
    'content_secret_scans': True, '_content_secret_scan_kinds': [azure_settings.KIND],
    azure_settings.OPTION: [site]}, [subscription])
azure_selection[azure_settings.KIND + '_receipts'] = arm_denied_receipts
azure_index['context']['metadata'].update(azure_selection)
azure_issues = discovery.native_denial_issues(azure_settings.KIND, azure_settings.MARKER,
    [arm_denied_item], azure_selection)
assert len(azure_issues) == 1
azure_index['context']['metadata']['automatic_workload_environment_batches'] = {
    azure_settings.KIND: [{'id': azure_settings.KIND + ':1', 'scope': subscription,
        'metadata': azure_selection, 'ids': [arm_denied_item['id']],
        'status': 'collected', 'error': None, 'issues': azure_issues}]}
azure_index['context']['metadata']['automatic_workload_environment_coverage'] = {
    azure_settings.KIND: {'complete': False}}
azure_status, azure_evidence = automatic_leaf(azure_check, arm_denied_item, azure_index)
assert azure_status == 'DENIED' and azure_evidence['reason'] == 'access_denied'
assert azure_evidence['operation'] == 'Microsoft.Web/sites:GET'
assert azure_evidence['provider_code'] == 'HTTP403'
print('PASS: Azure selected App Settings HTTP403 becomes DENIED with exact fixed identity operation')

k8s_check = importlib.import_module('peaso.checks.k8s_literal_configmap_association_evaluator')
k8s_cases = next(iter(json.loads((ROOT / 'peaso' / 'checks' /
    'k8s_literal_secret_review_20261020_fixtures.json').read_text()).values()))
k8s_index = deepcopy(k8s_cases['pass_index'])
k8s_index['context']['scope'] = 'team'
k8s_index['collections'][k8s_source.KIND][0]['scope'] = 'team'
k8s_index['collections'][k8s_source.KIND][0]['items'] = [k8s_denied_item]
k8s_index['collections'][k8s_source.KIND][0]['status'] = 'partial'
k8s_index['context']['metadata'].update(k8s_denied_metadata)
k8s_issues = discovery.native_denial_issues(k8s_source.KIND, k8s_source.MARKER,
    [k8s_denied_item], k8s_denied_metadata)
assert len(k8s_issues) == 1
k8s_index['context']['metadata']['automatic_workload_environment_batches'] = {
    k8s_source.KIND: [{'id': k8s_source.KIND + ':1', 'scope': 'team',
        'metadata': k8s_denied_metadata, 'ids': [k8s_denied_item['id']],
        'status': 'partial', 'error': {'code': 'selected_content_incomplete'}, 'issues': k8s_issues}]}
k8s_index['context']['metadata']['automatic_workload_environment_coverage'] = {
    k8s_source.KIND: {'complete': False}}
k8s_status, k8s_evidence = automatic_leaf(k8s_check, k8s_denied_item, k8s_index)
assert k8s_status == 'DENIED' and k8s_evidence['reason'] == 'access_denied'
assert k8s_evidence['operation'] == 'kubernetes:GET Pod'
assert k8s_evidence['provider_code'] == 'native_get_denied'
print('PASS: Kubernetes selected Pod native GET denial becomes DENIED without reading a Secret object')

# Scope partition preparation must accept two namespaces but never join or
# duplicate their batch identities across the scoped engine view.
team_a = deepcopy(k8s_index)
team_b = deepcopy(k8s_index)
other_item = deepcopy(k8s_denied_item)
other_item['id'] = k8s_source.KIND + ':' + 'b' * 64
other_item[k8s_source.MARKER]['identity'] = other_item['id']
other_item[k8s_source.MARKER]['scope'] = 'team-b'
other_collection = deepcopy(k8s_index['collections'][k8s_source.KIND][0])
other_collection['scope'] = 'team-b'
other_collection['items'] = [other_item]
other_batch = deepcopy(k8s_index['context']['metadata']['automatic_workload_environment_batches'][k8s_source.KIND][0])
other_batch['id'] = k8s_source.KIND + ':2'
other_batch['scope'] = 'team-b'
other_batch['ids'] = [other_item['id']]
other_batch['issues'] = {}
all_batches = deepcopy(k8s_index['context']['metadata']['automatic_workload_environment_batches'][k8s_source.KIND]) + [other_batch]
for scoped in (team_a, team_b):
    scoped['context']['metadata']['automatic_workload_environment_batches'] = {k8s_source.KIND: deepcopy(all_batches)}
team_b['context']['scope'] = 'team-b'
team_b['collections'][k8s_source.KIND] = [other_collection]
first = auto_adapter.prepare(team_a, k8s_source.CHECK)
second = auto_adapter.prepare(team_b, k8s_source.CHECK)
assert first['error'] is None and set(first['items']) == {k8s_denied_item['id']}
assert second['error'] is None and set(second['items']) == {other_item['id']}
team_b['context']['metadata']['automatic_workload_environment_batches'][k8s_source.KIND][1]['ids'] = [k8s_denied_item['id']]
assert auto_adapter.prepare(team_b, k8s_source.CHECK)['error'] is not None
print('PASS: two Kubernetes namespaces prepare independently and cross-scope duplicate binding is rejected')

class ConfigArmTransport(ArmTransport):
    verified_tenant = '22222222-2222-2222-2222-222222222222'
    tenant = verified_tenant
class ConfigArmReader(ArmReader):
    def __init__(self):
        super().__init__()
        self.configuration_secret_redactions = set()
config_arm_target = {'surface': 'aci_literals', 'resource_id': aci}
class DeniedConfigConnection:
    sock = None
    def __init__(self, host, timeout):
        assert host == 'management.azure.com' and 0 < timeout <= 10
    def set_debuglevel(self, level):
        assert level == 0
    def request(self, method, route, body=None, headers=None):
        assert method == 'GET' and route.startswith(aci + '?api-version=')
    def getresponse(self):
        return ArmResponse({}, status=403)
    def close(self):
        pass
original_config_connection = azure_config.http.client.HTTPSConnection
azure_config.http.client.HTTPSConnection = DeniedConfigConnection
try:
    config_arm_reader = ConfigArmReader()
    config_arm_receipts = []
    config_capture = 'arm-config-capture:' + '1' * 32
    config_arm_item = azure_config._scan(config_arm_reader, ConfigArmTransport(),
        config_arm_target, subscription, {'deadline': time.monotonic() + 60,
            'bytes': 0, 'calls': 0, 'capture': config_capture}, config_arm_receipts)
finally:
    azure_config.http.client.HTTPSConnection = original_config_connection
assert config_arm_reader.calls == 1 and len(config_arm_receipts) == 1
config_arm_kind = azure_config.KIND
config_arm_meta = {config_arm_kind + '_authorized': True,
    config_arm_kind + '_selection': {subscription: [config_arm_item['id']]},
    config_arm_kind + '_capture': config_capture,
    config_arm_kind + '_receipts': config_arm_receipts}
config_arm_issues = discovery.native_denial_issues(config_arm_kind,
    azure_config.MARKER, [config_arm_item], config_arm_meta)
config_arm_index = deepcopy(azure_cases['pass_index'])
config_arm_index['collections'][config_arm_kind] = [{
    'type': config_arm_kind, 'scope': subscription, 'service': 'Microsoft.Resources',
    'status': 'collected', 'items': [config_arm_item], '_provenance': {}}]
config_arm_index['context']['metadata'].update(config_arm_meta)
config_arm_index['context']['metadata']['automatic_workload_environment_batches'] = {
    config_arm_kind: [{'id': config_arm_kind + ':1', 'scope': subscription,
        'metadata': config_arm_meta, 'ids': [config_arm_item['id']],
        'status': 'collected', 'error': None, 'issues': config_arm_issues}]}
config_arm_index['context']['metadata']['automatic_workload_environment_coverage'] = {
    config_arm_kind: {'complete': False}}
config_arm_check = importlib.import_module('peaso.checks.azure_selected_configuration_secret_review_20261020')
config_arm_status, config_arm_evidence = automatic_leaf(config_arm_check, config_arm_item, config_arm_index)
assert config_arm_status == 'DENIED' and config_arm_evidence['reason'] == 'access_denied'
assert config_arm_evidence['operation'] == 'Microsoft.ContainerInstance/containerGroups:GET'
assert config_arm_evidence['provider_code'] == 'HTTP403'
print('PASS: Azure ACI native HTTP403 becomes DENIED with exact Microsoft.ContainerInstance GET operation')
