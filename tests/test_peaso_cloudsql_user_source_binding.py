"""Bound inert Cloud SQL users.list rows before IAM database-user classification."""
import pytest

from peaso.engine import evaluate_snapshot
from peaso.collectors.gcp import ReadError
from tests.test_peaso_collectors_gcp import snapshot, collection
from peaso.snapshot import make_snapshot

CID = 'gcp.sql.iam_database_authentication'


def observed(*, user=None, denied=False):
    raw = {'name': 'iam-user', 'host': '%', 'type': 'CLOUD_IAM_USER'}
    raw.update(user or {})
    def resolve(request):
        if request['url'].endswith('/instances'):
            return {'items': [{'name': 'db', 'databaseVersion': 'MYSQL_8_0'}]}
        assert request['url'].endswith('/db/users')
        if denied:
            raise ReadError('denied', 'inert_users_denied')
        return {'items': [raw]}
    captured, transport = snapshot(['sql_instance'], resolve)
    assert len(transport.requests) == 2
    assert all(request['method'] == 'GET' for request in transport.requests)
    findings = [f for f in evaluate_snapshot(captured, checks=[CID], include_not_applicable=True)['findings']
                if f['check_id'] == CID]
    assert len(findings) == 1
    return findings[0]['status'], captured


@pytest.mark.parametrize('field,value', [
    ('instance', 'another-db'), ('project', 'another-project'),
    ('instance', 42), ('project', 42),
])
def test_foreign_or_malformed_raw_user_binding_cannot_prove_iam_user(field, value):
    verdict, captured = observed(user={field: value})
    assert verdict == 'UNKNOWN'
    assert collection(captured, 'sql_instance')['coverage_status'] in ('collected', 'partial', 'malformed')


def test_exact_raw_project_instance_binding_is_admitted():
    verdict, captured = observed(user={'instance': 'db', 'project': 'p-one'})
    assert verdict == 'PASS'
    assert collection(captured, 'sql_instance')['items'][0]['usersList']['status'] == 'collected'


def test_omitted_optional_project_instance_fields_preserve_current_collection():
    assert observed()[0] == 'PASS'


def test_denied_users_inventory_cannot_certify_iam_user():
    assert observed(denied=True)[0] == 'UNKNOWN'


@pytest.mark.parametrize('field,value', [('instance', 'elsewhere'), ('project', 'foreign')])
def test_imported_snapshot_cannot_bypass_raw_user_identity(field, value):
    row = {'name': 'db', 'databaseVersion': 'MYSQL_8_0',
           '_provenance': {'scope': 'projects/p-one'},
           'usersList': {'status': 'collected', 'instance': 'db', 'items': [
               {'name': 'iam-user', 'type': 'CLOUD_IAM_USER', 'instanceId': 'db', field: value}]}}
    captured = make_snapshot('gcp', ['projects/p-one'], [
        {'type': 'sql_instance', 'scope': 'projects/p-one', 'status': 'collected', 'items': [row]}])
    findings = [f for f in evaluate_snapshot(captured, checks=[CID])['findings'] if f['check_id'] == CID]
    assert len(findings) == 1 and findings[0]['status'] == 'UNKNOWN'
