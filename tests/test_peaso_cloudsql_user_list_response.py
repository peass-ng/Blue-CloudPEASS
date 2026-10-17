"""Malformed SQL users responses cannot certify absence of IAM users."""
import pytest
from peaso.engine import evaluate_snapshot
from tests.test_peaso_collectors_gcp import snapshot

CID = 'gcp.sql.iam_database_authentication'
USER = {'name': 'iam-user', 'host': '%', 'type': 'CLOUD_IAM_USER'}


@pytest.mark.parametrize('payload,expected', [
    ({}, 'UNKNOWN'),
    ({'kind': 'sql#instancesList'}, 'UNKNOWN'),
    ({'kind': 'sql#instancesList', 'items': [USER]}, 'UNKNOWN'),
    ({'kind': None, 'items': [USER]}, 'UNKNOWN'),
    ({'kind': 'sql#usersList'}, 'FAIL'),
    ({'items': []}, 'FAIL'),
    ({'items': [USER]}, 'PASS'),
    ({'kind': 'sql#usersList', 'items': [USER]}, 'PASS'),
])
def test_normal_user_list_response_schema(payload, expected):
    def resolve(request):
        if request['url'].endswith('/instances'):
            return {'items': [{'name': 'db', 'databaseVersion': 'MYSQL_8_0'}]}
        assert request['url'].endswith('/db/users')
        return payload
    captured, transport = snapshot(['sql_instance'], resolve)
    findings = [f for f in evaluate_snapshot(captured, checks=[CID])['findings'] if f['check_id'] == CID]
    assert len(findings) == 1 and findings[0]['status'] == expected
    assert len(transport.requests) == 2
    assert all(r['method'] == 'GET' for r in transport.requests)
