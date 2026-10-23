"""Fresh, tenant-bound cancellation reads without large job payloads."""
import pytest
from peaso.storage import SQLiteStore, StoreError


@pytest.fixture(params=['sqlite', 'dynamodb'])
def store(request, tmp_path):
    if request.param == 'sqlite':
        yield SQLiteStore(tmp_path / 'state')
        return
    moto = pytest.importorskip('moto')
    import boto3
    from peaso.storage.dynamodb import DynamoStore
    with moto.mock_aws():
        client = boto3.client('dynamodb', region_name='us-east-1')
        client.create_table(TableName='jobs', BillingMode='PAY_PER_REQUEST',
            KeySchema=[{'AttributeName': key, 'KeyType': kind} for key, kind in [('PK', 'HASH'), ('SK', 'RANGE')]],
            AttributeDefinitions=[{'AttributeName': key, 'AttributeType': 'S'} for key in ['PK', 'SK']])
        yield DynamoStore('jobs', client)


def test_fresh_control_state_matches_full_job_and_excludes_payload(store):
    connector = store.add_connector('alice', {'provider': 'aws'}, 'encrypted-fixture')
    job = store.enqueue('alice', {'connector_id': connector['id']})
    ident = job['id']
    assert store.job_control('alice', ident)['status'] == store.job('alice', ident)['status']
    store.admit('alice', ident)
    claim = store.claim('collector', tenant='alice', ident=ident)
    assert claim
    control = store.job_control('alice', ident)
    assert control['status'] == 'collecting'
    assert set(control) <= {'status', 'expires_at'}
    assert store.cancel('alice', ident)
    assert store.job_control('alice', ident)['status'] == 'cancelled'
    for tenant, scan in [('bob', ident), ('alice', 'missing')]:
        with pytest.raises(StoreError) as exc:
            store.job_control(tenant, scan)
        assert exc.value.status == 404


def test_dynamo_projection_is_consistent_and_checks_ttl():
    from peaso.storage.dynamodb import DynamoStore, attrs
    class Client:
        def get_item(self, **kwargs):
            assert kwargs['ConsistentRead'] is True
            assert kwargs['ExpressionAttributeNames'] == {'#status': 'status', '#expires': 'expires_at'}
            assert kwargs['Key'] == attrs({'PK': 'tenant/alice', 'SK': 'job/one'})
            return {'Item': attrs({'status': 'collecting', 'expires_at': 10})}
    store = DynamoStore('jobs', Client())
    store.clock = lambda: 9
    assert store.job_control('alice', 'one')['status'] == 'collecting'
    store.clock = lambda: 10
    with pytest.raises(StoreError):
        store.job_control('alice', 'one')
