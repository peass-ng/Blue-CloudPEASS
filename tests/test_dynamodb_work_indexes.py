"""Index candidates never replace strongly consistent, fenced job authority."""
import boto3
import pytest
from botocore.exceptions import ClientError

from peaso.storage.dynamodb import DynamoStore, attrs
from peaso.storage.sqlite import StoreError


def test_batch_get_retries_only_unprocessed_keys_and_remains_consistent(monkeypatch):
    keys = [{'PK': 'workspace/one', 'SK': 'meta/current'}, {'PK': 'workspace/two', 'SK': 'meta/current'}]

    class Client:
        calls = []

        def batch_get_item(self, **arguments):
            self.calls.append(arguments)
            assert arguments['RequestItems']['table']['ConsistentRead'] is True
            if len(self.calls) == 1:
                return {'Responses': {'table': [attrs(dict(keys[0], name='One'))]},
                        'UnprocessedKeys': {'table': {'Keys': [attrs(keys[1])]}}}
            assert arguments['RequestItems']['table']['Keys'] == [attrs(keys[1])]
            return {'Responses': {'table': [attrs(dict(keys[1], name='Two'))]}}

    monkeypatch.setattr('peaso.storage.dynamodb.time.sleep', lambda _: None)
    client = Client()
    result = DynamoStore('table', client)._get_many(keys + keys)
    assert len(result) == 2 and len(client.calls) == 2


def test_unprocessed_reads_fail_instead_of_returning_partial_membership(monkeypatch):
    class Client:
        def batch_get_item(self, **arguments):
            return {'UnprocessedKeys': arguments['RequestItems']}

    monkeypatch.setattr('peaso.storage.dynamodb.time.sleep', lambda _: None)
    with pytest.raises(StoreError) as error:
        DynamoStore('table', Client())._get_many([{'PK': 'workspace/one', 'SK': 'member/user'}])
    assert error.value.status == 503


def test_stale_index_cannot_dispatch_a_completed_or_deleted_job():
    class Client:
        def query(self, **arguments):
            assert arguments['IndexName'] == 'work-state'
            return {'Items': [attrs({'PK': 'tenant/owner', 'SK': 'job/done'}),
                              attrs({'PK': 'tenant/owner', 'SK': 'job/deleted'})]}

        def batch_get_item(self, **arguments):
            assert arguments['RequestItems']['table']['ConsistentRead'] is True
            return {'Responses': {'table': [attrs({'PK': 'tenant/owner', 'SK': 'job/done',
                        'kind': 'job', 'status': 'completed'})]}}

    assert DynamoStore('table', Client(), work_state_index='work-state').queued_jobs() == []


def test_missing_index_during_rollout_uses_original_strong_scan():
    class Client:
        def query(self, **arguments):
            raise ClientError({'Error': {'Code': 'ResourceNotFoundException'}}, 'Query')

        def scan(self, **arguments):
            assert arguments['ConsistentRead'] is True
            return {'Items': [attrs(dict(PK='tenant/owner', SK='job/queued', kind='job',
                                         id='queued', status='queued', created=1))]}

    assert DynamoStore('table', Client(), work_state_index='work-state').queued_jobs()[0]['id'] == 'queued'


def test_batch_permission_rollout_falls_back_to_strong_gets():
    class Client:
        attempts = 0

        def batch_get_item(self, **arguments):
            self.attempts += 1
            raise ClientError({'Error': {'Code': 'AccessDeniedException'}}, 'BatchGetItem')

        def get_item(self, **arguments):
            assert arguments['ConsistentRead'] is True
            return {'Item': dict(arguments['Key'], role={'S': 'read'})}

    client = Client()
    store = DynamoStore('table', client)
    key = {'PK': 'workspace/one', 'SK': 'member/user'}
    assert store._get_many([key])[key['PK'], key['SK']]['role'] == 'read'
    assert store._get_many([key])[key['PK'], key['SK']]['role'] == 'read'
    assert client.attempts == 1


def test_real_index_queries_match_scan_results_and_claim_fences(monkeypatch):
    moto = pytest.importorskip('moto')
    with moto.mock_aws():
        client = boto3.client('dynamodb', region_name='us-east-1')
        client.create_table(TableName='table', BillingMode='PAY_PER_REQUEST',
            KeySchema=[{'AttributeName': 'PK', 'KeyType': 'HASH'}, {'AttributeName': 'SK', 'KeyType': 'RANGE'}],
            AttributeDefinitions=[{'AttributeName': name, 'AttributeType': kind} for name, kind in
                                  (('PK', 'S'), ('SK', 'S'), ('status', 'S'), ('created', 'N'), ('kind', 'S'), ('next_run', 'N'))],
            GlobalSecondaryIndexes=[{'IndexName': name, 'KeySchema': [
                {'AttributeName': partition, 'KeyType': 'HASH'}, {'AttributeName': sort, 'KeyType': 'RANGE'}],
                'Projection': {'ProjectionType': 'KEYS_ONLY'}} for name, partition, sort in
                (('work-state', 'status', 'created'), ('schedule-time', 'kind', 'next_run'))])
        old = DynamoStore('table', client, work_state_index='', schedule_time_index='')
        new = DynamoStore('table', client, work_state_index='work-state', schedule_time_index='schedule-time')
        for ident, status, created, queued in [('done', 'completed', 1, 1), ('later', 'queued', 2, 20), ('first', 'queued', 3, 10)]:
            old._put('owner', 'job', ident, dict(id=ident, tenant='owner', status=status, created=created,
                     queued_at=queued, owner=None, lease=None, deadline=10000, admitted_at=1))
        for ident, enabled, due in [('due', True, 10), ('future', True, 1000), ('disabled', False, 1)]:
            old._put('owner', 'schedule', ident, dict(id=ident, tenant='owner', enabled=enabled, next_run=due))
        assert new.queued_jobs() == old.queued_jobs()
        assert new.due_schedules(100) == old.due_schedules(100)
        monkeypatch.setattr(new, '_scan', lambda _: pytest.fail('indexed path scanned the table'))
        job = new.claim('collector', now=100)
        assert job['id'] == 'first'
        assert [item['id'] for item in new.queued_jobs()] == ['later']
        assert [item['id'] for item in new.due_schedules(100)] == ['due']
        new.expire(now=20000)
        assert new.queued_jobs() == []
        for ident, queued in [('older', 10), ('newer', 20)]:
            old._put('owner', 'job', ident, dict(id=ident, tenant='owner', status='queued',
                     created=queued, queued_at=queued, owner=None, lease=None, deadline=30000))
        monkeypatch.setattr(new, '_index_candidates', lambda *args: [new.job('owner', 'newer')])
        monkeypatch.setattr(new, '_scan', old._scan)
        assert [item['id'] for item in new.queued_jobs()] == ['newer']
        assert new.admit('owner', 'newer', now=20001) is False
