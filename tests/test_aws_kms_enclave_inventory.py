"""KMS applicability metadata collection retains pagination and failure evidence."""
from types import SimpleNamespace
import pytest
from botocore.exceptions import ClientError
from peaso.collectors import aws
from peaso.collectors.aws_kms_enclave_inventory import enrich_key_inventory
from peaso.checks.aws_kms_enclave_review_20261019 import enforced


class Client:
    def __init__(self, fail=None):
        self.fail = fail
        self.calls = []
    def can_paginate(self, operation):
        return True
    def get_paginator(self, operation):
        return SimpleNamespace(_pagination_cfg={'input_token': 'Marker', 'output_token': 'NextMarker', 'more_results': 'Truncated'})
    def list_aliases(self, **kwargs):
        self.calls.append(('list_aliases', kwargs))
        if self.fail == 'aliases':
            raise ClientError({'Error': {'Code': 'AccessDeniedException', 'Message': 'not retained'}}, 'ListAliases')
        if not kwargs:
            return {'Aliases': [{'AliasName': 'alias/other', 'TargetKeyId': 'other'}], 'Truncated': True, 'NextMarker': 'next'}
        return {'Aliases': [{'AliasName': 'alias/enclave-1', 'TargetKeyId': 'key-1'}, {'AliasName': 'alias/unassigned'}], 'Truncated': False}
    def list_resource_tags(self, **kwargs):
        self.calls.append(('list_resource_tags', kwargs))
        if self.fail == 'tags':
            raise ClientError({'Error': {'Code': 'AccessDeniedException', 'Message': 'not retained'}}, 'ListResourceTags')
        return {'Tags': [], 'Truncated': False}
    def describe_key(self, **kwargs):
        return {'KeyMetadata': {'KeyManager': 'CUSTOMER', 'KeyState': 'Enabled', 'Description': 'ordinary'}}
    def get_key_rotation_status(self, **kwargs):
        return {'KeyRotationEnabled': True}
    def get_key_policy(self, **kwargs):
        return {'Policy': {'Statement': [{'Effect': 'Allow', 'Principal': '*', 'Action': 'kms:Decrypt', 'Resource': '*'}]}}


def requests(monkeypatch, fail=None, **options):
    client = Client(fail)
    session = SimpleNamespace(client=lambda *args, **kwargs: client)
    # Central admission belongs to coordinator. Exercise real request guard/cache
    # with these specific read actions without modifying the production allowlist.
    monkeypatch.setattr(aws, 'READ_ACTIONS', aws.READ_ACTIONS | {('kms', 'list_aliases'), ('kms', 'list_resource_tags')})
    return aws.Requests({'retry_attempts': 1, **options}), session, client


def test_account_alias_pages_cached_once_and_filtered_per_key(monkeypatch):
    request, session, client = requests(monkeypatch)
    one = enrich_key_inventory(request, session, 'us-east-1', {'KeyId': 'key-1'})
    two = enrich_key_inventory(request, session, 'us-east-1', {'KeyId': 'key-2'})
    assert one['Aliases'] == [{'AliasName': 'alias/enclave-1', 'TargetKeyId': 'key-1'}]
    assert two['Aliases'] == []
    assert one['_coverage']['Aliases']['status'] == 'collected'
    assert sum(op == 'list_aliases' for op, params in client.calls) == 2  # two pages total, not per key
    assert request.cache_hits >= 2


@pytest.mark.parametrize('failed,field', [('aliases', 'Aliases'), ('tags', 'Tags')])
def test_denied_inventory_not_converted_to_empty(monkeypatch, failed, field):
    request, session, client = requests(monkeypatch, failed)
    item = enrich_key_inventory(request, session, 'us-east-1', {'KeyId': 'key-2'})
    assert item['_coverage'][field]['status'] == 'denied'
    assert item['_coverage'][field]['error']['code'] == 'AccessDeniedException'
    item.update(Metadata={'KeyMetadata': {'KeyManager': 'CUSTOMER', 'KeyState': 'Enabled', 'Description': 'ordinary'}},
        Policy={'Policy': {'Statement': [{'Effect': 'Allow', 'Principal': '*', 'Action': 'kms:Decrypt', 'Resource': '*'}]}})
    assert enforced(item)[0] == 'UNKNOWN'


def test_truncated_alias_inventory_stays_partial(monkeypatch):
    request, session, client = requests(monkeypatch, max_pages=1)
    item = enrich_key_inventory(request, session, 'us-east-1', {'KeyId': 'key-1'})
    assert item['_coverage']['Aliases']['status'] == 'partial'
    assert item['_coverage']['Aliases']['error']['code'] == 'page_limit'


def test_kms_branch_preserves_metadata_and_policy_and_adds_inventory(monkeypatch):
    request, session, client = requests(monkeypatch)
    rows = aws._enrich(request, session, 'us-east-1', 'kms_key', [{'KeyId': 'key-1'}])
    assert len(rows) == 1
    item = rows[0]
    assert item['Metadata']['KeyMetadata']['KeyState'] == 'Enabled'
    assert item['Policy']['Policy']['Statement'][0]['Action'] == 'kms:Decrypt'
    assert item['Aliases'][0]['AliasName'] == 'alias/enclave-1'
    assert enforced(item)[0] == 'FAIL'
