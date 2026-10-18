"""Bounded independent alias I/O and shared unread Future, without network."""
from collections import Counter
from copy import deepcopy
from threading import Barrier, Event, Lock, get_ident
from types import SimpleNamespace
import pytest

from tests.test_peaso_aws_bedrock_reasoning_native import (
    fixtures, AGENT, ALIAS, ALIAS_ARN, ACCOUNT, REGION,
)
from peaso.collectors import aws, aws_bedrock_reasoning_native as native


@pytest.mark.parametrize('layout', ['one_agent_three_aliases', 'two_agents_one_alias_each'])
def test_two_workers_overlap_alias_reads_preserve_order_and_share_unread_future(monkeypatch, layout):
    agents, aliases, alias, version, guardrail = fixtures('pass')
    ids = [ALIAS, 'BCDEFGHIJK', 'CDEFGHIJKL']
    seed = aliases['agentAliasSummaries'][0]
    aliases['agentAliasSummaries'] = [{**seed, 'agentAliasId': identifier} for identifier in ids]
    if layout == 'two_agents_one_alias_each':
        agents['agentSummaries'].append({**agents['agentSummaries'][0], 'agentId': 'F6G7H8I9J0'})
        aliases['agentAliasSummaries'] = [deepcopy(seed)]
    agent_ids = [row['agentId'] for row in agents['agentSummaries']]
    expected_order = [(aid, row['agentAliasId']) for aid in agent_ids for row in aliases['agentAliasSummaries']]
    watched = 'get_agent_version' if len(agent_ids) == 1 else 'get_guardrail'
    barrier, backend_entered, second_entered = Barrier(2), Event(), Event()
    lock, counts, threads = Lock(), Counter(), set()
    state = {'active': 0, 'peak': 0, 'version_dispatches': 0, 'unread_seen': False}
    class Client:
        def can_paginate(self, operation): return False
        def list_agents(self):
            counts['list_agents'] += 1; return deepcopy(agents)
        def list_agent_aliases(self, agentId):
            assert agentId in agent_ids
            counts['list_agent_aliases'] += 1; return deepcopy(aliases)
        def get_agent_alias(self, agentId, agentAliasId):
            assert agentId in agent_ids
            with lock:
                counts['get_agent_alias'] += 1; ordinal = counts['get_agent_alias']
                state['active'] += 1; state['peak'] = max(state['peak'], state['active'])
                threads.add(get_ident())
            try:
                if ordinal <= 2: barrier.wait(timeout=3)
                value = deepcopy(alias)
                value['agentAlias']['agentId'] = agentId
                value['agentAlias']['agentAliasId'] = agentAliasId
                value['agentAlias']['agentAliasArn'] = ALIAS_ARN.replace(AGENT, agentId).replace(ALIAS, agentAliasId)
                return value
            finally:
                with lock: state['active'] -= 1
        def get_agent_version(self, agentId, agentVersion):
            assert agentId in agent_ids and agentVersion == '1'
            counts['get_agent_version'] += 1
            if watched == 'get_agent_version':
                backend_entered.set()
                assert second_entered.wait(timeout=3)
            value = deepcopy(version)
            value['agentVersion']['agentId'] = agentId
            value['agentVersion']['agentArn'] = value['agentVersion']['agentArn'].replace(AGENT, agentId)
            return value
        def get_guardrail(self, guardrailIdentifier, guardrailVersion):
            assert guardrailVersion == '1'
            counts['get_guardrail'] += 1
            if watched == 'get_guardrail':
                backend_entered.set()
                assert second_entered.wait(timeout=3)
            return deepcopy(guardrail)
        def get_automated_reasoning_policy(self, policyArn):
            counts['get_automated_reasoning_policy'] += 1
            return {'policyArn': policyArn, 'policyId': policyArn.rsplit('/', 1)[1].split(':')[0],
                'version': '1', 'definitionHash': 'a' * 128, 'name': 'Policy', 'updatedAt': fixtures('pass')[0]['agentSummaries'][0]['updatedAt']}
    client = Client()
    monkeypatch.setattr(aws.Requests, 'client', lambda self, session, service, region: client)
    original = aws.Requests.call
    def observed(self, session, service, region, operation, **arguments):
        if operation == watched:
            with lock:
                state['version_dispatches'] += 1; ordinal = state['version_dispatches']
            if ordinal == 2:
                assert backend_entered.wait(timeout=3)
                with self._lock:
                    state['unread_seen'] = any(key[3] == operation and not future.done()
                        for key, future in self._cache.items())
                second_entered.set()
        return original(self, session, service, region, operation, **arguments)
    monkeypatch.setattr(aws.Requests, 'call', observed)
    reader = aws.Requests({'service_concurrency': 2, 'retry_attempts': 1})
    session = SimpleNamespace(get_partition_for_region=lambda region: 'aws')
    read = native.collect(reader, session, REGION, ACCOUNT)
    assert read.status == 'collected' and len(read.items) == len(expected_order)
    assert [(row['NativeAgentId'], row['NativeAliasId']) for row in read.items] == expected_order
    assert all(native.assess(row, ACCOUNT, REGION)[0] == 'PASS' for row in read.items)
    assert state['peak'] == 2 and len(threads) <= 2 and state['unread_seen']
    assert counts == {'list_agents': 1, 'list_agent_aliases': len(agent_ids), 'get_agent_alias': len(expected_order),
        'get_agent_version': len(agent_ids), 'get_guardrail': 1, 'get_automated_reasoning_policy': 1}
    assert reader.calls == sum(counts.values())
    assert reader.cache_hits == (6 if len(agent_ids) == 1 else 2)
