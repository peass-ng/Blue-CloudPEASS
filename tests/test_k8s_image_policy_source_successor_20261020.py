"""Literal source compliance and immutable-image security are distinct criteria."""
from copy import deepcopy
import pytest
from tests import test_k8s_workloads_native_review_20261020 as native
from tests.test_k8s_workloads_native_review_20261020 import hard_network_auth_guard

@pytest.mark.parametrize('kind',sorted(native.KINDS))
@pytest.mark.parametrize('predicate',['always_pull','content_digest_or_always_pull'])
@pytest.mark.parametrize('mode',['explicit_always','digest_if_not_present','untagged_missing_policy','mutable_if_not_present'])
def test_native_literal_policy_and_content_pin_keep_distinct_results(kind,predicate,mode):
    spec=native.configured(predicate);container=spec['containers'][0]
    if mode=='explicit_always':container.update(image='registry.example.test/team/web:v2',imagePullPolicy='Always')
    elif mode=='digest_if_not_present':container.update(image='registry.example.test/team/web@sha256:'+'a'*64,imagePullPolicy='IfNotPresent')
    elif mode=='untagged_missing_policy':container.update(image='registry.example.test/team/web');container.pop('imagePullPolicy',None)
    else:container.update(image='registry.example.test/team/web:v2',imagePullPolicy='IfNotPresent')
    cid='k8s.ports.'+kind+'.'+predicate
    statuses,_=native.run(cid,'source-successor-'+mode,spec=deepcopy(spec))
    expected='PASS'if mode=='explicit_always'or predicate=='content_digest_or_always_pull'and mode in('digest_if_not_present','untagged_missing_policy')else'FAIL'
    assert statuses==[expected]
