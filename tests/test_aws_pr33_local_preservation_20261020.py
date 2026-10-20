"""Preserve the production label exception without exposing runtime content."""
import pytest
from peaso.collectors.aws import _safe

@pytest.mark.parametrize('labels',[{'Environment':'production'},{'environment':'production'}])
def test_scalar_classification_labels_survive(labels):
    assert _safe({'Tags':labels})['Tags']==labels

@pytest.mark.parametrize('value',[{'Variables':{'PASSWORD':'private-fixture'}},['private-fixture'],42,None])
def test_non_scalar_environment_tag_never_borrows_scalar_exception(value):
    assert 'Environment'not in _safe({'Tags':{'Environment':value}})['Tags']


def test_runtime_environment_is_still_omitted_and_credential_labels_redacted():
    raw={'Tags':{'Environment':'production','Password':'private-fixture','ApiToken':'private-fixture'},'Environment':{'Variables':{'PASSWORD':'private-fixture'}},'SecretAccessKey':'private-fixture'}
    projected=_safe(raw)
    assert projected['Tags']['Environment']=='production'
    assert 'Password'not in projected['Tags']
    assert projected['Tags']['ApiToken']=='[redacted]'
    assert 'Environment'not in projected and 'SecretAccessKey'not in projected
    assert 'private-fixture'not in str(projected)


def test_scalar_environment_outside_a_label_container_is_not_a_tag():
    assert _safe({'Environment':'private-fixture'})=={}
