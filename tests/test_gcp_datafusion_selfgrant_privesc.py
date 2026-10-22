"""Policy self-grants require exact policy control and a runnable code path."""

from peaso import privesc
from tests.test_gcp_datafusion_pipeline_privesc import RUNNER, case


ENTRY = next(row for row in privesc.catalog()['entries']
             if row['id'] == 'gcp-datafusion-setiampolicy-self-grant')


def result(**kwargs):
    return case(entry=ENTRY, namespace_rights=False, **kwargs)


def test_instance_or_namespace_policy_write_reaches_exact_runner():
    expected = [('serviceAccount:' + RUNNER, 'conditional')]
    assert result(instance_write=True) == expected
    assert result(namespace_write=True) == expected
    assert result(instance_write=True, instance_get=False) == expected
    assert result(instance_write=True, external=True) == [
        ('serviceAccount:runner@p2.iam.gserviceaccount.com', 'conditional')]


def test_unusable_policy_grant_or_runtime_does_not_create_positive_path():
    assert result() == []
    assert result(instance_write=True, plugin=False) == []
    assert result(instance_write=True, code=False) == []
    assert result(instance_write=True, profile=False) == []
    assert result(namespace_write=True, rbac=False) == []
    assert result(instance_write=True, writer_condition=
                  'resource.name.startsWith("projects/p9/")') == []
    assert result(instance_write=True, deny_instance_write=True) == []


def test_namespace_accessor_ambiguity_and_incomplete_inventory_are_unknown():
    assert result(namespace_write=True, instance_get=False)[0][1] == 'unknown'
    assert result(instance_write=True, missing_inventory=True)[0][1] == 'unknown'
    assert result(instance_write=True, agent_actas=False)[0][1] == 'unknown'
