"""The new read dependency cannot silently replace an unreviewed predicate."""
from dataclasses import replace
import inspect
import pytest
from peaso.checks import CHECKS
from peaso.checks.azure_synapse_dependency_review_20261020 import CHECK_ID, BEFORE, AFTER, reviewed_check


def target():
    return next(c for c in CHECKS if c.id == CHECK_ID)


def test_successor_changes_only_declared_read_dependencies_and_is_idempotent():
    current=target();prior=replace(current,declared_dependencies=BEFORE)
    successor=reviewed_check(prior)
    assert successor==current and current.declared_dependencies==AFTER
    assert successor.evaluate is prior.evaluate
    assert inspect.getsource(successor.evaluate)==inspect.getsource(prior.evaluate)
    assert reviewed_check(current)==current
    assert replace(successor,declared_dependencies=BEFORE)==prior


@pytest.mark.parametrize('changes',[
 {'declared_dependencies':('unreviewed_evidence',)},
 {'provider':'aws'},{'kind':'vm'},{'target':'scope'},
])
def test_unreviewed_metadata_is_not_admitted(changes):
    with pytest.raises(ValueError,match='predecessor changed'):
        reviewed_check(replace(target(),**changes))


def unreviewed(item,index):
    return 'PASS',{}


def test_changed_predicate_is_not_admitted():
    with pytest.raises(ValueError,match='predicate source changed'):
        reviewed_check(replace(target(),evaluate=unreviewed))
