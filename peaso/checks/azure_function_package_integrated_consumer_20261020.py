"""Two-argument normal check over owner-admitted portable native facts."""
from copy import deepcopy
from peaso import azure_function_package_index_20261020 as owner
from peaso import azure_function_package_portable_20261020 as contract
from . import azure_function_package_runtime_consumer_20261020 as predecessor

CHECK, KIND = predecessor.CHECK, predecessor.KIND
DECLARATION = dict(predecessor.DECLARATION, category='hardening', control='security_configuration')


def evaluate(item, index):
    try:
        admitted = index[owner.INDEX_KEY]
        contract.require(type(admitted) in (owner._Admitted, owner._Assertions)
            and index['context']['provider'] == 'azure'
            and index['context']['scope'] == admitted.scope
            and index['context']['metadata'][KIND] == admitted.snapshot['metadata'][KIND])
        collections = [c for c in admitted.snapshot['collections'] if c['scope'] == admitted.scope]
        contract.require(index['collections'][KIND] == collections)
        scoped = predecessor.build_index(admitted.snapshot, scope=admitted.scope,
                                        expected_index_context=admitted.expected)
        status, evidence = predecessor.evaluate(item, scoped, expected_index_context=admitted.expected)
        return status, dict(evidence, context_provenance=('native_owner_retained_context'
            if type(admitted) is owner._Admitted else 'supplied_snapshot_assertions'))
    except (KeyError, TypeError, ValueError, AttributeError, IndexError):
        return contract.evaluate({}, '', expected_index_context={})
