"""Pure unregistered index consumer; no collector/key/scanner/registry imports."""
from copy import deepcopy
from peaso import azure_function_package_portable_20261020 as portable

KIND = portable.KIND
CHECK = 'azure.review.function.selected_package_source_secret_indicators'
DECLARATION = {'id': CHECK, 'kind': KIND, 'provider': 'azure', 'severity': 'high',
    'finding_type': 'secrets', 'ui_group': 'Secrets', 'requirements': [],
    'dependencies': [KIND], 'allow_incomplete_failure': True,
    'title': 'Selected configured deployment package source has no detected secrets',
    'remediation': 'Remove exposed literals, rotate confirmed exposed credentials, and rebuild with managed identities or supported secret references.'}


def build_index(snapshot, *, scope, expected_index_context):
    """Validate a package slice; expected context is separately owner-admitted.

    The owner hands this exact slice from the finalized union to its normal
    index layer. Do not synthesize expected context from supplied metadata.
    """
    portable.validate_snapshot(snapshot, expected_index_context)
    portable.require(scope in expected_index_context['scopes'])
    return {'context': {'provider': 'azure', 'scope': scope},
            'collections': {KIND: deepcopy(snapshot['collections'])},
            'package_snapshot': deepcopy(snapshot)}


def evaluate(item, index, *, expected_index_context):
    """Public item/index-shaped entrypoint with an explicit independent context."""
    try:
        portable.bounded(index)
        portable.require(set(index) == {'context', 'collections', 'package_snapshot'}
            and set(index['context']) == {'provider', 'scope'}
            and index['context']['provider'] == 'azure'
            and set(index['collections']) == {KIND}
            and index['collections'][KIND] == index['package_snapshot']['collections'])
        scope = index['context']['scope']
        portable.require(scope in expected_index_context['scopes']
                         and item['identity'] in expected_index_context['selection'][scope])
        rows = [row for c in index['collections'][KIND] if c['scope'] == scope for row in c['items']]
        portable.require(sum(row == item for row in rows) == 1)
        return portable.evaluate(index['package_snapshot'], item['identity'], expected_index_context=expected_index_context)
    except (KeyError, TypeError, ValueError, AttributeError, IndexError, UnicodeError, OverflowError):
        return portable.evaluate({}, '', expected_index_context=expected_index_context)
