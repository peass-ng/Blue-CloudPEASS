"""Single-check native default-retention evaluator for a reviewed integration.

The signed SW23 predicate accepts Locked and Unlocked positive default policies.
This module deliberately leaves registry and presentation metadata untouched.
"""
from dataclasses import replace
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace
import inspect

from peaso.checks import CHECKS, result, unknown
from peaso.checks.facts import Unavailable, get

CHECK_ID = 'azure_storage_account_10_3_4_7_02943e9'
SOURCE_SHA256 = '43074e9025001581fb2e0f99b65c8d17ef2f6deb1b0cd62216535ffac4800bdd'
SOURCE_OPERATION = 'storageAccounts.GET+containers.LIST/GET+immutabilityPolicies.GET'
TITLE = 'Blob containers have an effective default retention policy'
REMEDIATION = ('Configure a default retention period for containers without one. '
               'Lock the policy when retention must not be shortened or removed.')
DESCRIPTION = ('Reads each container and its account or container default policy to check '
               'whether new writes inherit a positive retention period. '
               'Unlocked policies satisfy this configuration check but can still be changed.')


# SW23 is bootstrap-executed from a source loader, not importable a second time:
# re-executing it would duplicate every signed check. Bind its reviewed helpers
# through the already registered function and verify the exact source below.
_registered = next(c for c in CHECKS if c.id == CHECK_ID)
_signed_function = inspect.unwrap(_registered.evaluate)
source = SimpleNamespace(**_signed_function.__globals__)


def reviewed_source():
    """Fail closed if the signed helpers used below change before review."""
    source_file = Path(inspect.getsourcefile(_signed_function))
    if sha256(source_file.read_bytes()).hexdigest() != SOURCE_SHA256:
        raise RuntimeError('SW23 signed source changed; review native successor again')
    matches = [c for c in CHECKS if c.id == CHECK_ID]
    if len(matches) != 1 or matches[0].declared_dependencies != (
        'storage_account', 'storage_immutability_evidence'
    ):
        raise RuntimeError('SW23 check identity or dependencies changed')
    return matches[0]


def _native_evidence(item, index):
    parent = source._own(item, index, 'storage_account')
    rows = source._inventory(index, 'storage_immutability_evidence')
    found = []
    accounts = source._inventory(index, 'storage_account')
    for row in rows.values():
        pid = get(row, 'parent_id', str).casefold()
        rid = get(row, 'id', str).casefold()
        if not rid.startswith(pid + '/complianceevidence/') or pid not in accounts:
            raise Unavailable('native evidence identity or parent invalid')
        if pid == parent:
            found.append(row)
    if len(found) != 1:
        raise Unavailable('native evidence absent or ambiguous')
    row = found[0]
    proof = get(row, '_provenance', dict)
    if get(proof, 'schema_version', int) != 1:
        raise Unavailable('native evidence version unsupported')
    source._require(proof, 'read_only', 'complete')
    if get(proof, 'source_operation', str) != SOURCE_OPERATION:
        raise Unavailable('native source operation differs')
    context, _ = source._context(index)
    if source._time(get(proof, 'captured_at', str)) != source._time(get(context, 'created_at', str)):
        raise Unavailable('native evidence instant differs')
    payload = get(row, 'payload', dict)
    source._validate_evidence(payload)
    return payload


def _evaluate(item, index):
    evidence = _native_evidence(item, index)
    source._require(evidence, 'account_read_complete')
    containers = source._containers(evidence, get(item, 'id', str))
    if not containers:
        return source._na('complete container inventory is empty')
    bad = []
    observed = []
    for container in containers:
        source._require(container, 'container_read_complete', 'default_version_policy_support_resolved')
        effective = get(container, 'effective_default_policy', dict)
        policy = source._immutability(effective)
        inherited = get(effective, 'new_writes_inherit', bool)
        if policy is not None:
            kind = get(effective, 'source_kind', str)
            source_id = get(effective, 'source_id', str).casefold()
            expected = {
                'container_time': get(container, 'id', str).casefold() + '/immutabilitypolicies/default',
                'container_version_default': get(container, 'id', str).casefold(),
                'account_version_default': get(item, 'id', str).casefold(),
            }
            if kind not in expected or source_id != expected[kind]:
                raise Unavailable('native policy source or inheritance unresolved')
        observed.append({'container_id': get(container, 'id', str),
                         'state': policy[0] if policy else 'Absent',
                         'retention_days': policy[1] if policy else 0,
                         'new_writes_inherit': inherited})
        if policy is None or policy[0] == 'Disabled' or policy[1] <= 0 or not inherited:
            bad.append(get(container, 'id', str))
    return result(bool(bad), containers_without_effective_default_retention=bad,
                  observed_default_policies=observed)


def evaluate(item, index):
    try:
        return _evaluate(item, index)
    except (Unavailable, KeyError, TypeError, ValueError, AttributeError, OverflowError):
        return unknown('complete source-bound native default-retention evidence unavailable')


def proposed_registry(registry):
    """Pure isolated public-engine adapter; no global registry mutation."""
    original = reviewed_source()
    if sum(check.id == CHECK_ID for check in registry) != 1:
        raise RuntimeError('one current native check required')
    return [replace(check, evaluate=evaluate, title=TITLE, remediation=REMEDIATION) if check.id == original.id else check
            for check in registry]


def observation(finding):
    """Render only this successor's measured rows, never infer a locked policy."""
    if not isinstance(finding, dict) or finding.get('check_id') != CHECK_ID:
        return None
    if finding.get('status') not in {'PASS', 'FAIL'}:
        return None
    evidence = finding.get('evidence')
    if not isinstance(evidence, dict):
        return None
    rows = evidence.get('observed_default_policies')
    bad = evidence.get('containers_without_effective_default_retention')
    if not isinstance(rows, list) or not rows or not isinstance(bad, list):
        return None
    seen = set()
    calculated_bad = []
    for row in rows:
        if not isinstance(row, dict):
            return None
        cid, state = row.get('container_id'), row.get('state')
        days, inherited = row.get('retention_days'), row.get('new_writes_inherit')
        if (not isinstance(cid, str) or not cid or cid in seen or
            state not in {'Locked', 'Unlocked', 'Disabled', 'Absent'} or
            type(days) is not int or days < 0 or type(inherited) is not bool):
            return None
        seen.add(cid)
        if state in {'Disabled', 'Absent'} or days == 0 or not inherited:
            calculated_bad.append(cid)
    if bad != calculated_bad or (finding['status'] == 'FAIL') != bool(bad):
        return None
    if bad:
        return ('New writes lack a positive inherited default retention policy in: '
                + ', '.join(bad) + '.')
    text = f'New writes inherit a positive default retention period in all {len(rows)} observed Blob containers.'
    if any(row['state'] == 'Unlocked' for row in rows):
        text += ' At least one default policy is unlocked and can still be changed.'
    return text
