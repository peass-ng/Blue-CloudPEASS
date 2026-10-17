"""Complete active-member OU paths using native Organizations read operations.

An incomplete account roster never authorizes subsequent traversal. Existing
Requests owns retries, budgets, pagination and the single-flight request cache.
"""
from concurrent.futures import ThreadPoolExecutor
import re

ACCOUNT = re.compile(r'[0-9]{12}')
OU = re.compile(r'ou-[0-9a-z]{4,32}-[0-9a-z]{8,32}')
ROOT = re.compile(r'r-[0-9a-z]{4,32}')
ACCOUNT_ARN = re.compile(r'arn:(aws(?:-[a-z0-9-]+)?):organizations::([0-9]{12}):account/(o-[0-9a-z]{10,32})/([0-9]{12})')
LEGACY = {'ACTIVE': 'ACTIVE', 'PENDING_ACTIVATION': 'ACTIVE', 'SUSPENDED': 'SUSPENDED',
          'CLOSED': 'SUSPENDED', 'PENDING_CLOSURE': 'PENDING_CLOSURE'}
MAX_DEPTH = 128
READ_ACTIONS = {('organizations', 'list_accounts'), ('organizations', 'list_parents'),
                ('organizations', 'describe_organizational_unit')}


def _invalid(code='organization_ou_native_invalid'):
    from .aws import ReadFailure
    raise ReadFailure('malformed', code)


def _state(row):
    coverage = row.get('_coverage', {})
    if not isinstance(coverage, dict):
        _invalid()
    if 'State' in row or 'State' in coverage:
        state = row.get('State')
        if (not isinstance(state, str) or state not in LEGACY or
                'Status' in row and row['Status'] != LEGACY[state]):
            _invalid('organization_account_state_invalid')
        if 'State' in coverage and (not isinstance(coverage['State'], dict) or coverage['State'].get('status') != 'collected'):
            _invalid('organization_account_state_unavailable')
        return state
    if 'Status' in coverage and (not isinstance(coverage['Status'], dict) or coverage['Status'].get('status') != 'collected'):
        _invalid('organization_account_status_unavailable')
    status = row.get('Status')
    if status not in ('ACTIVE', 'SUSPENDED', 'PENDING_CLOSURE'):
        _invalid('organization_account_status_invalid')
    return status


def _accounts(inventory, account):
    from .aws import ReadFailure
    status = inventory.get('status') if isinstance(inventory, dict) else getattr(inventory, 'status', None)
    rows = inventory.get('items') if isinstance(inventory, dict) else getattr(inventory, 'items', None)
    error = inventory.get('error') if isinstance(inventory, dict) else getattr(inventory, 'error', None)
    if status not in ('collected', 'empty'):
        raise ReadFailure(status if isinstance(status, str) and status in {'partial', 'denied', 'timeout', 'not_collected', 'malformed', 'unknown'} else 'unknown',
                          error.get('code', 'organization_account_inventory_incomplete') if isinstance(error, dict) else 'organization_account_inventory_incomplete')
    if error or not isinstance(rows, list) or (status == 'empty') != (not rows):
        _invalid('organization_account_inventory_invalid')
    found, active, authority = set(), [], None
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get('Id'), str) or not ACCOUNT.fullmatch(row['Id']) or row['Id'] in found:
            _invalid('organization_account_identity_invalid')
        arn = ACCOUNT_ARN.fullmatch(row.get('Arn', '')) if isinstance(row.get('Arn'), str) else None
        if not arn or arn[4] != row['Id']:
            _invalid('organization_account_arn_invalid')
        current = (arn[1], arn[2], arn[3])
        if authority is not None and current != authority:
            _invalid('organization_account_authority_conflict')
        authority = current
        found.add(row['Id'])
        if _state(row) == 'ACTIVE':
            active.append(row['Id'])
    if authority is None or account not in found or authority[1] not in found:
        _invalid('organization_account_roster_binding_invalid')
    return list(dict.fromkeys([account, authority[1], *sorted(active)])), authority


def _read_failure(read, code):
    from .aws import ReadFailure
    status = getattr(read, 'status', None)
    error = getattr(read, 'error', None)
    cause = error.get('cause_status', status) if isinstance(error, dict) else status
    raise ReadFailure(cause if isinstance(cause, str) and cause in {'denied', 'timeout', 'not_collected', 'malformed', 'unknown'} else 'unknown',
                      error.get('code', code) if isinstance(error, dict) else code)


def _path(requests, session, region, account, authority):
    from .aws import _failure
    partition, management, organization = authority
    child, path, seen, rows, failure = account, [account], {account}, [], None
    try:
        for _ in range(MAX_DEPTH):
            read = requests.pages(session, 'organizations', region, 'list_parents', 'Parents', ChildId=child)
            if read.status not in ('collected', 'empty'):
                _read_failure(read, 'organization_parent_visibility_incomplete')
            if not isinstance(read.items, list) or len(read.items) != 1 or not isinstance(read.items[0], dict):
                _invalid('organization_parent_missing_or_ambiguous')
            parent = read.items[0]
            pid, kind = parent.get('Id'), parent.get('Type')
            if (not isinstance(pid, str) or kind not in ('ROOT', 'ORGANIZATIONAL_UNIT') or
                    not (ROOT if kind == 'ROOT' else OU).fullmatch(pid)):
                _invalid('organization_parent_type_identity_invalid')
            if pid in seen:
                _invalid('organization_parent_cycle')
            name, parent_arn = None, None
            if kind == 'ORGANIZATIONAL_UNIT':
                detail = requests.detail(session, 'organizations', region, 'describe_organizational_unit', OrganizationalUnitId=pid)
                if not isinstance(detail, dict) or detail.get('collection_status') != 'collected':
                    from .aws import ReadFailure
                    status = detail.get('collection_status', 'unknown') if isinstance(detail, dict) else 'malformed'
                    if status not in {'denied', 'timeout', 'not_collected', 'malformed', 'unknown'}:
                        status = 'unknown'
                    error = detail.get('error') if isinstance(detail, dict) else None
                    raise ReadFailure(status, error.get('code', 'organization_unit_detail_unavailable') if isinstance(error, dict) else 'organization_unit_detail_unavailable')
                unit = detail.get('OrganizationalUnit')
                if not isinstance(unit, dict) or unit.get('Id') != pid:
                    _invalid('organization_unit_identity_invalid')
                name, parent_arn = unit.get('Name'), unit.get('Arn')
                expected_arn = f'arn:{partition}:organizations::{management}:ou/{organization}/{pid}'
                if not isinstance(name, str) or not 1 <= len(name) <= 128 or parent_arn != expected_arn:
                    _invalid('organization_unit_name_or_authority_invalid')
            seen.add(pid)
            path.append(pid)
            row = {'_resource_id': child, 'Id': pid, 'Type': kind, 'ChildId': child, 'ParentId': pid, 'ParentType': kind,
                   'ParentPath': list(path), 'OrganizationId': organization,
                   'OrganizationManagementAccountId': management,
                   '_provenance': {'read_only': True, 'adapter_version': 'organization-ou-native-v1',
                       'source_operation': 'organizations:list_parents' + ('+describe_organizational_unit' if name is not None else '')}}
            if name is not None:
                row.update(OrganizationalUnitName=name, Arn=parent_arn)
            rows.append(row)
            if kind == 'ROOT':
                break
            child = pid
        else:
            _invalid('organization_parent_depth_limit')
    except Exception as exc:
        failure = _failure(exc)
    for row in rows:
        row['InheritanceComplete'] = failure is None
        row['ParentCollection'] = {'collection_status': 'collected' if failure is None else failure.status,
                                   'complete': failure is None}
        if failure:
            row['ParentCollection']['error'] = {'code': failure.code}
    return rows, failure


def collect(requests, session, region, account, account_inventory=None):
    from .aws import ReadResult, _failure
    try:
        if not isinstance(account, str) or not ACCOUNT.fullmatch(account):
            _invalid('organization_audited_account_invalid')
        roster = account_inventory
        if roster is None:
            roster = requests.pages(session, 'organizations', region, 'list_accounts', 'Accounts')
        targets, authority = _accounts(roster, account)
    except Exception as exc:
        failure = _failure(exc)
        return ReadResult([], failure.status, {'code': failure.code, 'cause_status': failure.status})
    workers = max(1, min(16, getattr(requests, 'workers', 1), len(targets)))
    by_child, failure = {}, None
    # map reduces in target order, preserving the audited account's ParentPath
    # on shared OU edges without duplicating their authoritative identities.
    with ThreadPoolExecutor(max_workers=workers) as pool:
        outcomes = pool.map(lambda aid: _path(requests, session, region, aid, authority), targets)
        for rows, problem in outcomes:
            if problem is not None and failure is None:
                failure = problem
            for row in rows:
                prior = by_child.get(row['ChildId'])
                if prior is not None:
                    keys = ('Id', 'Type', 'ParentId', 'ParentType', 'OrganizationalUnitName', 'Arn', 'OrganizationId', 'OrganizationManagementAccountId')
                    if any(prior.get(key) != row.get(key) for key in keys):
                        from .aws import ReadFailure
                        failure = ReadFailure('malformed', 'organization_parent_conflict')
                    continue
                by_child[row['ChildId']] = row
    rows = list(by_child.values())
    if failure:
        return ReadResult(rows, 'partial' if rows else failure.status,
                          {'code': failure.code, 'cause_status': failure.status})
    return ReadResult(rows, 'collected' if rows else 'empty')
