"""Registration-free strict backup evidence primitives.

Pure observation validators copied from the accepted SW13 backup contract;
no check registration, provider calls, policy synthesis or live data reads.
SW13 remains unchanged to preserve its independently reviewed predecessor.
"""
from datetime import datetime
import re
from .facts import Unavailable, complete_items, get, list_of_objects


def text(value):
    if not isinstance(value, str) or not value.strip():
        raise Unavailable('empty or malformed string')
    return value


def strings(value, *, nonempty=False):
    if not isinstance(value, list) or any(not isinstance(v, str) or not v for v in value) or len(set(value)) != len(value):
        raise Unavailable('malformed or duplicate string list')
    if nonempty and not value:
        raise Unavailable('empty required scope')
    return value


def instant(value):
    try:
        stamp = datetime.fromisoformat(text(value).replace('Z', '+00:00'))
        if stamp.tzinfo is None or stamp.utcoffset() is None:
            raise ValueError('timezone missing')
        return stamp
    except ValueError as exc:
        raise Unavailable('invalid observation timestamp') from exc


def scope(index):
    context = get(index, 'context', dict)
    if get(context, 'provider', str) != 'azure':
        raise Unavailable('foreign provider')
    return text(get(context, 'scope', str))


def now(index):
    return instant(get(index, 'context.created_at', str))


def bound(rid, index):
    """ARM identity belongs to the evaluated subscription/resource scope."""
    rid, owner = text(rid), scope(index)
    if not rid.startswith('/subscriptions/') or not (rid.casefold() == owner.casefold() or rid.casefold().startswith(owner.rstrip('/').casefold() + '/')):
        raise Unavailable('malformed or foreign ARM identity')
    if not re.fullmatch(r'/subscriptions/[^/]+/(?:[^/]+/)*[^/]+', rid):
        raise Unavailable('malformed ARM identity')
    return rid.casefold()


def inventory(index, kind, *, parent=None, graph=False):
    rows = complete_items(index, kind)
    owner = scope(index)
    envelopes = get(index, 'collections', dict)[kind]
    for env in envelopes:
        es = text(get(env, 'scope', str))
        if not (es.casefold() == owner.casefold() or es.casefold().startswith(owner.rstrip('/').casefold() + '/')):
            raise Unavailable('foreign collection scope: ' + kind)
        if get(env, 'type', str) != kind:
            raise Unavailable('foreign collection kind')
    resources = get(index, kind, list)
    if len(resources) != len(rows):
        raise Unavailable('resource projection inconsistent')
    native_types = {'app_service': 'Microsoft.Web/sites', 'recovery_vault': 'Microsoft.RecoveryServices/vaults',
                    'scheduled_query_rule': 'Microsoft.Insights/scheduledQueryRules',
                    'action_group': 'Microsoft.Insights/actionGroups',
                    'subnet': 'Microsoft.Network/virtualNetworks/[^/]+/subnets'}
    ids = set()
    for wrapped, row in zip(resources, rows):
        rs = text(get(wrapped, 'scope', str))
        if not (rs.casefold() == owner.casefold() or rs.casefold().startswith(owner.rstrip('/').casefold() + '/')):
            raise Unavailable('foreign resource envelope')
        rid = text(get(row, 'id', str))
        if graph:
            if not owner.startswith('/tenants/'):
                raise Unavailable('tenant scope unresolved')
            tenant = get(row, '_provenance.tenant_id', str)
            if tenant.casefold() != owner.removeprefix('/tenants/').casefold():
                raise Unavailable('foreign Graph tenant')
        else:
            bound(rid, index)
            if kind in native_types and not re.fullmatch(r'/subscriptions/[^/]+/resourceGroups/[^/]+/providers/' + native_types[kind] + r'/[^/]+', rid, re.I):
                raise Unavailable('foreign native resource kind')
        if rid.casefold() in ids:
            raise Unavailable('duplicate resource identity: ' + kind)
        ids.add(rid.casefold())
        if not graph and 'parent_id' in row:
            declared_parent = text(get(row, 'parent_id', str))
            bound(declared_parent, index)
            if not rid.casefold().startswith(declared_parent.rstrip('/').casefold() + '/'):
                raise Unavailable('resource identity conflicts with declared parent')
        if parent is not None and not rid.casefold().startswith(parent.rstrip('/').casefold() + '/'):
            # Cross-vault rows are valid in subscription-wide collections; filter below.
            continue
    # Require projection to agree with complete envelope payloads when supplied.
    if all('items' in env for env in envelopes):
        expected = [r for env in envelopes for r in list_of_objects(get(env, 'items', list))]
        if sorted(repr(r) for r in expected) != sorted(repr(r) for r in rows):
            raise Unavailable('collection payload differs from resource projection')
    if parent is not None:
        return [r for r in rows if r['id'].casefold().startswith(parent.rstrip('/').casefold() + '/')]
    return rows


def current(row, index):
    text(get(row, 'document_id', str))
    text(get(row, 'authorized_by', str))
    start, end = instant(get(row, 'observed_at', str)), instant(get(row, 'expires_at', str))
    if end < start:
        raise Unavailable('malformed validity interval')
    if start > now(index):
        raise Unavailable('future-dated evidence')
    return now(index) <= end


def backup_restore_native_capture(index):
    """Opaque collector capture plus the actual native read authority."""
    metadata = get(index, 'context.metadata', dict)
    if get(metadata, 'tenant_verified', bool) is not True:
        raise Unavailable('restore native tenant authority unresolved')
    capture = {key: text(get(metadata, key, str))
               for key in ('tenant_id', 'credential_context_id', 'customer_context_id')}
    for kind in ('recovery_vault', 'backup_protected_item', 'backup_job'):
        envelopes = get(index, 'collections', dict).get(kind, [])
        expected_service = 'Microsoft.RecoveryServices'
        if (len(envelopes) != 1 or get(envelopes[0], 'service', str) != expected_service
                or get(envelopes[0], 'scope', str).casefold() != scope(index).casefold()):
            raise Unavailable('restore native source scope unresolved')
        envelope_proof = get(envelopes[0], '_provenance', dict)
        if any(get(envelope_proof, key, str) != capture[key]
               for key in ('credential_context_id', 'customer_context_id')):
            raise Unavailable('restore native collection capture inconsistent')
        for row in inventory(index, kind):
            proof = get(row, '_provenance', dict)
            if (any(get(proof, key, str) != capture[key]
                    for key in ('credential_context_id', 'customer_context_id'))
                    or get(proof, 'read_only', bool) is not True
                    or get(proof, 'api_version', str) != '2024-04-01'):
                raise Unavailable('restore native source capture or readonly authority unresolved')
            if kind == 'recovery_vault':
                if (get(proof, 'source_operation', str) != 'get'
                        or get(proof, 'representation', str) != 'full'):
                    raise Unavailable('restore vault requires actual full native GET')
            else:
                parent = get(row, 'parent_id', str)
                field, operation = (('backupJobs', 'BackupJobs_List') if kind == 'backup_job'
                                    else ('backupProtectedItems', 'BackupProtectedItems_List'))
                if (get(proof, 'source_operation', str) != operation
                        or get(proof, 'representation', str) != 'metadata'
                        or get(proof, 'endpoint', str).casefold() != (parent + '/' + field).casefold()):
                    raise Unavailable('restore native metadata operation or endpoint unresolved')
    return capture


def backup_restore_digest(value):
    """Local canonical evidence digest; never represented as a provider hash."""
    import hashlib
    import json
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                     ensure_ascii=True, allow_nan=False).encode()).hexdigest()


def backup_restore_arm_resource(value):
    """An unencoded ARM namespace followed by genuine type/name pairs."""
    if not isinstance(value, str) or not value.startswith('/'):
        raise Unavailable('restore ARM resource malformed')
    parts = value[1:].split('/')
    if (len(parts) < 8 or len(parts[6:]) % 2
            or [part.casefold() for part in (parts[0], parts[2], parts[4])] != ['subscriptions', 'resourcegroups', 'providers']
            or not re.fullmatch(r'[A-Za-z0-9]+(?:\.[A-Za-z0-9]+)+', parts[5])
            or any(not part or part in ('.', '..') or re.search(r'[%/?#\x00-\x20]', part) for part in parts)):
        raise Unavailable('restore ARM resource has invalid type/name pairs or encoded/traversal segments')
    return value


def backup_restore_validation(test, job, protected, index, vault_id, capture):
    """Explicit independent external test binds the exact native observations."""
    pid, jid = get(protected, 'id', str), get(job, 'id', str)
    segment = r'[^/?#\x00-\x20]+'
    if (not re.fullmatch(re.escape(vault_id) + '/backupJobs/' + segment, jid, re.I)
            or not re.fullmatch(re.escape(vault_id) + '/backupFabrics/' + segment
                + '/protectionContainers/' + segment + '/protectedItems/' + segment, pid, re.I)):
        raise Unavailable('restore native item or job ARM kind unresolved')
    management = get(job, 'properties.backupManagementType', str)
    job_types = {'AzureIaaSVMJob': 'AzureIaasVM', 'AzureIaaSVMJobV2': 'AzureIaasVM',
                 'AzureStorageJob': 'AzureStorage', 'AzureWorkloadJob': 'AzureWorkload'}
    if (job_types.get(get(job, 'properties.jobType', str)) != management
            or get(protected, 'properties.backupManagementType', str) != management):
        raise Unavailable('restore job and protected workload contradict or are unsupported')
    evidence = get(test, 'validationEvidence', dict)
    proof = get(evidence, '_provenance', dict)
    if (get(proof, 'source_operation', str) != 'external:restore-validation'
            or get(proof, 'representation', str) != 'full'
            or get(proof, 'read_only', bool) is not True
            or not current(evidence, index)):
        raise Unavailable('independent full restore validation authority unresolved')
    if get(evidence, 'document_id', str) != get(test, 'verificationDocumentId', str):
        raise Unavailable('restore validation document join unresolved')
    for field, expected in (('vaultId', vault_id), ('protectedItemId', pid), ('jobId', jid)):
        if get(evidence, field, str).casefold() != expected.casefold():
            raise Unavailable('restore validation exact resource binding differs')
    point = get(evidence, 'sourceRecoveryPointId', str)
    target_id = get(evidence, 'restoreTargetId', str)
    if (not re.fullmatch(re.escape(pid) + '/recoveryPoints/' + segment, point, re.I)
            or get(test, 'sourceRecoveryPointId', str).casefold() != point.casefold()
            or get(test, 'restoreTargetId', str).casefold() != target_id.casefold()):
        raise Unavailable('external restore source point or target binding unresolved')
    bound(target_id, index)
    for identity in (pid, jid, point, target_id):
        backup_restore_arm_resource(identity)
    for key in ('credential_context_id', 'customer_context_id'):
        if get(evidence, key, str) != capture[key]:
            raise Unavailable('external restore validation belongs to another capture')
    expected_digest = backup_restore_digest({'job': job, 'protected_item': protected, 'capture': capture})
    if get(evidence, 'nativeEvidenceSha256', str) != expected_digest:
        raise Unavailable('external restore validation native evidence digest differs')
    verified = instant(get(test, 'verifiedAt', str))
    if instant(get(evidence, 'observed_at', str)) != verified:
        raise Unavailable('usable-data validation timestamp differs')
    usable = get(evidence, 'usableDataValidation', dict)
    if get(usable, 'method', str) not in (
            'application-functional-test', 'database-consistency-check', 'restored-content-checksum'):
        raise Unavailable('restore verification method does not demonstrate usable data')
    text(get(usable, 'testId', str))
    if not re.fullmatch(r'[0-9a-f]{64}', get(usable, 'resultArtifactSha256', str)):
        raise Unavailable('usable-data result artifact binding unresolved')
    if get(usable, 'result', str) != get(test, 'result', str):
        raise Unavailable('usable-data validation outcome conflicts')
    if (get(test, 'result', str) == 'Passed'
            and get(test, 'restoredDataVerified', bool) is not True):
        raise Unavailable('restore usable-data outcome contradicts verification')
