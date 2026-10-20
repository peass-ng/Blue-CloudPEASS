"""Uninstalled parent-context adapter; reuses the caller's reader and budget."""
from copy import deepcopy
import json
import re
from threading import RLock
from uuid import uuid4

from . import azure
from . import azure_nsp_query_cmk_metadata_proposal_20261020 as native

SCHEMA = 'azure-nsp-query-cmk-parent-context-v1'
METADATA_KEY = 'azure_nsp_query_cmk_metadata'
ADAPTER = 'azure_nsp_query_cmk_runtime_20261020'
KINDS = native.KINDS
SUBSCRIPTION_VERSION = '2022-12-01'


class ContextUnavailable(ValueError):
    """Fixed non-sensitive unavailable parent/capture context."""


def parent_context(metadata, scope):
    """Inspect only provider-owned parent metadata, never connector options."""
    native.scope_id(scope)
    if not isinstance(metadata, dict):
        raise ContextUnavailable('parent metadata unavailable')
    credential = metadata.get('credential_context_id')
    customer = metadata.get('customer_context_id')
    tenant = metadata.get('tenant_id')
    mapping = metadata.get('subscription_tenants')
    if (not isinstance(credential, str) or not re.fullmatch('[0-9a-f]{32}', credential)
            or customer != 'scan-local:' + credential or metadata.get('context_binding') != 'scan_local'
            or metadata.get('tenant_verified') is not True or not isinstance(tenant, str)
            or not re.fullmatch(native.GUID, tenant, re.I) or not isinstance(mapping, dict)):
        raise ContextUnavailable('parent credential/customer/tenant unavailable')
    aliases = [value for key, value in mapping.items() if isinstance(key, str) and key.casefold() == scope.casefold()]
    if (len(aliases) != 1 or not isinstance(aliases[0], str)
            or aliases[0].casefold() != tenant.casefold()):
        raise ContextUnavailable('parent subscription tenant unavailable')
    return {'credential_context_id': credential, 'customer_context_id': customer,
            'tenant_id': tenant.casefold(), 'tenant_verified': True, 'context_binding': 'scan_local'}


def selected(scopes, wanted):
    if not isinstance(wanted, (list, tuple, set, frozenset)) or any(not isinstance(kind, str) for kind in wanted):
        raise ValueError('exact Azure metadata requirements required')
    kinds = tuple(kind for kind in KINDS if kind in wanted)
    if not kinds:
        return ()
    if (not isinstance(scopes, (list, tuple)) or not scopes
            or len({native.scope_id(scope).casefold() for scope in scopes}) != len(scopes)):
        raise ValueError('exact selected Azure metadata scopes required')
    return kinds


def subscription_job(reader, transport, scope, *, credential_context_id, customer_context_id):
    """Replace the one selected subscription dependency GET, not an extra read.

    This reuses immutable metadata_get and emits an explicit native parent
    receipt, without depending on a second GET or rewriting a completed receipt.
    """
    native.scope_id(scope)
    if (not isinstance(reader, azure._Reader) or not isinstance(transport, azure.AzureTransport)
            or not isinstance(credential_context_id, str) or not re.fullmatch('[0-9a-f]{32}', credential_context_id)
            or customer_context_id != 'scan-local:' + credential_context_id):
        raise ContextUnavailable('parent subscription context unavailable')
    transport_id = transport.ai_context_id
    def fetch():
        raw = reader.call(native.metadata_get, transport, native.ARM + scope + '?api-version=' + SUBSCRIPTION_VERSION)
        tenant = getattr(transport, 'verified_tenant', None)
        if (not isinstance(raw, dict) or raw.get('id') != scope
                or not isinstance(raw.get('subscriptionId'), str)
                or raw['subscriptionId'].casefold() != scope.rsplit('/', 1)[-1].casefold()
                or not isinstance(tenant, str) or not re.fullmatch(native.GUID, tenant, re.I)
                or not isinstance(raw.get('tenantId'), str) or raw['tenantId'].casefold() != tenant.casefold()
                or not isinstance(transport.tenant, str) or transport.tenant.casefold() != tenant.casefold()
                or raw.get('state') != 'Enabled' or transport.ai_context_id != transport_id):
            raise ContextUnavailable('native selected subscription identity/state unavailable')
        # Preserve documented metadata needed by other subscription controls;
        # the shared reader applies its existing metadata sanitizer afterwards.
        fields = ('id', 'subscriptionId', 'tenantId', 'state', 'displayName', 'subscriptionPolicies',
                  'managedByTenants', 'authorizationSource', 'tags')
        yield [{**{key: raw[key] for key in fields if key in raw}, '_provenance': {
                    'adapter': ADAPTER + '.subscription', 'operation': 'Subscriptions_Get', 'method': 'GET',
                    'request_path': scope, 'api_version': SUBSCRIPTION_VERSION, 'read_only': True,
                    'credential_context_id': credential_context_id, 'customer_context_id': customer_context_id,
                    'tenant_id': tenant.casefold(), 'tenant_verified': True, 'transport_context_id': transport_id}}]
    return ('subscription', scope, 'Microsoft.Resources', fetch)


def subscription_receipt(item, scope, credential, customer, tenant):
    proof = item.get('_provenance')
    if (not isinstance(proof, dict) or proof.get('adapter') != ADAPTER + '.subscription'
            or proof.get('operation') != 'Subscriptions_Get' or proof.get('method') != 'GET'
            or proof.get('request_path') != scope or proof.get('api_version') != SUBSCRIPTION_VERSION
            or proof.get('read_only') is not True or proof.get('credential_context_id') != credential
            or proof.get('customer_context_id') != customer or proof.get('tenant_id') != tenant.casefold()
            or proof.get('tenant_verified') is not True or not isinstance(proof.get('transport_context_id'), str)
            or not re.fullmatch('[0-9a-f]{32}', proof['transport_context_id'])):
        raise ContextUnavailable('selected subscription native source receipt unavailable')
    return proof


def parent_metadata_from_inventory(reader, transport, scopes, *, credential_context_id, customer_context_id):
    """Use the already-read exact subscription dependency, before final metadata.

    The two opaque context IDs are the actual parent collect locals. Subscription
    ownership comes from native collected rows, not auth options or a guessed map.
    This performs no additional native read and creates no context or budget.
    """
    selected(scopes, KINDS)
    tenant = getattr(transport, 'verified_tenant', None)
    if (not isinstance(reader, azure._Reader) or not isinstance(transport, azure.AzureTransport)
            or not isinstance(tenant, str) or not re.fullmatch(native.GUID, tenant, re.I)
            or not isinstance(transport.tenant, str) or transport.tenant.casefold() != tenant.casefold()):
        raise ContextUnavailable('authenticated parent tenant unavailable')
    mapping = {}
    for scope in scopes:
        own = [row for row in reader.collections if row.get('type') == 'subscription' and row.get('scope') == scope]
        if (len(own) != 1 or own[0].get('status') != 'collected'
                or own[0].get('service') != 'Microsoft.Resources' or len(own[0].get('items', [])) != 1):
            raise ContextUnavailable('complete selected subscription dependency unavailable')
        item = own[0]['items'][0]
        if (not isinstance(item, dict) or item.get('id') != scope
                or not isinstance(item.get('subscriptionId'), str)
                or item['subscriptionId'].casefold() != scope.rsplit('/', 1)[-1].casefold()
                or not isinstance(item.get('tenantId'), str) or item['tenantId'].casefold() != tenant.casefold()
                or item.get('state') != 'Enabled'):
            raise ContextUnavailable('selected subscription native identity/state unavailable')
        proof = subscription_receipt(item, scope, credential_context_id, customer_context_id, tenant)
        if proof['transport_context_id'] != transport.ai_context_id:
            raise ContextUnavailable('selected subscription transport differs')
        mapping[scope] = item['tenantId']
    metadata = {'credential_context_id': credential_context_id, 'customer_context_id': customer_context_id,
                'tenant_id': tenant, 'tenant_verified': True, 'context_binding': 'scan_local',
                'subscription_tenants': mapping}
    for scope in scopes:
        parent_context(metadata, scope)
    return metadata


class ParentCapture(native.Capture):
    """Bind the parent before first read; original source receipts are untouched."""
    def __init__(self, reader, transport, scope, *, parent_metadata):
        if not isinstance(reader, azure._Reader) or not isinstance(transport, azure.AzureTransport):
            raise ContextUnavailable('existing Azure reader and transport required')
        context = parent_context(parent_metadata, scope)
        transport_id = getattr(transport, 'ai_context_id', None)
        if not isinstance(transport_id, str) or not re.fullmatch('[0-9a-f]{32}', transport_id):
            raise ContextUnavailable('native transport identity unavailable')
        # Intentionally do not call native.Capture.__init__: it binds transport
        # identity rather than the parent credential. No transport field changes.
        self.reader, self.transport, self.scope = reader, transport, scope
        self.context = context['credential_context_id']
        self.parent_metadata = parent_metadata
        self.parent = context
        self.transport_id = transport_id
        self.capture_id = uuid4().hex
        self.cache = {}
        self.lock = RLock()
        self.check_context()

    def check_context(self):
        if (parent_context(self.parent_metadata, self.scope) != self.parent
                or self.transport.ai_context_id != self.transport_id
                or any(not isinstance(value, str) or value.casefold() != self.parent['tenant_id']
                       for value in (self.transport.tenant, self.transport.verified_tenant))):
            raise ContextUnavailable('parent or authenticated transport context changed')

    def binding(self, kind=None):
        self.check_context()
        value = {'schema': SCHEMA, 'adapter': ADAPTER, 'scope': self.scope,
                 'capture_id': self.capture_id, 'transport_context_id': self.transport_id,
                 'read_only': True, **self.parent}
        if kind is not None:
            value['kind'] = kind
        return value

    def request(self, path, version, operation, continuation=None):
        with self.lock:
            self.check_context()
            value, receipt = super().request(path, version, operation, continuation)
            self.check_context()
            return value, receipt  # No completed source-receipt rebind/stamping.

    def full(self, rid, typ, version, operation):
        with self.lock:
            self.check_context()
            return super().full(rid, typ, version, operation)

    def marker(self, receipts):
        return {**super().marker(receipts), 'runtime': self.binding()}


def jobs(reader, transport, scopes, wanted, *, parent_metadata):
    """Return (native _Reader job tuples, pre-read envelope bindings)."""
    kinds = selected(scopes, wanted)
    if not kinds:
        return [], []
    planned, bindings = [], []
    for scope in scopes:
        for kind in kinds:
            if any(row.get('type') == kind and str(row.get('scope', '')).casefold() == scope.casefold()
                   for row in reader.collections):
                raise RuntimeError('metadata runtime collection collision')
        capture = ParentCapture(reader, transport, scope, parent_metadata=parent_metadata)
        for kind in kinds:
            binding = capture.binding(kind)
            bindings.append(binding)
            def fetch(kind=kind, capture=capture, binding=binding):
                source = native.nsp_items(capture) if kind == native.NSP_KIND else native.query_items(capture)
                for item in source:
                    if '_provenance' in item:
                        raise ValueError('unexpected metadata item provenance')
                    yield [{**item, '_provenance': deepcopy(binding)}]
            service = 'Microsoft.Network' if kind == native.NSP_KIND else 'Microsoft.OperationalInsights'
            planned.append((kind, scope, service, fetch))
    return planned, bindings


def finish(reader, bindings):
    """Stamp only exact newly collected envelopes; return namespaced metadata."""
    for binding in bindings:
        own = [row for row in reader.collections if row.get('type') == binding['kind']
               and row.get('scope') == binding['scope']]
        if len(own) != 1:
            raise RuntimeError('metadata runtime envelope missing or ambiguous')
        envelope = own[0]
        prior = envelope.get('_provenance')
        if prior is not None and json.dumps(prior, sort_keys=True) != json.dumps(binding, sort_keys=True):
            raise RuntimeError('metadata runtime envelope provenance conflict')
        if any(json.dumps(item.get('_provenance'), sort_keys=True) != json.dumps(binding, sort_keys=True)
               for item in envelope['items']):
            raise RuntimeError('metadata runtime item provenance conflict')
        envelope['_provenance'] = deepcopy(binding)
    return {METADATA_KEY: {'schema': SCHEMA, 'bindings': deepcopy(bindings)}} if bindings else {}


def collect_into(reader, transport, scopes, wanted, *, parent_metadata):
    """Use existing reader.run: no second reader, budget, token or scan context."""
    kinds = selected(scopes, wanted)
    if not kinds:
        return {}
    if isinstance(parent_metadata, dict) and METADATA_KEY in parent_metadata:
        raise RuntimeError('metadata runtime namespace already exists')
    try:
        planned, bindings = jobs(reader, transport, scopes, wanted, parent_metadata=parent_metadata)
    except ContextUnavailable:
        for scope in scopes:
            for kind in kinds:
                reader.unavailable(kind, scope, 'Microsoft.Network' if kind == native.NSP_KIND else
                                   'Microsoft.OperationalInsights', ContextUnavailable('parent context unavailable'))
        return {METADATA_KEY: {'schema': SCHEMA, 'bindings': []}}
    reader.run(planned)
    return finish(reader, bindings)
