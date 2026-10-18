"""Opt-in read-only EKS validating-webhook metadata; no signature/runtime probe."""
import base64
from copy import deepcopy
from botocore.exceptions import BotoCoreError, ClientError
import json
import re
import ssl
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import Request, HTTPSHandler, HTTPRedirectHandler, ProxyHandler, build_opener

SPECS = {'k8s_admission_policy': ('eks', 'describe_cluster', None)}
NATIVE_IDS = {'k8s_admission_policy': 'cluster_arn'}
READ_ACTIONS = {('eks', 'describe_cluster')}
PATH = '/apis/admissionregistration.k8s.io/v1/validatingwebhookconfigurations'
ARN = re.compile(r'arn:aws:eks:([a-z]{2}(?:-[a-z]+)+-[0-9]):([0-9]{12}):cluster/([A-Za-z0-9][A-Za-z0-9_-]{0,99})')
MAX_PAGES = 32
MAX_ROWS = 4096
MAX_PAGE_BYTES = 2_000_000
MAX_TOTAL_BYTES = 16_000_000


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def normalize(options, scopes=None):
    policy = options.get('compliance_policy', {})
    if not isinstance(policy, dict):
        raise ValueError('EKS owner policy must be an object')
    if 'eks_image_integrity' not in policy:
        return None
    value = policy['eks_image_integrity']
    if not isinstance(value, dict) or set(value) != {'status', 'designated_cluster_arns', 'approved_verifier_services'} or value['status'] != 'collected':
        raise ValueError('EKS image verifier policy fields invalid')
    arns = value['designated_cluster_arns']
    services = value['approved_verifier_services']
    if not isinstance(arns, list) or not arns or len(arns) > 32 or any(not isinstance(a, str) or not ARN.fullmatch(a) for a in arns) or len(set(arns)) != len(arns):
        raise ValueError('EKS designated cluster identities invalid')
    if not isinstance(services, list) or not services or len(services) > 128:
        raise ValueError('EKS approved verifier services invalid')
    seen = set()
    for service in services:
        if not isinstance(service, dict) or set(service) != {'namespace', 'name'}:
            raise ValueError('EKS approved verifier service fields invalid')
        pair = tuple(service[k] for k in ('namespace', 'name'))
        if any(not isinstance(v, str) or len(v) > 63 or not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]*[a-z0-9])?', v) for v in pair) or pair in seen:
            raise ValueError('EKS approved verifier service identity invalid')
        seen.add(pair)
    if scopes is not None:
        if not isinstance(scopes, (list, tuple)) or not scopes or any(not isinstance(s, str) or not re.fullmatch(r'[0-9]{12}(?:/[a-z]{2}(?:-[a-z]+)+-[0-9])?', s) for s in scopes):
            raise ValueError('EKS selected AWS account scope invalid')
        regions = options.get('regions', [])
        if not isinstance(regions, list) or any(not isinstance(r, str) or not re.fullmatch(r'[a-z]{2}(?:-[a-z]+)+-[0-9]', r) for r in regions) or len(regions) != len(set(regions)):
            raise ValueError('EKS explicit region selection invalid')
        for arn in arns:
            region, account, _ = ARN.fullmatch(arn).groups()
            if account + '/' + region not in scopes and not (account in scopes and region in regions):
                raise ValueError('EKS designated cluster outside exact selected account/regions')
    return deepcopy(value)


def _cluster(detail, arn, region):
    if not isinstance(detail, dict) or detail.get('collection_status') != 'collected':
        raise ValueError('eks_cluster_detail_unavailable')
    cluster = detail.get('cluster')
    if not isinstance(cluster, dict) or cluster.get('arn') != arn or cluster.get('name') != ARN.fullmatch(arn)[3] or cluster.get('status') != 'ACTIVE':
        raise ValueError('eks_cluster_identity_or_state_unavailable')
    vpc = cluster.get('resourcesVpcConfig')
    if not isinstance(vpc, dict) or vpc.get('endpointPublicAccess') is not True:
        raise ValueError('eks_private_endpoint_unsupported')
    endpoint = cluster.get('endpoint')
    if not isinstance(endpoint, str) or len(endpoint) > 255:
        raise ValueError('eks_endpoint_invalid')
    parsed = urlsplit(endpoint)
    # Conservative standard AWS endpoint dialect only. api.aws/China/GovCloud
    # variants remain unavailable rather than being guessed or rewritten.
    pattern = r'[a-fA-F0-9]{16,64}(?:\.[a-z0-9-]{1,30})?\.' + re.escape(region) + r'\.eks\.amazonaws\.com'
    if parsed.scheme != 'https' or parsed.path or parsed.query or parsed.fragment or not re.fullmatch(pattern, parsed.netloc):
        raise ValueError('eks_endpoint_dialect_unsupported')
    ca = cluster.get('certificateAuthority')
    if not isinstance(ca, dict) or not isinstance(ca.get('data'), str) or len(ca['data']) > 90000:
        raise ValueError('eks_ca_missing')
    try:
        pem = base64.b64decode(ca['data'], validate=True)
        if len(pem) > 65536 or not pem.startswith(b'-----BEGIN CERTIFICATE-----'):
            raise ValueError('eks_ca_invalid')
        context = ssl.create_default_context(cadata=pem.decode('ascii'))
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
    except (ValueError, UnicodeError, ssl.SSLError) as exc:
        raise ValueError('eks_ca_invalid') from None
    return cluster['name'], endpoint, context


def _token(session, region, name):
    """Same local STS Query presign format as aws eks get-token; no STS call."""
    from botocore.auth import SigV4QueryAuth
    from botocore.awsrequest import AWSRequest
    credentials = session.get_credentials()
    if credentials is None:
        raise ValueError('eks_session_credentials_unavailable')
    request = AWSRequest(method='GET', url='https://sts.' + region + '.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15',
                         headers={'x-k8s-aws-id': name})
    SigV4QueryAuth(credentials.get_frozen_credentials(), 'sts', region, expires=60).add_auth(request)
    return 'k8s-aws-v1.' + base64.urlsafe_b64encode(request.url.encode()).decode().rstrip('=')


class Budget:
    def __init__(self, requests):
        self.requests = requests
        self.started = time.monotonic()
        self.pages = self.bytes = self.rows = 0
    def charge(self):
        from .aws import ReadFailure
        self.requests.check_deadline()
        if time.monotonic() - self.started >= 120:
            raise ReadFailure('timeout', 'eks_admission_deadline')
        limit = min(MAX_PAGES, self.requests.max_pages) if self.requests.max_pages is not None else MAX_PAGES
        if self.pages >= limit:
            raise ReadFailure('not_collected', 'eks_admission_page_limit')
        with self.requests._lock:
            if self.requests.max_calls is not None and self.requests.calls >= self.requests.max_calls:
                raise ReadFailure('not_collected', 'call_limit')
            self.requests.calls += 1
        self.pages += 1


def _project(config):
    if not isinstance(config, dict) or ('apiVersion' in config and config['apiVersion'] != 'admissionregistration.k8s.io/v1') or ('kind' in config and config['kind'] != 'ValidatingWebhookConfiguration'):
        raise ValueError('eks_admission_configuration_invalid')
    meta = config.get('metadata')
    if not isinstance(meta, dict) or not isinstance(meta.get('name'), str) or not re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?', meta['name']) or not isinstance(meta.get('uid'), str) or not meta['uid'] or len(meta['uid']) > 128:
        raise ValueError('eks_admission_configuration_identity_invalid')
    hooks = config.get('webhooks')
    if not isinstance(hooks, list) or len(hooks) > 256:
        raise ValueError('eks_admission_webhooks_unavailable')
    projected = []
    hook_names = set()
    for hook in hooks:
        if not isinstance(hook, dict) or not isinstance(hook.get('clientConfig'), dict):
            raise ValueError('eks_admission_webhook_invalid')
        hook_name = hook.get('name')
        if not isinstance(hook_name, str) or len(hook_name) > 253 or not re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?', hook_name) or hook_name in hook_names:
            raise ValueError('eks_admission_webhook_name_duplicate_or_invalid')
        hook_names.add(hook_name)
        client = hook['clientConfig']
        if hook.get('failurePolicy') not in ('Fail', 'Ignore'):
            raise ValueError('eks_admission_failure_policy_invalid')
        for key in ('namespaceSelector', 'objectSelector'):
            if key in hook and not isinstance(hook[key], dict):
                raise ValueError('eks_admission_selector_invalid')
        if 'matchConditions' in hook and (not isinstance(hook['matchConditions'], list) or len(hook['matchConditions']) > 64 or any(not isinstance(v, dict) for v in hook['matchConditions'])):
            raise ValueError('eks_admission_conditions_invalid')
        rules = hook.get('rules')
        if not isinstance(rules, list) or len(rules) > 128:
            raise ValueError('eks_admission_rules_invalid')
        for rule in rules:
            if not isinstance(rule, dict) or any(not isinstance(rule.get(k), list) or any(not isinstance(v, str) or len(v) > 256 for v in rule[k]) for k in ('operations', 'apiGroups', 'apiVersions', 'resources')):
                raise ValueError('eks_admission_rule_shape_invalid')
            if 'scope' in rule and rule['scope'] not in ('*', 'Namespaced', 'Cluster'):
                raise ValueError('eks_admission_rule_scope_invalid')
        row = {k: deepcopy(hook[k]) for k in ('name', 'failurePolicy', 'namespaceSelector', 'objectSelector', 'matchConditions', 'rules') if k in hook}
        if 'url' in client:
            url = client['url']
            if 'service' in client or not isinstance(url, str) or not 0 < len(url) <= 2048 or urlsplit(url).scheme != 'https' or not urlsplit(url).netloc:
                raise ValueError('eks_admission_url_client_invalid')
            row['clientConfig'] = {'url': '[omitted]'}
            row['_provenance'] = {'url_omitted': True, 'native_client_kind': 'url'}
        else:
            service = client.get('service')
            if not isinstance(service, dict) or any(not isinstance(service.get(k), str) or len(service[k]) > 63 or not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]*[a-z0-9])?', service[k]) for k in ('name', 'namespace')):
                raise ValueError('eks_admission_service_identity_invalid')
            row['clientConfig'] = {'service': {k: service[k] for k in ('name', 'namespace')}}
        projected.append(row)
    return {'metadata': {'name': meta['name'], 'uid': meta['uid']}, 'webhooks': projected}


def _list(requests, session, region, name, endpoint, context, budget):
    token = _token(session, region, name)
    opener = build_opener(ProxyHandler({}), HTTPSHandler(context=context), NoRedirect())
    output, seen_names, seen_uids, seen_tokens = [], set(), set(), set()
    continuation = None
    resource_version = None
    while True:
        query = {'limit': '100'}
        if continuation is not None:
            query['continue'] = continuation
        url = endpoint + PATH + '?' + urlencode(query)
        budget.charge()
        request = Request(url, method='GET', headers={'Authorization': 'Bearer ' + token, 'Accept': 'application/json'})
        with opener.open(request, timeout=min(requests.timeout, max(0.1, 120 - (time.monotonic() - budget.started)))) as response:
            if response.status != 200 or response.geturl() != url:
                raise ValueError('eks_admission_http_response_invalid')
            body = response.read(MAX_PAGE_BYTES + 1)
        budget.bytes += len(body)
        if len(body) > MAX_PAGE_BYTES or budget.bytes > MAX_TOTAL_BYTES:
            raise ValueError('eks_admission_byte_limit')
        page = json.loads(body)
        if not isinstance(page, dict) or page.get('kind') != 'ValidatingWebhookConfigurationList' or page.get('apiVersion') != 'admissionregistration.k8s.io/v1' or not isinstance(page.get('metadata'), dict) or not isinstance(page.get('items'), list):
            raise ValueError('eks_admission_list_shape_invalid')
        metadata = page['metadata']
        version = metadata.get('resourceVersion')
        if not isinstance(version, str) or not version or len(version) > 256 or resource_version is not None and version != resource_version:
            raise ValueError('eks_admission_list_version_unavailable')
        resource_version = version
        for raw in page['items']:
            config = _project(raw)
            name_, uid = config['metadata']['name'], config['metadata']['uid']
            if name_ in seen_names or uid in seen_uids:
                raise ValueError('eks_admission_duplicate_configuration')
            seen_names.add(name_); seen_uids.add(uid); output.append(config); budget.rows += 1
            if budget.rows > MAX_ROWS or requests.max_items is not None and budget.rows > requests.max_items:
                raise ValueError('eks_admission_resource_limit')
        continuation = metadata.get('continue', '')
        if not isinstance(continuation, str) or len(continuation) > 8192:
            raise ValueError('eks_admission_continuation_invalid')
        if not continuation:
            remaining = metadata.get('remainingItemCount')
            if remaining not in (None, 0) or type(remaining) is bool:
                raise ValueError('eks_admission_terminal_remaining_items')
            return output, resource_version
        if continuation in seen_tokens or not page['items']:
            raise ValueError('eks_admission_pagination_incomplete')
        seen_tokens.add(continuation)


def collect(requests, session, region, account):
    from .aws import ReadFailure, ReadResult
    policy = getattr(requests, 'eks_admission_policy', None)
    if policy is None:
        return ReadResult([], 'not_collected', {'code': 'eks_image_verifier_owner_scope_required'})
    try:
        policy = normalize({'compliance_policy': {'eks_image_integrity': policy}})
        if session.get_partition_for_region(region) != 'aws' or not re.fullmatch(r'[0-9]{12}', account):
            raise ValueError('eks_partition_or_account_unsupported')
        selected = [a for a in policy['designated_cluster_arns'] if ARN.fullmatch(a)[1] == region and ARN.fullmatch(a)[2] == account]
        output = []
        budget = Budget(requests)
        for arn in selected:
            name = ARN.fullmatch(arn)[3]
            detail = requests.detail(session, 'eks', region, 'describe_cluster', name=name)
            if detail.get('collection_status') != 'collected':
                raise ReadFailure(detail.get('collection_status', 'not_collected'), 'eks_cluster_detail_unavailable')
            cluster_name, endpoint, context = _cluster(detail, arn, region)
            configurations, version = _list(requests, session, region, cluster_name, endpoint, context, budget)
            output.append({'cluster_arn': arn, 'validating_webhook_configurations': configurations,
                '_provenance': {'source_operation': 'GET ' + PATH, 'identity_operation': 'eks:DescribeCluster',
                                'list_resource_version': version, 'api_pages_complete': True,
                                'scope': 'explicit owner-designated clusters only', 'read_only': True}})
        return ReadResult(output, 'collected' if output else 'empty')
    except ReadFailure as exc:
        return ReadResult([], exc.status, {'code': exc.code})
    except (BotoCoreError, ClientError):
        return ReadResult([], 'not_collected', {'code': 'eks_token_session_unavailable'})
    except HTTPError as exc:
        return ReadResult([], 'not_collected', {'code': 'eks_kubernetes_authorization_or_http_unavailable'})
    except (ValueError, KeyError, TypeError, AttributeError, UnicodeError, ssl.SSLError, OSError, URLError):
        return ReadResult([], 'not_collected', {'code': 'eks_admission_native_evidence_unavailable'})


FETCHERS = {'k8s_admission_policy': collect}
