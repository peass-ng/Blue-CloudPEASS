"""Explicit account OAuth, read-only metadata and exact Azure workspace joins."""
import json
import re
from urllib.parse import urlsplit
from urllib.request import Request, build_opener, ProxyHandler, HTTPRedirectHandler
from urllib.error import HTTPError

HOST = 'https://accounts.azuredatabricks.net'
KIND = 'databricks_account_workspace'
MAX_RESPONSE_BYTES = 2_000_000
MAX_WORKSPACES = 1000
_UUID = r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'


def validate_auth(auth):
    if 'databricks_account_token' not in auth:
        return
    value = auth['databricks_account_token']
    if not isinstance(value, str) or not 1 <= len(value) <= 16384 or any(ord(c) <= 32 or ord(c) >= 127 for c in value):
        raise ValueError('invalid Databricks account credential')


def normalize(options):
    parent = options.get('compliance_policy', {})
    if not isinstance(parent, dict):
        raise ValueError('invalid compliance policy')
    raw = parent.get('sw33', {})
    if not isinstance(raw, dict):
        raise ValueError('invalid SW33 policy')
    if 'databricksAccount' not in raw:
        return None
    account = raw['databricksAccount']
    if (raw.get('status') != 'collected' or not isinstance(raw.get('scope'), str)
            or not re.fullmatch(r'/subscriptions/' + _UUID, raw['scope'], re.I)
            or not isinstance(account, dict) or set(account) != {'accountId'}
            or not isinstance(account['accountId'], str) or not re.fullmatch(_UUID, account['accountId'])):
        raise ValueError('invalid Databricks account approval')
    return {'status': 'collected', 'scope': raw['scope'], 'databricksAccount': {'accountId': account['accountId']}}


def owner_policy(options, scopes):
    policy = normalize(options)
    if policy and policy['scope'].casefold() in {s.casefold() for s in scopes}:
        return policy
    return None


def endpoint(url):
    if not isinstance(url, str) or any(ord(c) <= 32 or ord(c) >= 127 for c in url) or "%" in url or "\\" in url:
        raise ValueError("malformed Databricks metadata endpoint")
    parsed = urlsplit(url)
    if (parsed.scheme != 'https' or parsed.netloc != 'accounts.azuredatabricks.net'
            or parsed.username or parsed.password or parsed.query or parsed.fragment
            or not re.fullmatch(r'/api/2\.0/accounts/' + _UUID + r'/workspaces(?:/[1-9][0-9]{0,18}(?:/metastore)?)?', parsed.path)):
        raise ValueError('untrusted Databricks metadata endpoint')
    return parsed.path


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError('Databricks redirects are unsupported')


def _unique_object(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError('duplicate JSON metadata field')
        out[key] = value
    return out


def request_metadata(url, auth):
    """No ambient credential, proxy, redirect or token exchange; never read error bodies."""
    from .azure import AzureReadError
    path = endpoint(url)
    validate_auth(auth)
    token = auth.get('databricks_account_token')
    if not token:
        raise AzureReadError('databricks_account_credential_missing')
    req = Request(url, headers={'Authorization': 'Bearer ' + token, 'Accept': 'application/json'}, method='GET')
    try:
        with build_opener(ProxyHandler({}), _NoRedirect()).open(req, timeout=20) as response:
            body = response.read(MAX_RESPONSE_BYTES + 1)
        if len(body) > MAX_RESPONSE_BYTES:
            raise AzureReadError('databricks_metadata_response_limit')
        value = json.loads(body, object_pairs_hook=_unique_object)
        return project_response(value, path)
    except HTTPError as exc:
        status = exc.code
        exc.close()
        # Only the fixed, already-identified assignment endpoint documents 404
        # as no assignment. Its workspace join is rechecked before evaluation.
        if status == 404 and path.endswith('/metastore'):
            return {'httpStatus': 404, 'documentedNoAssignment': True}
        raise AzureReadError('databricks_metadata_http_error', status) from None


def project_response(value, path):
    if re.search(r'/workspaces/[1-9][0-9]*$', path):
        if not isinstance(value, dict):
            raise ValueError('invalid native account workspace GET')
        return project_response([value], path.rsplit('/', 1)[0])[0]
    if path.endswith('/metastore'):
        if not isinstance(value, dict) or not isinstance(value.get('metastore_assignment'), dict):
            raise ValueError('invalid native metastore assignment')
        item = value['metastore_assignment']
        return {'httpStatus': 200, 'metastore_assignment': {k: item[k] for k in ('workspace_id', 'metastore_id') if k in item}}
    if not isinstance(value, list) or len(value) > MAX_WORKSPACES:
        raise ValueError('invalid or oversized native account workspace array')
    out = []
    for item in value:
        if not isinstance(item, dict):
            raise ValueError('invalid account workspace metadata')
        row = {k: item[k] for k in ('account_id', 'workspace_id', 'workspace_status', 'cloud') if k in item}
        info = item.get('azure_workspace_info')
        if info is not None:
            if not isinstance(info, dict):
                raise ValueError('invalid Azure workspace metadata')
            row['azure_workspace_info'] = {k: info[k] for k in ('subscription_id', 'resource_group') if k in info}
        out.append(row)
    return out


def collect(reader, request, transport, scopes, wanted, options, auth):
    if KIND not in wanted:
        return
    from .azure import AzureReadError, ARM
    policy = normalize(options)
    jobs = []
    for scope in scopes:
        def inventory(scope=scope):
            if not policy or policy['scope'].casefold() != scope.casefold():
                raise AzureReadError('databricks_account_approval_missing')
            if not auth.get('databricks_account_token'):
                raise AzureReadError('databricks_account_credential_missing')
            account = policy['databricksAccount']['accountId']
            path = '/api/2.0/accounts/' + account + '/workspaces'
            # Parent collection must come from the complete ARM subscription
            # LIST, never ARG's eventually consistent membership projection.
            parents = [c for c in reader.collections if c['type'] == 'databricks_workspace' and c['scope'].casefold() == scope.casefold()]
            if len(parents) != 1 or parents[0]['status'] not in ('collected', 'empty'):
                raise AzureReadError('databricks_arm_inventory_incomplete')
            native = reader.call(transport.request_databricks, HOST + path)
            # Injected transports follow the same projection before join/cache.
            native = project_response(native, path)
            all_ids, rows = set(), {}
            for row in native:
                wid = row.get('workspace_id')
                if (row.get('account_id') != account or type(wid) is not int or not 1 <= wid <= 2**63-1 or wid in all_ids):
                    raise ValueError('foreign or duplicate account workspace')
                all_ids.add(wid)
                if row.get('cloud') != 'azure':
                    if row.get('cloud') not in ('aws', 'gcp'):
                        raise ValueError('unresolved workspace cloud')
                    continue
                info = row.get('azure_workspace_info')
                if not isinstance(info, dict) or not isinstance(info.get('subscription_id'), str) or not re.fullmatch(_UUID, info['subscription_id']) or not isinstance(info.get('resource_group'), str) or not info['resource_group']:
                    raise ValueError('Azure account workspace identity unavailable')
                if info['subscription_id'].casefold() == scope.rsplit('/', 1)[-1].casefold():
                    rows[wid] = row
            matched, output = set(), []
            for parent in parents[0]['items']:
                rid = parent.get('id')
                pattern = re.escape(scope) + r'/resourceGroups/([^/?#%\\\s]+)/providers/Microsoft\.Databricks/workspaces/([^/?#%\\\s]+)'
                match = re.fullmatch(pattern, rid or '', re.I)
                if not match or any(ord(c) <= 32 or ord(c) == 127 for c in rid) or any(x in ('.', '..') for x in rid.split('/')):
                    raise ValueError('foreign ARM workspace')
                raw = reader.call(request, ARM + rid + '?api-version=2024-05-01')
                if not isinstance(raw, dict) or raw.get('id', '').casefold() != rid.casefold() or raw.get('type', '').casefold() != 'microsoft.databricks/workspaces' or not isinstance(raw.get('name'), str) or raw['name'].casefold() != match.group(2).casefold():
                    raise ValueError('ARM workspace GET identity mismatch')
                props = raw.get('properties')
                if not isinstance(props, dict) or props.get('provisioningState') != 'Succeeded':
                    raise ValueError('ARM workspace unavailable')
                wid_raw = props.get('workspaceId')
                if not isinstance(wid_raw, str) or not re.fullmatch(r'[1-9][0-9]{0,18}', wid_raw):
                    raise ValueError('ARM native workspace ID unavailable')
                wid = int(wid_raw)
                row = rows.get(wid)
                if wid in matched or row is None or row['azure_workspace_info']['resource_group'].casefold() != match.group(1).casefold() or row.get('workspace_status') != 'RUNNING':
                    raise ValueError('ARM/account workspace join unavailable')
                matched.add(wid)
                metapath = path + '/' + str(wid) + '/metastore'
                meta = reader.call(transport.request_databricks, HOST + metapath)
                if not isinstance(meta, dict) or meta.get('httpStatus') not in (200, 404):
                    raise ValueError('metastore result unavailable')
                if meta['httpStatus'] == 200:
                    assignment = meta.get('metastore_assignment')
                    if not isinstance(assignment, dict) or type(assignment.get('workspace_id')) is not int or assignment['workspace_id'] != wid or not isinstance(assignment.get('metastore_id'), str) or not 1 <= len(assignment['metastore_id']) <= 1024 or any(ord(c) <= 32 or ord(c) == 127 for c in assignment['metastore_id']):
                        raise ValueError('foreign or malformed metastore assignment')
                    meta = {'httpStatus': 200, 'metastore_assignment': {k: assignment[k] for k in ('workspace_id', 'metastore_id')}}
                elif meta.get('documentedNoAssignment') is not True:
                    raise ValueError('undocumented assignment absence')
                else:
                    # The same endpoint can be requested during workspace deletion.
                    # Prove the account workspace still exists AFTER the 404.
                    current = reader.call(transport.request_databricks, HOST + path + '/' + str(wid))
                    current = project_response(current, path + '/' + str(wid))
                    if current != row:
                        raise ValueError('account workspace changed across assignment absence')
                    meta = {'httpStatus': 404, 'documentedNoAssignment': True}
                output.append({'id': rid, 'accountId': account, 'workspaceId': wid, 'state': 'ACTIVE', 'metastore': meta,
                    '_provenance': {'source_operations': ['ARM.Workspaces.ListBySubscription', 'ARM.Workspaces.Get', 'Account.Workspaces.List', 'Account.MetastoreAssignment.Get'] + (['Account.Workspaces.Get'] if meta['httpStatus'] == 404 else []),
                                    'read_only': True, 'exact_resource_id': rid, 'native_workspace_status': 'RUNNING', 'account_id': account}})
            if matched != set(rows):
                raise ValueError('account workspace universe exceeds complete ARM scope')
            yield output
        jobs.append((KIND, scope, 'Databricks.Account', inventory))
    reader.run(jobs)
