"""Bound, read-only Synapse and Load Testing network metadata.

These are data-plane APIs. Their qualified identities are joined to the ARM
parent without claiming that the data-plane path is an ARM collection route.
"""
import re
from urllib.parse import urlsplit, parse_qs

SYNAPSE = 'https://dev.azuresynapse.net'
LOAD_TEST = 'https://cnt-prod.loadtesting.azure.com'


def is_network_audience(audience):
    return audience in {SYNAPSE, LOAD_TEST}


def allowed_route(url, audience):
    parsed = urlsplit(url)
    if (parsed.scheme != 'https' or parsed.port not in (None, 443) or parsed.username
            or parsed.password or parsed.fragment):
        return False
    if audience == SYNAPSE:
        return bool(re.fullmatch(r'[a-z0-9-]{1,63}\.dev\.azuresynapse\.net', parsed.netloc)
            and re.fullmatch(r'/managedVirtualNetworks/[A-Za-z0-9_-]+/managedPrivateEndpoints', parsed.path)
            and parse_qs(parsed.query).get('api-version') == ['2020-12-01'])
    if audience == LOAD_TEST:
        return bool(re.fullmatch(r'[a-z0-9-]+\.[a-z0-9-]+\.cnt-prod\.loadtesting\.azure\.com', parsed.netloc)
            and parsed.path == '/tests' and parse_qs(parsed.query).get('api-version') == ['2022-11-01'])
    return False


def project_response(response, audience):
    from .azure import AzureReadError
    if not isinstance(response, dict) or not isinstance(response.get('value'), list):
        raise AzureReadError('malformed_network_data_list')
    rows = []
    for native in response['value']:
        if not isinstance(native, dict):
            raise AzureReadError('malformed_network_data_row')
        if audience == SYNAPSE:
            props = native.get('properties')
            if not isinstance(props, dict):
                raise AzureReadError('malformed_network_data_properties')
            retained = {k: props[k] for k in ('privateLinkResourceId', 'groupId', 'provisioningState', 'fqdns') if k in props}
            state = props.get('connectionState')
            if isinstance(state, dict) and isinstance(state.get('status'), str):
                retained['connectionState'] = {'status': state['status']}
            rows.append({**{k: native[k] for k in ('id', 'name', 'type') if k in native}, 'properties': retained})
        elif audience == LOAD_TEST:
            retained = {k: native[k] for k in ('testId', 'subnetId', 'publicIPDisabled') if k in native}
            configuration = native.get('loadTestConfiguration', {})
            optional = configuration.get('optionalLoadTestConfig', {}) if isinstance(configuration, dict) else {}
            if isinstance(optional, dict) and isinstance(optional.get('endpointUrl'), str):
                from peaso.analysis.network_observations import safe_url
                retained['endpointUrl'] = safe_url(optional['endpointUrl'])
            rows.append(retained)
        else:
            raise AzureReadError('unsupported_network_data_audience')
    return {'value': rows, **({'nextLink': response['nextLink']} if 'nextLink' in response else {})}


def child_pages(reader, request, parent, kind):
    from .azure import AzureReadError
    rid = parent['id']
    props = parent.get('properties', {})
    if kind == 'synapse_workspace':
        network = props.get('managedVirtualNetwork')
        if not network:
            yield []
            return
        if not isinstance(network, str) or not re.fullmatch(r'[A-Za-z0-9_-]+', network):
            raise AzureReadError('untrusted_synapse_managed_network')
        endpoint = props.get('connectivityEndpoints', {}).get('dev')
        if not isinstance(endpoint, str) or endpoint.rstrip('/') != 'https://' + rid.rsplit('/', 1)[-1].lower() + '.dev.azuresynapse.net':
            raise AzureReadError('untrusted_synapse_network_endpoint')
        url = endpoint.rstrip('/') + '/managedVirtualNetworks/' + network + '/managedPrivateEndpoints?api-version=2020-12-01'
        audience, prefix = SYNAPSE, rid + '/managedVirtualNetworks/' + network + '/managedPrivateEndpoints/'
        native_type = 'Microsoft.Synapse/workspaces/managedVirtualNetworks/managedPrivateEndpoints'
    elif kind == 'load_test_resource':
        endpoint = props.get('dataPlaneURI')
        if not isinstance(endpoint, str):
            raise AzureReadError('load_test_network_endpoint_missing')
        endpoint = endpoint if endpoint.startswith('https://') else 'https://' + endpoint
        url = endpoint.rstrip('/') + '/tests?api-version=2022-11-01'
        audience, prefix = LOAD_TEST, rid + '/tests/'
        native_type = 'Microsoft.LoadTestService/loadTests/tests'
    else:
        raise AzureReadError('unsupported_network_data_parent')
    if not allowed_route(url, audience):
        raise AzureReadError('untrusted_network_data_endpoint')
    for page in reader.pages(request, url, audience=audience):
        rows = project_response({'value': page}, audience)['value']
        result = []
        for row in rows:
            name = row.get('name') if audience == SYNAPSE else row.get('testId')
            if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9_-]+', name):
                raise AzureReadError('malformed_network_data_identity')
            if row.get('id', prefix + name).casefold() != (prefix + name).casefold():
                raise AzureReadError('network_data_identity_outside_parent')
            result.append(dict(row, id=prefix + name, name=name, type=native_type,
                               networkDataPlaneParent=rid))
        yield result
