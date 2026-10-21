"""Credential-free GKE image selector used by API save and collector preflight."""
from copy import deepcopy
import ipaddress
import re

OPTION = 'selected_gke_pod_images'
HOSTS = 'selected_registry_hosts'
SECRET_CHECK = 'gcp.review.gke.selected_pod_image_secret_indicators'
VULN_CHECK = 'gcp.review.gke.selected_pod_image_high_vulnerabilities'
MAX_TARGETS = 4
CLUSTER = re.compile(r'projects/([a-z][a-z0-9-]{4,28}[a-z0-9])/locations/([a-z][a-z0-9-]{0,62})/clusters/([a-z][a-z0-9-]{0,38})\Z')
LABEL = re.compile(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z')
POD = re.compile(r'[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?\Z')
TOKEN = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z')
DIGEST = re.compile(r'sha256:[a-f0-9]{64}\Z')
REPOSITORY = re.compile(r'[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*\Z')
FIELDS = {'cluster_id', 'namespace', 'pod', 'uid', 'resource_version', 'container_type', 'container_name', 'image'}


def host(value):
    if (type(value) is not str or not 3 <= len(value) <= 253 or value.lower() != value
            or '.' not in value or any(not LABEL.fullmatch(part) for part in value.split('.'))
            or value.endswith(('.local', '.internal', '.localhost', '.test', '.invalid'))):
        raise ValueError('invalid_registry_host')
    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        raise ValueError('registry_ip_literal_unsupported')
    return value


def image_parts(value):
    if type(value) is not str or len(value) > 512 or value.count('@') != 1:
        raise ValueError('invalid_immutable_image')
    name, digest = value.split('@')
    if not DIGEST.fullmatch(digest) or '/' not in name:
        raise ValueError('invalid_immutable_image')
    registry, repository = name.split('/', 1)
    if host(registry) != registry or not REPOSITORY.fullmatch(repository):
        raise ValueError('invalid_immutable_image')
    return registry, repository, digest


def selected(options, scopes, named=()):
    if (type(options) is not dict or type(scopes) is not list
            or any(key in options and type(options[key]) is not bool
                   for key in ('content_secret_scans', 'image_vulnerability_scans'))):
        raise ValueError('invalid_gke_image_selection')
    if any(key in options for key in ('trivy_db_cache', 'trivy_cli')):
        raise ValueError('trivy_runtime_configuration_is_not_a_request_option')
    active = ((options.get('content_secret_scans') is True and SECRET_CHECK in named)
              or (options.get('image_vulnerability_scans') is True and VULN_CHECK in named))
    if OPTION not in options and not active:
        return []
    rows, hosts = options.get(OPTION), options.get(HOSTS)
    if (type(rows) is not list or not 1 <= len(rows) <= MAX_TARGETS
            or type(hosts) is not list or not 1 <= len(hosts) <= 4
            or len(hosts) != len(set(hosts)) or any(type(h) is not str for h in hosts)):
        raise ValueError('invalid_gke_image_selection')
    for value in hosts:
        host(value)
    authorized = set(scopes)
    seen = set()
    for row in rows:
        if type(row) is not dict or set(row) != FIELDS:
            raise ValueError('invalid_gke_image_selection')
        cluster = row['cluster_id']; match = CLUSTER.fullmatch(cluster) if type(cluster) is str else None
        if not match or 'projects/' + match[1] not in authorized:
            raise ValueError('foreign_gke_cluster')
        namespace, pod = row['namespace'], row['pod']
        if (type(namespace) is not str or not LABEL.fullmatch(namespace)
                or type(pod) is not str or not POD.fullmatch(pod)
                or any(not LABEL.fullmatch(part) for part in pod.split('.'))
                or any(type(row[k]) is not str or not TOKEN.fullmatch(row[k]) for k in ('uid', 'resource_version'))
                or row['container_type'] not in ('regular', 'init', 'ephemeral')
                or type(row['container_name']) is not str or not LABEL.fullmatch(row['container_name'])):
            raise ValueError('invalid_gke_pod_selection')
        registry, _, _ = image_parts(row['image'])
        if registry not in hosts:
            raise ValueError('registry_not_allowlisted')
        key = (cluster, namespace, pod, row['uid'], row['container_type'], row['container_name'])
        if key in seen:
            raise ValueError('duplicate_gke_selection')
        seen.add(key)
    return deepcopy(rows)


def kubernetes_auth(auth, rows):
    """Only exact explicit bearer contexts, no kubeconfig or client key surface."""
    if type(auth) is not dict:
        raise ValueError('invalid_gke_image_auth')
    contexts = auth.get('gke_image_kubernetes', [])
    if type(contexts) is not list or len(contexts) > MAX_TARGETS:
        raise ValueError('invalid_gke_image_auth')
    selected_clusters = {row['cluster_id'] for row in rows}
    output = {}
    for entry in contexts:
        if type(entry) is not dict or set(entry) != {'cluster_id', 'server', 'ca_cert_data', 'token'}:
            raise ValueError('invalid_gke_image_auth')
        cluster, server, ca, token = (entry[k] for k in ('cluster_id', 'server', 'ca_cert_data', 'token'))
        if type(cluster) is not str or cluster not in selected_clusters or cluster in output:
            raise ValueError('foreign_gke_image_auth')
        if type(server) is not str or not server.startswith('https://') or '/' in server[8:] or ':' in server[8:]:
            raise ValueError('invalid_gke_image_server')
        try:
            address = ipaddress.ip_address(server[8:])
        except ValueError:
            raise ValueError('invalid_gke_image_server') from None
        if address.version != 4 or not address.is_global or str(address) != server[8:]:
            raise ValueError('unsupported_gke_image_server')
        if (type(ca) is not str or not 1 <= len(ca) <= 24000 or 'PRIVATE KEY' in ca
                or type(token) is not str or not 1 <= len(token) <= 8192 or not token.isascii()
                or any(ord(char) < 33 or ord(char) > 126 for char in token)):
            raise ValueError('invalid_gke_image_auth')
        output[cluster] = deepcopy(entry)
    return output


def registry_auth(auth, rows, hosts):
    """Pure shape and repository authorization; native reader builds headers later."""
    if type(auth) is not dict:
        raise ValueError('invalid_gke_registry_auth')
    entries = auth.get('registry_auth', [])
    if type(entries) is not list or len(entries) > 2:
        raise ValueError('invalid_gke_registry_auth')
    allowed = {image_parts(row['image'])[:2] for row in rows}
    seen = set()
    for entry in entries:
        if type(entry) is not dict or entry.get('method') not in ('basic', 'bearer'):
            raise ValueError('invalid_gke_registry_auth')
        expected = {'host', 'repository', 'method', 'token'} if entry['method'] == 'bearer' else {'host', 'repository', 'method', 'username', 'password'}
        if set(entry) != expected:
            raise ValueError('invalid_gke_registry_auth')
        key = (entry['host'], entry['repository'])
        if key not in allowed or key[0] not in hosts or key in seen:
            raise ValueError('foreign_gke_registry_auth')
        seen.add(key)
        fields = ('token',) if entry['method'] == 'bearer' else ('username', 'password')
        for field in fields:
            value = entry[field]
            if (type(value) is not str or not 1 <= len(value) <= (512 if field == 'username' else 8192)
                    or not value.isascii() or any(ord(char) < 33 or ord(char) > 126 for char in value)):
                raise ValueError('invalid_gke_registry_auth')
        if entry['method'] == 'basic' and ':' in entry['username']:
            raise ValueError('invalid_gke_registry_auth')
    return True
