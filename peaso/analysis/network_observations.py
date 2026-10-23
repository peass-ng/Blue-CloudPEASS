"""Provider-native network fields that must survive service-specific wrappers.

Observations preserve the native field path. They supplement typed relationships;
they do not turn DNS/IP matches, templates or policy declarations into traffic.
Application content and credential-bearing branches are never traversed.
"""
import re
import json
import ipaddress
from functools import lru_cache
from urllib.parse import urlsplit


def key_name(value):
    return re.sub(r"[^a-z0-9]", "", value.lower())


_OMIT = frozenset("""metadata tags labels annotations provenance environmentvariables environmentvariablesmap
runtimeenvironmentvariables runtimeenvironmentsecrets env appsettings sourceconfiguration
code buildspec script commands command args arguments userdata customdata requesttemplates responsetemplates
requestparameters responseparameters headers httpheaders headermatches customheaders requestheadermodifier responseheadermodifier
connectionstring connectionstrings taskgroups steps payload body content text sql query parameters
airflowconfigurationoptions propertymap propertygroups environmentpropertydescriptions environmentproperties
configvariables headerparameters querystringparameters pathparametervalues inputtemplate
startupscript shutdownscript initscript inlinescript softwareconfig hyperparameters
applicationconfiguration configurationoverrides containeroverrides
""".split())
_CREDENTIAL = re.compile(r"password|secret|token|credential|privatekey|accesskey|presharedkey|sharedkey|authenticationkey|username")
_PSC = r'(?:^psc|enablepsc|disablepsc|privateserviceconnect)'
_CONTEXT = re.compile(r"vpc|subnet|network|privatelink|privateendpoint|privateconnection|firewall|securitygroup|endpoint|dns|ipconfig|tls|ssl|peering|exportpolicy|exportrules|accessrules|ipfilter|" + _PSC + r"|destination|ipam|bgp|route|gateway|peer|interface|bridge|connectivity|localresources|remoteresources")
_LEAF = re.compile(r"vpc|subnet|network|privatelink|privateendpoint|firewall|securitygroup|endpoint|dns|cidr|ipmask|netmask|iprestriction|ipallowlist|allowedclients|"
                   r"(?:^|private|public|ipv4|ipv6|external|internal|eni)ip(?:v4|v6|address|addresses)?$|"
                   r"port(?:s|range|ranges)?$|protocol|publiclyaccessible|publicaccess|internetaccess|internetfacing|"
                   r"hostnetwork|hostname|domainname|fullyqualifieddomainname|allowopen|insecureskip|requiretls|requiressl|scheme$|^url$|status$|state$|"
                   r"^resourcelink$|^membership$|^cluster$|vip$|workerpool$|^connectors$|appgateway|serviceconnection|privateconnection|serviceattachment|" + _PSC + r"|ingress|egress|consumeraccept|ipaddress|iprange|ip(?:address|addresses|enabled|range|ranges|prefix|prefixes)?$|fqdn|internet|enableexternal|^host$|^address(?:es)?$|privateinstance|publicconnectivity|asn$|expressroute|gatewayid|circuitid|nexthop|(?:router|gateway|endpoint|dns)ips$|^ips$")
_CONTEXT_LEAVES = frozenset("""id name arn type mode enabled disabled status state address addresses host hostname uri url
region zone owner ownerid accountid tenantid projectid action priority direction allow deny connectiontype
groupid groupids eni eniip eniipv6 eniid serviceclass connectionpreference endpointtype resourcearn
interface ips mac default defaultroute master bridge vlan mtu localasn peerasn peeraddress peerport
start end rangestart rangeend gateway dst gw routes nameservers search addresses
resourceconfigurationarn privateconnectionresourcearn
identifier resource resourcetype sourcevpces sourceservices allowfrompublic
clients allowedclients deniedclients source sourceip sourceips destination destinationip destinationips
accesstype privilege readonly readwrite rootsquash allsquash squashmode securityflavor nfsv3 nfsv4 kerberosenabled
destinations addressprefix addressprefixes destinationprefix destinationprefixes nexthop nexthoptype nexthopipaddress
assignpublicip associatepublicipaddress directinternetaccess enableprivateenvironment
""".split())


@lru_cache(maxsize=4096)
def _field_traits(key):
    """Only bounded schema field names, never native values or evidence trees."""
    normalized = key_name(key)
    return normalized, bool(_CREDENTIAL.search(normalized)), bool(_LEAF.search(normalized)), bool(_CONTEXT.search(normalized))


def safe_url(value):
    if not isinstance(value, str):
        return value
    prefix = "jdbc:" if value.startswith("jdbc:") else ""
    raw = value[len(prefix):]
    if "://" not in raw:
        return value
    try:
        parsed = urlsplit(raw)
        return prefix + parsed._replace(netloc=parsed.netloc.rsplit("@", 1)[-1], query="", fragment="").geturl()
    except ValueError:
        return "[invalid endpoint URL]"


def network_observations(data, *, network_context=False):
    """Return all retained network attributes without arbitrary application data."""
    observations = []

    def visit(value, path="", context=False):
        if isinstance(value, dict):
            # Already-projected observations are validated below, not recursively
            # interpreted as user-selected field names or application payloads.
            for key, item in value.items():
                traits = _field_traits(key) if type(key) is str and len(key) <= 128 else None
                normalized = traits[0] if traits is not None else key_name(key)
                if normalized == 'metadata' and isinstance(item, dict):
                    for network in multus_networks({'metadata': item}):
                        native_path = f"{path}.metadata.annotations.{network['_annotation']}".lstrip('.')
                        observations.append({'path': native_path, 'name': 'NetworkAttachmentDefinition',
                                             'value': network['namespace'] + '/' + network['name']})
                        for field in ('interface', 'ips', 'mac', 'default', 'defaultRoute'):
                            if field in network:
                                observations.append({'path': native_path, 'name': field, 'value': network[field]})
                if key.startswith("_") or normalized in _OMIT or (traits[1] if traits is not None else _CREDENTIAL.search(normalized)):
                    continue
                if normalized == "environment":
                    if isinstance(item, dict) and isinstance(item.get("workerPools"), list):
                        visit({"workerPools": item["workerPools"]}, f"{path}.{key}".lstrip("."), True)
                    continue
                if key == "NetworkAttributes":
                    if isinstance(item, list):
                        for i, row in enumerate(item):
                            if (isinstance(row, dict) and isinstance(row.get("path"), str) and isinstance(row.get("name"), str)
                                    and not _CREDENTIAL.search(key_name(row["name"]))
                                    and (_LEAF.search(key_name(row["name"])) or key_name(row["name"]) in _CONTEXT_LEAVES
                                         or isinstance(row.get('value'), bool) and any(_CONTEXT.search(key_name(part))
                                             for part in row['path'].split('.')))
                                    and (isinstance(row.get("value"), (str, bool, int, float)) or
                                         isinstance(row.get("value"), list) and all(isinstance(x, (str, bool, int, float)) for x in row["value"]))):
                                sanitized = [safe_url(v) for v in row['value']] if isinstance(row['value'], list) else safe_url(row['value'])
                                observations.append({"path": row["path"], "name": row["name"], "value": sanitized,
                                    "evidence_path": f"{path}.NetworkAttributes[{i}].value".lstrip(".")})
                    continue
                current = f"{path}.{key}".lstrip(".")
                leaf = traits[2] if traits is not None else bool(_LEAF.search(normalized))
                contextual = traits[3] if traits is not None else bool(_CONTEXT.search(normalized))
                interested = (leaf or
                              (context or contextual) and
                              (normalized in _CONTEXT_LEAVES or isinstance(item, bool)))
                nested = context or contextual
                if isinstance(item, (dict, list)):
                    if interested and isinstance(item, list) and all(isinstance(x, (str, bool, int, float)) for x in item):
                        observations.append({"path": current, "name": key, "value": [safe_url(x) for x in item]})
                    else:
                        visit(item, current, nested)
                elif interested and isinstance(item, (str, bool, int, float)):
                    observations.append({"path": current, "name": key, "value": safe_url(item)})
        elif isinstance(value, list):
            for i, item in enumerate(value):
                visit(item, f"{path}[{i}]", context)

    visit(data, context=network_context)
    seen, result = set(), []
    for row in observations:
        identity = (row["path"], repr(row["value"]))
        if identity not in seen:
            result.append(row)
            seen.add(identity)
    return result


def multus_networks(data):
    """Parse only native Multus attachment/status fields, never CNI arguments."""
    meta = data.get('metadata') or {}
    annotations = meta.get('annotations') or {} if isinstance(meta, dict) else {}
    if not isinstance(annotations, dict):
        return []
    result = []
    for key in ('k8s.v1.cni.cncf.io/networks', 'k8s.v1.cni.cncf.io/network-status'):
        text = annotations.get(key)
        if not isinstance(text, str) or len(text) > 1024 * 1024:
            continue
        try:
            entries = json.loads(text) if text.lstrip().startswith(('[', '{')) else text.split(',')
        except ValueError:
            continue
        for entry in entries if isinstance(entries, list) else [entries]:
            if isinstance(entry, str):
                name, _, interface = entry.strip().partition('@')
                entry = {'name': name, **({'interface': interface} if interface else {})}
            if not isinstance(entry, dict) or not isinstance(entry.get('name'), str):
                continue
            parts = entry['name'].split('/')
            namespace = parts[0] if len(parts) == 2 else entry.get('namespace', meta.get('namespace', ''))
            name = parts[-1]
            if len(parts) > 2 or not all(isinstance(s, str) and re.fullmatch(r'[a-z0-9][a-z0-9.-]{0,252}', s) for s in (namespace, name)):
                continue
            row = {'name': name, 'namespace': namespace, '_annotation': key}
            if isinstance(entry.get('interface'), str) and re.fullmatch(r'[a-zA-Z0-9_.-]{1,64}', entry['interface']):
                row['interface'] = entry['interface']
            if isinstance(entry.get('mac'), str) and re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', entry['mac']):
                row['mac'] = entry['mac']
            if isinstance(entry.get('default'), bool):
                row['default'] = entry['default']
            for native, field in (('ips', 'ips'), ('default-route', 'defaultRoute')):
                values = entry.get(native)
                if isinstance(values, list):
                    valid = []
                    for value in values:
                        try:
                            if isinstance(value, str):
                                ipaddress.ip_interface(value)
                                valid.append(value)
                        except ValueError:
                            continue
                    row[field] = valid
            result.append(row)
    return result


def aws_attachment(row):
    """Classify only explicit native AWS resource IDs, never addresses or names."""
    value = row["value"]
    key = key_name(row['name'])
    if key in {'networkresourceid', 'networkparentids'} or key.endswith(('name', 'names', 'url', 'uri')):
        return
    values = value if isinstance(value, list) else [value]
    for i, item in enumerate(values):
        if not isinstance(item, str):
            continue
        original = item
        if item.startswith('arn:') and ':ec2:' in item:
            item = item.rsplit('/', 1)[-1]
        if not re.fullmatch(r'(?:vpc|subnet|sg|eni|vpce)-[a-zA-Z0-9-]+', item):
            continue
        kind = None
        if item.startswith("vpc-") and "endpoint" not in key:
            kind = "vpc"
        elif item.startswith("subnet-"):
            kind = "subnet"
        elif item.startswith("sg-"):
            kind = "security_group"
        elif item.startswith("eni-"):
            kind = "network_interface"
        elif item.startswith('vpce-svc-'):
            kind = 'vpc_endpoint_service'
        elif item.startswith("vpce-"):
            kind = "vpc_endpoint"
        if kind:
            yield row.get("evidence_path", row["path"]) + (f"[{i}]" if isinstance(value, list) else ""), kind, original


def projected_metadata(data, *, identity_fields=()):
    """Minimal identity plus network observations for new metadata API reads."""
    if isinstance(data, list):
        return [projected_metadata(item, identity_fields=identity_fields) if isinstance(item, dict) else item for item in data]
    if not isinstance(data, dict):
        return data
    safe = {key: safe_url(item) for key, item in data.items() if isinstance(item, (str, bool, int, float)) and
            (key in identity_fields or key_name(key) in {"id", "name", "arn", "status", "state", "type"} or
             key_name(key).endswith(("id", "arn", "name", "status", "state", "type", "identifier", "region", "owner"))) and not _CREDENTIAL.search(key_name(key))}
    safe["NetworkAttributes"] = network_observations(data)
    return safe
