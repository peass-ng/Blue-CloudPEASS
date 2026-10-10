# Native Azure and Kubernetes collection

`peaso.collectors.azure.collect(connector, requirements=None)` and
`peaso.collectors.k8s.collect(connector, requirements=None)` return sealed schema
1.0 snapshots. Collection envelopes contain native metadata, scope, service,
status, items and sanitized error codes. `requirements` selects inventory types;
`options.inventories` supplies the selection when requirements are omitted.
Supporting parent inventories are collected when a requested child needs them.
Collectors do not run Steampipe, Powerpipe or Prowler.

## Budgets and evidence

| Option | Default | Allowed range | Meaning |
| --- | --- | --- | --- |
| `concurrency` | 4 | 1–16 | Concurrent API reads |
| `max_calls` | 200 | 1–10,000 | Total read attempts, including retries |
| `max_pages` | 10 | 1–100 | Pages per list operation |
| `max_resources` | 10,000 | 1–100,000 | Total retained inventory records |
| `page_size` | 200 | 1–1,000 | Kubernetes and Resource Graph list size |
| `retries` | 2 | 0–5 | Additional attempts for HTTP 429/500/502/503/504 |
| `activity_days` | 30 | 1–90 | Azure management/directory audit request window |

The scheduler limits concurrent requests and counts retries against the shared
call budget. Retry backoff is bounded. Budget exhaustion produces `partial`
coverage, including when no records could be retained. Failed pagination keeps
earlier evidence. Repeated tokens, malformed lists and changed Kubernetes list
resource versions cannot produce complete coverage. Results distinguish `empty`,
`denied`, `malformed`, `timeout`, `unknown` and `partial`.
Owned Kubernetes transports disable SDK retries and redirects so hidden attempts
cannot bypass the collector's budget or hosted destination pinning.

Azure continuation links must retain their HTTPS origin and list path. Redirects
are rejected before credentials can be forwarded. Kubernetes continuation tokens
are query parameters on fixed allowlisted list paths. Errors contain a class name
and bounded code, never exception bodies or bearer credentials.

## Azure

Subscription scopes accept subscription IDs or `/subscriptions/<id>`. Empty
scopes or `*` discover accessible subscriptions, bounded to 100 scopes. Explicit
scopes constrain resource detail reads. Tenant and subscription discovery record
only what the selected identity can read; visibility never implies access to every
resource in the tenant.

| Authentication | Fields in `auth` |
| --- | --- |
| Client secret | `method: client-secret`, `tenant_id`, `client_id`, `client_secret` |
| Client certificate | `method: client-cert`, `tenant_id`, `client_id`, `certificate_path` or inline `certificate_data`/`client_certificate`; optional `certificate_password` |
| Azure CLI | `method: az-cli`, optional `tenant_id` |
| DefaultAzureCredential | `method: default` or `auto`; optional `tenant_id`, `client_id` |
| Managed identity | `method: managed-identity`, optional user-assigned `client_id` |
| Workload identity | `method: workload-identity`, `tenant_id`, `client_id`, local `token_file` or inline `federated_token` OIDC assertion |
| Device code | `method: device-code`, `tenant_id`, `client_id`; explicitly interactive |
| Direct tokens | `method: token`, `arm_token` or legacy `token`, optional separate `graph_token`, optional `tenant_id` |

An explicit method selects that credential source. Automatic mode infers supplied
client credentials or uses the default chain; interactive authentication requires
the device-code method. SDK credentials request fixed ARM and Microsoft Graph
`/.default` scopes. ARM and Graph tokens remain separate and refresh before
expiry. When a token exposes tenant/audience claims, mismatches fail before the
API request. Claims are routing checks; the Azure service authenticates the token.
The first observed tenant pins subsequent token requests. Direct ARM tokens do not
silently acquire Graph access from another identity.

Resource Graph discovers resource IDs and types before authoritative ARM lists.
Those lists reconcile membership and provide native detail; thin list records
receive detail GETs. Resource Graph is eventually consistent, so a completed or
empty query never establishes authoritative membership by itself. Denied,
malformed or truncated discovery does not prevent independent ARM reads.
A failed detail retains its authoritative ID and explicit unavailable
detail evidence; it does not reuse potentially stale discovery properties as
verified detail.

| Area | Native collection types and facts |
| --- | --- |
| Scope and IAM | `subscription`, `tenant`, `management_group`, `role_assignment`, `role_definition`, `deny_assignment`; accessible management group parents/children, subscription/management group/root assignment lists |
| Permission semantics | Native `actions`, `notActions`, `dataActions`, `notDataActions`, assignment scope, principal IDs, conditions/version, deny principals/exclusions and child-scope flags |
| Virtual networking | `vnet`, `subnet`, `vnet_peering`, `nsg`, `route_table`, `nic`, `vm`; address ranges, NSG rule priorities, native association/reference IDs, routes, peerings and interfaces |
| Edge networking | `load_balancer`, `application_gateway`, `public_ip`, `private_endpoint`; native frontend/backend/listener and endpoint references |
| DNS | `dns_zone`, `dns_record`, `private_dns_zone`, `private_dns_link` |
| Storage | `storage_account`, `storage_service`; account TLS/public access/network restrictions/encryption and blob/file/queue/table service settings |
| SQL | `sql_server`, `sql_database`, `sql_firewall_rule`, `sql_audit`, `sql_security` |
| AKS | `aks_cluster`; ARM cluster configuration, identity, network and access settings |
| Vault | `vault`, `secret_metadata`; ARM secret-list metadata only |
| Diagnostics | `diagnostic_setting` per discovered parent, `activity_log`; requested management event window and native event IDs |
| Entra directory | `directory_user`, `directory_group`, `directory_service_principal`, `directory_application`, `directory_role_assignment`, `directory_role_definition`, `directory_audit`, `directory_membership` |

Role definitions retain exclusions: NotActions is an exclusion from a grant, not
an independent deny. Data and control permissions stay separate. Conditions and
deny assignments remain facts for offline interpretation; this collector does
not compute effective access. Management group/root reads can independently be
denied. Directory collections use selected fields for users, groups, applications
and service principals, and direct group-member links; inaccessible Graph reads
produce explicit `metadata.directory_coverage` and collection failures.
Root role-assignment enumeration uses the required `atScope()` filter; it never
elevates access or changes role assignments.

`metadata.activity_window` contains the requested start/end and explicitly marks
overall completeness false: retention, directory access and data-plane history
are not all verified. Successful management-event pagination establishes only
completion of that API request. Missing activity never proves unused permission.
Secret values, access keys, connection strings, VM passwords/custom data and
protected settings are omitted. No listKeys, credential export, secret-value GET,
cluster credential generation, or mutating ARM operation is called. Resource
Graph POST is a read-only query.

Collection limits remain explicit: effective NIC routes/NSGs, DNS runtime
resolution, SQL data-plane activity, object-level storage contents, private DNS
record sets and full transitive/PIM directory authorization are not inferred.
Subscription discovery may include inaccessible tenant resources only as scope
metadata; selected subscription scans fetch details within their selected scope.

## Kubernetes

`scopes` are namespace names or `*`; cluster-scoped inventory is read once under
the first selected scope. Namespaced endpoints are constructed separately for each
namespace. A returned object from another namespace is malformed evidence.
Namespaces are administrative containers, never IP subnets.

| Authentication | Fields in `auth` |
| --- | --- |
| Local kubeconfig | `method: kubeconfig`, optional `kubeconfig`, `context`; official loader uses current context and supports trusted exec helpers |
| In cluster | `method: in_cluster` or `in_cluster: true`; service account token and CA via official loader |
| Direct bearer | `server`, `token` or `token_file`, optional `ca_cert` |
| Client TLS | `server`, `client_cert`, `client_key`, optional `ca_cert` |
| Inline kubeconfig | `kubeconfig_data` mapping or YAML string, optional `context`; token or inline certificate material |
| Inline TLS | `server`, `ca_cert_data`, `client_cert_data`, `client_key_data`; PEM strings or base64 data, with bearer token as needed |

Direct servers require HTTPS and verified TLS. Certificate/key pairs must be
complete. Existing EKS, GKE and AKS kubeconfigs work through the official loader
and installed provider exec/auth helpers. The collector does not create cloud
cluster credentials, install helpers or change kubeconfig/cluster state.

`auth.cluster_id` can supply the provider's authoritative EKS ARN, GKE full cluster
name or AKS ARM ID. Otherwise the API origin digest distinguishes clusters, with
`metadata.cluster_id_source` identifying that fallback. Object IDs include the
cluster, inventory kind, namespace and Kubernetes UID (name fallback when UID is
absent). Native metadata retains owner references, labels, resource versions and
identity annotations. Encrypted credentials never enter these IDs or snapshots.

| Area | Native collection types |
| --- | --- |
| RBAC | `role`, `clusterrole`, `rolebinding`, `clusterrolebinding`, `serviceaccount` |
| Workloads | `pod`, `deployment`, `daemonset`, `statefulset`, `replicaset`, `job`, `cronjob` |
| Cluster scope | `namespace`, `node` |
| Network declarations | `service`, `endpointslice`, `ingress`, `networkpolicy` |
| Admission | `admission_configuration`; validating/mutating webhook metadata |
| Observed addresses | `network_interface`; derived node/pod status addresses with provenance and `authoritative_interface_inventory: false` |

Rules, roleRef, subjects, selectors, policyTypes, IP blocks, pod service accounts
and node/network references stay native. Workload literal environment values,
commands/arguments, managedFields and arbitrary annotations are omitted; secret
references and selected identity/network annotations remain metadata. No Secret
objects, Secret values, pod exec, pod logs, node proxy or writes are read/called.
`metadata.usage_evidence` is unknown because runtime/audit history is not fetched.
`metadata.network_policy_enforcement` is unknown because a NetworkPolicy object
cannot establish CNI implementation or runtime enforcement. Derived addresses
cannot establish the authoritative network-interface inventory.

## Hosted credential boundary

The API worker must set `options.hosted: true` for tenant-owned hosted jobs.
Azure then requires tenant-provided inline client credentials or direct tokens;
ambient identity and input filesystem paths are rejected. Inline certificates go
directly to CertificateCredential as bytes.
Inline federation uses ClientAssertionCredential with the supplied OIDC assertion;
the caller must supply an assertion valid for the collection window.

Hosted Kubernetes requires an explicit server or inline kubeconfig. Ambient
kubeconfig/in-cluster credentials and arbitrary filesystem paths are rejected.
Inline kubeconfigs always reject exec/auth-provider helpers, local file references,
proxy overrides and insecure TLS. Hosted destinations must resolve entirely to
public addresses; the selected validated IP is pinned while TLS SNI and certificate
hostname validation use the original server name. This excludes private-cluster
endpoints in the hosted collector; local trusted kubeconfigs can reach them.
Inline CA/certificate/key material is materialized in private temporary files
with mode 0600 and cleaned when the owned API client closes.

## Verification

Run `.venv/bin/python -m pytest tests/test_peaso_collectors_azurek8s.py -q`.
The fake SDK/API suite covers method selection, tenant/audience pinning, direct
tokens/TLS, kubeconfig/context/in-cluster loaders, denied and failed auth, safe
pagination, malformed responses, scope isolation, concurrency/retries/global
budgets, inherited permission semantics, secret-field redaction, temporary file
cleanup and hosted destination validation.

On 2026-10-10, a live read-only scan using the current Azure CLI identity made
three API reads with `max_calls: 4`, `max_pages: 1`, `concurrency: 1`, `retries: 0`:
subscription enumeration retained 50 records and reported partial coverage at the
page cap; Resource Graph collected one resource; the selected subscription's
resource-group API collected two groups. No auth material or resource contents
were persisted. A live Kubernetes scan was unavailable because the local
kubeconfig had no current context. Fake tests do not establish live coverage of
every Azure service or Kubernetes distribution.
An additional bounded root role-assignment read returned four assignments after
applying the documented `atScope()` filter; the unfiltered endpoint had returned
HTTP 400 in the coordinator's broader scan.

API behavior references: [Azure Resource Graph REST queries](https://learn.microsoft.com/en-us/rest/api/azureresourcegraph/resourcegraph/resources/resources),
[Azure deny assignments](https://learn.microsoft.com/azure/role-based-access-control/deny-assignments),
[Azure root assignment listing](https://learn.microsoft.com/en-us/azure/role-based-access-control/elevate-access-global-admin),
[Azure Identity credentials](https://github.com/Azure/azure-sdk-for-python/tree/main/sdk/identity/azure-identity),
[Kubernetes list pagination](https://kubernetes.io/docs/reference/using-api/api-concepts/),
[NetworkPolicy API](https://kubernetes.io/docs/reference/kubernetes-api/networking/network-policy-v1/).
