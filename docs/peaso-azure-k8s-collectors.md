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
| `concurrency` | 12 | 1–32 | Concurrent API reads |
| `max_calls` | No implicit cap | Positive integer | Explicit total read-attempt limit, including retries |
| `max_pages` | No implicit cap | Positive integer | Explicit pages per list operation |
| `max_resources` | No implicit cap | Positive integer | Explicit retained-inventory limit |
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
scopes or `*` discover accessible subscriptions; `max_scopes` can set an explicit positive limit. Explicit
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
| Direct tokens | `method: token`, `arm_token` or legacy `token`, optional separate `graph_token`, `vault_token`, `storage_token`, `logs_token`, optional `tenant_id` |

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
| Compute disks | `disk`; encryption and upload/export network/authentication metadata; no SAS or disk contents |
| App Service | `app_service`, `app_service_config`; safe site/configuration fields only, excluding app settings and publishing credentials |
| Defender | `security_pricing`; pricing plan configuration and declared tier, without asset/sensor coverage claims |
| Vault | `vault`, `secret_metadata`; ARM secret-list metadata only |
| Diagnostics | `diagnostic_setting` per discovered parent, `activity_log`; requested management event window and native event IDs |
| Entra directory | `directory_user`, `directory_group`, `directory_service_principal`, `directory_application`, `directory_role_assignment`, `directory_role_definition`, `directory_audit`, `directory_membership` |

HackTricks Cloud Best Practices reads (all GET, paginated where the API lists,
bounded by the shared call/page budgets; denied/partial reads keep explicit
`_coverage` and never become empty):

| Read | API call | Permission | Kept |
| --- | --- | --- | --- |
| `app_service.scmBasicAuthPolicy` / `ftpBasicAuthPolicy` | `GET {site}/basicPublishingCredentialsPolicies/scm` and `/ftp` (2023-12-01) | `Microsoft.Web/sites/basicPublishingCredentialsPolicies/read` (Reader) | `properties.allow` only |
| `app_service.configuration` | existing `GET {site}/config/web` | `Microsoft.Web/sites/config/read` | adds `scmIpSecurityRestrictionsUseMain` |
| `automation_account.webhooks` | `GET {account}/webhooks` (2015-10-31) | `Microsoft.Automation/automationAccounts/webhooks/read` (Reader) | name, isEnabled, expiry/creation/lastInvoked/lastModified times, runOn, runbook name; never `uri` or `parameters` |
| `synapse_workspace.firewallRules` | `GET {workspace}/firewallRules` (2021-06-01) | `Microsoft.Synapse/workspaces/firewallRules/read` (Reader) | start/end IP ranges |
| `web_pubsub` | `GET /subscriptions/{sub}/providers/Microsoft.SignalRService/webPubSub` (2023-02-01) | `Microsoft.SignalRService/webPubSub/read` (Reader) | disableLocalAuth, network ACL/public access metadata; access keys never listed |
| `directory_service_principal` | `$select` adds `passwordCredentials,keyCredentials,preferredSingleSignOnMode` | Graph `Application.Read.All` (or `Directory.Read.All`) | credentials reduced to `keyId`/`endDateTime` |
| `directory_federated_credential` (one envelope per app) | `GET /v1.0/applications/{id}/federatedIdentityCredentials?$select=id,name,issuer,subject,audiences` | Graph `Application.Read.All` | issuer, subject, audiences; unknown when the application list is not complete |
| `directory_cba_configuration` | `GET /v1.0/organization?$select=id`, then `GET /v1.0/organization/{id}/certificateBasedAuthConfiguration` | Graph `Organization.Read.All` (or `Directory.Read.All`) | CA issuer, issuerSki, isRootAuthority, CRL URLs; CA certificates dropped |

Role definitions retain exclusions: NotActions is an exclusion from a grant, not
an independent deny. Data and control permissions stay separate. Conditions and
deny assignments remain facts for offline interpretation; this collector does
not compute effective access. Management group/root reads can independently be
denied. Directory collections use selected fields for users, groups, applications
and service principals, and direct group-member links; inaccessible Graph reads
produce explicit `metadata.directory_coverage` and collection failures.
Root role/deny-assignment enumeration uses the required `atScope()` filter; it never
elevates access or changes role assignments.

`metadata.activity_window` contains the requested start/end and explicitly marks
overall completeness false: retention, directory access and data-plane history
are not all verified. Successful management-event pagination establishes only
completion of that API request. Missing activity never proves unused permission.
Secret values, access keys, connection strings, VM passwords/custom data and
protected settings are omitted. App Service configuration retains an allowlist of
safe settings; application settings, machine keys and credential material are
excluded. `sql_tde` reads user database encryption metadata and skips master.
No listKeys, credential export, secret-value GET,
cluster credential generation, or mutating ARM operation is called. Resource
Graph POST is a read-only query.

Collection limits remain explicit: effective NIC routes/NSGs, DNS runtime
resolution, SQL data-plane activity, object-level storage contents, private DNS
record sets and full transitive/PIM directory authorization are not inferred.
Subscription discovery may include inaccessible tenant resources only as scope
metadata; selected subscription scans fetch details within their selected scope.

### Optional selected app-settings secret scanning

Standard Azure inventory omits application-setting values. To inspect literal
settings for App Service or Azure Functions, explicitly name
`azure.review.app_service.selected_app_settings_secret_indicators`, set
`options.content_secret_scans` to `true`, and supply
`options.selected_azure_app_settings`: an array of 1–8 unique, exact native site
or deployment-slot resource IDs. Use explicit `/subscriptions/<UUID>` scopes
containing those resources. Broad category/framework selection does not enable
content reads; no sites or slots are enumerated.

```json
{
  "connector": {
    "provider": "azure",
    "scopes": ["/subscriptions/11111111-1111-1111-1111-111111111111"],
    "options": {
      "content_secret_scans": true,
      "selected_azure_app_settings": [
        "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/example/providers/Microsoft.Web/sites/example-app",
        "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/example/providers/Microsoft.Web/sites/example-app/slots/staging"
      ]
    }
  },
  "checks": ["azure.review.app_service.selected_app_settings_secret_indicators"]
}
```

Reader alone is insufficient for these optional sensitive reads. Grant only the
following actions at the selected sites or slots; Contributor and write
permissions are unnecessary. The `config/list/Action` permission can expose other
sensitive configuration through Azure, although this reader calls only the
app-settings endpoint.

| Selected resource | Native API (2025-03-01) | Required action |
| --- | --- | --- |
| Site identity | `GET {site}` | `Microsoft.Web/sites/read` |
| Site literal app settings | `POST {site}/config/appsettings/list` | `Microsoft.Web/sites/config/list/Action` |
| Slot identity | `GET {site}/slots/{slot}` | `Microsoft.Web/sites/slots/read` |
| Slot literal app settings | `POST {site}/slots/{slot}/config/appsettings/list` | `Microsoft.Web/sites/slots/config/list/Action` |

These POST operations are documented reads, with no request payload or mutation.
Only the fixed `management.azure.com` ARM origin is used. The returned identity
must match the selected resource before literal values are scanned. Documented
Key Vault references are excluded without resolution; no Key Vault secret-value
permission is needed. A selection containing only references or empty literals
remains UNKNOWN because no literal content was inspected.

Both pinned offline engines, Kingfisher 1.4.0 and TruffleHog 3.92.5, must complete
for PASS. Credential verification is disabled. Exact matching leaks are merged
across engines and selected sites; values, setting names and native resource
names are not exported. Reads use memory only, with no content files: at most
2 MiB per response, 8 MiB across native responses, 512 settings, 64 KiB per value,
256 KiB of literal content per selected resource, and a shared 60-second deadline.
Denied, deleted, omitted, unsupported, partial, oversized or failed reads/scans
remain UNKNOWN. Coverage applies only to the selected observed literal settings,
not source packages, connection strings, images, logs, unselected slots, secret
stores or credential validity.

API and permission references: [site app settings](https://learn.microsoft.com/en-us/rest/api/appservice/web-apps/list-application-settings?view=rest-appservice-2025-03-01),
[slot app settings](https://learn.microsoft.com/en-us/rest/api/appservice/web-apps/list-application-settings-slot?view=rest-appservice-2025-03-01),
[Microsoft.Web actions](https://learn.microsoft.com/en-us/azure/role-based-access-control/permissions/web-and-mobile),
and [Key Vault reference syntax](https://learn.microsoft.com/en-us/azure/app-service/app-service-key-vault-references).

### Optional selected ACR image secret scanning

To inspect private Azure Container Registry image content, name
`azure.review.acr.selected_image_secret_indicators` in `checks`, set
`options.content_secret_scans` to `true`, and supply
`options.selected_azure_acr_images`: an array of 1–4 exact objects with
`registry_id`, `repository` and immutable `digest` fields. Use explicit matching
`/subscriptions/<UUID>` scopes. Tags, URLs, wildcard scopes and broad
category/framework selection cannot enable these reads.

```json
{
  "content_secret_scans": true,
  "selected_azure_acr_images": [{
    "registry_id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/example/providers/Microsoft.ContainerRegistry/registries/exampleregistry",
    "repository": "team/application",
    "digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
  }]
}
```

Replace the example digest with the selected image's actual manifest SHA256.
Grant `Microsoft.ContainerRegistry/registries/read` on the selected registry for
its native identity and endpoint metadata. Image pulls need separate content
rights: **AcrPull** in classic RBAC mode, or **Container Registry Repository
Reader** with the appropriate repository condition in ABAC-enabled mode. ARM
Reader alone is insufficient; the ABAC Repository Catalog Lister role is
unnecessary for exact repository selections. No Contributor, write, push,
admin-user credential export or `listCredentials` permission is requested.

| Read | Native route | Authority |
| --- | --- | --- |
| Registry identity/endpoints/mode | `GET {registry_id}?api-version=2025-11-01` at `management.azure.com` | Registry metadata read |
| Existing Entra token exchange | `POST /oauth2/exchange` at the verified native login server | Fixed ACR audience preferred; ARM fallback only when explicitly allowed |
| Repository pull token | `POST /oauth2/token` at that same server | Only `repository:<exact repository>:pull` scope |
| Immutable manifest/config/layers | `GET /v2/<repository>/manifests/<sha256>` and `/blobs/<sha256>` | Exact repository content-read rights above |

The reader uses the existing Azure credential configuration. It reads native
registry identity with an ARM token, then requests the fixed Entra audience
`https://containerregistry.azure.net/.default` through the existing SDK credential
for exchange, requiring the same verified tenant. This supports hardened
ACR-audience-only registries without changing their policy. If that audience is
unavailable, an existing ARM token is used only when the native registry response
explicitly reports ARM-audience authentication enabled. A direct ARM-only token
connector with no SDK credential remains UNKNOWN on hardened registries; do not
weaken their policy for scanning. No new registry username/password, Docker
configuration, managed identity source, challenge-supplied realm or external auth
URL is used. Expired, foreign or broader-than-pull registry tokens are rejected;
invalid ACR tokens never trigger ARM fallback.

The ARM response must bind the selected registry ID to its public Azure ACR
login server. Blob downloads may follow one native 307 redirect only to an exact
registry-specific `dataEndpointHostNames` entry returned by ARM, with no bearer
token forwarded. Default redirects to wildcard Azure Storage hosts, regional
login aliases, sovereign clouds and additional redirects are unsupported and
remain UNKNOWN. Existing dedicated data endpoints may be used; this reader does
not enable endpoints or alter network policy.

Every manifest, config and layer is checked against the selected/declared SHA256
and size. Both pinned offline scanners must complete for manifest/config bytes,
decoded JSON strings, and each supported layer file. Only single-platform Linux
amd64/arm64 OCI or Docker schema-2 images are supported. Multiarch indexes,
foreign layers, duplicate descriptors, zstd, links/devices, nested archives,
malformed or partial TARs, and unsupported content stay UNKNOWN. Layers are
inspected individually, including files deleted by later whiteouts; no container
is executed and no filesystem extraction occurs.

Bounds are shared across the explicit selection: 4 images, 160 native HTTP
calls, 64 MiB transferred and 120 seconds; per image, 16 layers, 16 MiB compressed,
32 MiB expanded and 2,000 members. Individual limits are 256 KiB per manifest,
1 MiB per config and 8 MiB per compressed or expanded layer. Reads and parsing
use memory only; responses/connections close on every path. Values, native
repository names, registry tokens, signed redirect URLs and original file paths
are absent from exported evidence. Exact-value detections are redacted and
merged across engines, files and selected images; credentials are never verified.
PASS describes only the selected observed supported bytes and detector rules,
not all registries, running workloads, history, secret stores or secret formats.

References: [native registry GET](https://learn.microsoft.com/en-us/rest/api/container-registry/registries/get?view=rest-container-registry-2025-11-01),
[ACR token exchange](https://github.com/Azure/acr/blob/main/docs/AAD-OAuth.md),
[ACR read roles](https://learn.microsoft.com/en-us/azure/container-registry/container-registry-rbac-built-in-roles-directory-reference),
[ARM audience policy](https://learn.microsoft.com/en-us/azure/container-registry/container-registry-disable-authentication-as-arm),
and [dedicated data endpoints](https://learn.microsoft.com/en-us/azure/container-registry/container-registry-dedicated-data-endpoints).

### Optional selected ARM configuration and source literals (local proposal)

The proposed check `azure.review.configuration.selected_content_secret_indicators`
is unregistered until native admission. After admission, enable
`content_secret_scans: true`, name that exact check, and supply
`selected_azure_configuration_content` with 1–8 unique exact selectors. Each
selector has exactly `surface` and `resource_id`; every ID must belong to an
explicitly selected subscription. Bulk check selection does not authorize reads.

```json
{
  "content_secret_scans": true,
  "selected_azure_configuration_content": [
    {
      "surface": "vm_userdata",
      "resource_id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/example/providers/Microsoft.Compute/virtualMachines/selected-vm"
    }
  ]
}
```

All requests are authenticated GETs to `management.azure.com`. Grant only the
following existing read actions at the selected resource scope, subject to Azure's
supported RBAC assignment scopes. Automation documents account-level scope; use
the narrow account containing the selected runbook or variable. No permission is
created or expanded by the reader. An appropriately scoped Reader assignment
normally includes these management-plane reads; no Contributor, write, decrypt,
list-secrets, exec, deployment, runbook-start or policy-test action is needed.

| `surface` | Selected native fields / API version | Minimum read action |
| --- | --- | --- |
| `aci_literals` | Container and init-container `properties.environmentVariables[].value` and `command[]`; `2023-05-01` | `Microsoft.ContainerInstance/containerGroups/read` |
| `container_app_literals` | Current `properties.template` container/init-container literal `env[].value`, `command[]`, `args[]`; `2024-03-01` | `Microsoft.App/containerApps/read` |
| `logic_workflow` | Current `properties.definition` strings; `2016-06-01` | `Microsoft.Logic/workflows/read` |
| `vm_userdata` | `properties.userData` using `GET {id}?api-version=2025-04-01&$expand=userData`; canonical Base64 UTF-8, at most 64 KiB decoded | `Microsoft.Compute/virtualMachines/read` |
| `vmss_model_userdata` | `properties.virtualMachineProfile.userData` with the same expansion/version; model only, no VM instance claim | `Microsoft.Compute/virtualMachineScaleSets/read` |
| `vm_extension_settings` | Selected extension `properties.settings`; `2025-04-01` | `Microsoft.Compute/virtualMachines/extensions/read` |
| `image_builder_inline` | Shell/PowerShell `properties.customize[].inline[]`; `2022-07-01` | `Microsoft.VirtualMachineImages/imageTemplates/read` |
| `automation_runbook` | Published supported text runbook identity GET, then `GET {runbook-id}/content`; `2023-11-01` | `Microsoft.Automation/automationAccounts/runbooks/read` and `Microsoft.Automation/automationAccounts/runbooks/content/read` |
| `automation_variable` | JSON-serialized `properties.value` only when `isEncrypted` is explicitly false; `2023-11-01` | `Microsoft.Automation/automationAccounts/variables/read` |
| `apim_policy` | Exact global/API/operation `/policies/policy` child, `properties.value` returned as `rawxml`; `2024-05-01&format=rawxml` | `Microsoft.ApiManagement/service/policies/read`, `service/apis/policies/read` or `service/apis/operations/policies/read`, matching the selected level |

Runbook reads support published PowerShell, PowerShellWorkflow, PowerShell72,
Python2 and Python3 text only. Graphical, draft and unsupported encodings are
unresolved. APIM selection supports the global child, an exact API (including a
safe literal revision suffix), or an exact operation child; policies at other
scopes, named values and fragments are not fetched. Logic Apps Standard
`Microsoft.Web/sites` source files are outside this ARM workflow surface.

`customData` is not recoverable through this reader. Protected extension settings,
ACI secure values, Container Apps secret references and encrypted Automation
variables are intended-store exclusions and are never decrypted or dereferenced.
External scripts, links, inherited APIM policies, fragments and named values are
not followed. Masks, binary/empty/unsupported content, missing facts or references
prevent a clean result. A directly observed credential literal remains a finding
with incomplete coverage when another portion or detector is unavailable.

Reads are serial and bounded: 8 targets, 16 GET attempts, 2 MiB per response,
8 MiB total wire bytes, 256 KiB inspected literals per resource, and a shared
120-second deadline. Configured collector cancellation/call/resource bounds also
apply. Content is memory-only and never executed. Both pinned offline detectors
must complete for PASS; credentials are never validated. Exact-value HMACs merge
repeated detections with other readers. Only opaque selected-object locators,
counts, bounded request receipts and redacted findings reach snapshots/caches;
the union of detected values is scrubbed from mixed-inventory metadata too.
Coverage describes the selected current literals, not all subscriptions, history,
running environments, external content or every possible secret format.

Primary contracts: [ACI GET](https://learn.microsoft.com/en-us/rest/api/container-instances/container-groups/get?view=rest-container-instances-2023-05-01),
[Container Apps GET](https://learn.microsoft.com/en-us/rest/api/resource-manager/containerapps/container-apps/get?view=rest-resource-manager-containerapps-2024-03-01),
[workflow GET](https://learn.microsoft.com/en-us/rest/api/logic/workflows/get?view=rest-logic-2016-06-01),
[VM GET](https://learn.microsoft.com/en-us/rest/api/compute/virtual-machines/get?view=rest-compute-2025-04-01),
[VMSS GET](https://learn.microsoft.com/en-us/rest/api/compute/virtual-machine-scale-sets/get?view=rest-compute-2025-04-01),
[extension GET](https://learn.microsoft.com/en-us/rest/api/compute/virtual-machine-extensions/get?view=rest-compute-2025-04-01),
[Image Builder GET](https://learn.microsoft.com/en-us/rest/api/imagebuilder/virtual-machine-image-templates/get?view=rest-imagebuilder-2022-07-01),
[runbook content](https://learn.microsoft.com/en-us/rest/api/automation/runbook/get-content?view=rest-automation-2023-11-01),
[variable GET](https://learn.microsoft.com/en-us/rest/api/automation/variable/get?view=rest-automation-2023-11-01),
[APIM global](https://learn.microsoft.com/en-us/rest/api/apimanagement/policy/get?view=rest-apimanagement-2024-05-01),
[API](https://learn.microsoft.com/en-us/rest/api/apimanagement/api-policy/get?view=rest-apimanagement-2024-05-01)
and [operation](https://learn.microsoft.com/en-us/rest/api/apimanagement/api-operation-policy/get?view=rest-apimanagement-2024-05-01).

## Kubernetes

### Kubelet ConfigMap declarations

The eight `k8s.review.kubelet_configmap.*` checks read explicit settings from
ConfigMaps whose names start with `kubelet-config`. They use metadata-only
ConfigMap LISTs in the selected namespaces, then GET only those matching names.
The full GET must match the discovered namespace, name, UID and resourceVersion.
This is a normal configuration inventory; it does not enable content secret
scanning. Other ConfigMaps receive no content GET.

The checks assess explicit Webhook authorization, a client CA path declaration,
disabled anonymous authentication, disabled read-only port, client certificate
rotation, a fixed explicit cipher allowlist, certificate/key path declarations,
and a positive event creation rate limit. A matching name does not prove that
any node uses the ConfigMap. Node flags, overrides, file contents, certificate
validity, approval and runtime enforcement are not verified. Missing, unsupported,
malformed, denied or partial evidence cannot prove a clean declaration.

Minimum permissions are `list` on core `configmaps` in each selected namespace
and `get` on the matching names. GET may be restricted to exact known names:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: read-kubelet-declarations
  namespace: kube-system
rules:
  - apiGroups: [""]
    resources: ["configmaps"]
    verbs: ["list"]
  - apiGroups: [""]
    resources: ["configmaps"]
    resourceNames: ["kubelet-config", "kubelet-config-1.34"]
    verbs: ["get"]
```

Use the actual names present in your cluster and an existing RoleBinding to the
scanner identity. Kubernetes RBAC cannot restrict LIST to a name prefix or to
metadata, and the metadata permission also authorizes full-object LISTs; this
collector requests only metadata representations. An existing `*` namespace
scope requires the corresponding cluster-wide list authorization. No Secret,
node, proxy, log, exec or write permission is needed by these eight checks.

Per selected namespace (or one existing wildcard scope), reads are bounded to
eight metadata pages, sixteen matching content GETs, eight MiB total response
bytes and thirty seconds. YAML is limited to 64 KiB, 4,096 tokens and depth 12;
aliases, custom tags and duplicate fields are rejected. Only native identity and
safe whitelisted indicators enter snapshots. YAML, paths, annotations, private
keys and unrelated values are discarded; explicit collection limits and failed
metadata negotiation leave coverage unresolved.

### Optional selected literal-content secret scanning

This reader is off by default. Enable `options.content_secret_scans: true`, name
`k8s.review.selected_literals.secret_indicators` in `checks`, and supply
`options.selected_k8s_literal_resources` with 1–8 unique exact selectors. Each
selector has exactly `cluster_id`, `namespace`, `kind` (`Pod` or `ConfigMap`) and
`name`. The namespace must be an explicit requested scope; `*` is not supported
for this reader. The cluster ID must equal the configured `auth.cluster_id` or
the collector's API-origin digest. Selectors cannot be URLs or contain path
escapes, wildcards or discovery instructions.

```json
{
  "checks": ["k8s.review.selected_literals.secret_indicators"],
  "connector": {
    "provider": "k8s",
    "scopes": ["team-a"],
    "auth": {"method": "context", "context": "review-context", "cluster_id": "review-cluster"},
    "options": {
      "content_secret_scans": true,
      "selected_k8s_literal_resources": [
        {"cluster_id": "review-cluster", "namespace": "team-a", "kind": "Pod", "name": "review-pod"},
        {"cluster_id": "review-cluster", "namespace": "team-a", "kind": "ConfigMap", "name": "review-config"}
      ]
    }
  }
}
```

The reader issues two exact native GETs per selected object through the existing
authenticated TLS transport, checks namespace/name/kind/API version, and requires
unchanged UID, resourceVersion and selected content between reads. It inspects
literal env values, command and args in regular, init and ephemeral containers,
and ConfigMap `data` plus UTF-8 text decoded from `binaryData`. Selected object identities, container/env names and literal
keys enter the same offline detector input so detected values copied into
identity fields cannot survive in retained metadata. Variable substitutions are
not evaluated. Secret/config-map env references, downward API values and
`envFrom` references are counted and excluded without dereference. It never reads
Secret payloads, logs, exec, node/kubelet/host files or registry images.

Minimum additional permission for this exact check is namespace-scoped `get` on
the exact selected resource names. The reader supports Pods, ConfigMaps,
Deployments, DaemonSets, StatefulSets, ReplicaSets, Jobs, CronJobs,
ReplicationControllers and PodTemplates; controller coverage is limited to the
current Pod template. The overall scan may use `["*"]`, but every content selector
still names an exact namespace and object. See the [per-kind read permission table](secret-content-permissions.md#kubernetes-selected-workload-literals). No `list` or `get secrets` grant is
needed. For example, an administrator can bind this Role to the existing scanner
identity in `team-a`; remove unused resource rules and use the actual exact names:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: peaso-selected-literal-reader
  namespace: team-a
rules:
  - apiGroups: [""]
    resources: ["pods"]
    resourceNames: ["review-pod"]
    verbs: ["get"]
  - apiGroups: [""]
    resources: ["configmaps"]
    resourceNames: ["review-config"]
    verbs: ["get"]
```

There is no blanket enumeration. The hard ceiling is 16 native GET attempts,
2 MiB per response, 8 MiB total response bytes, 256 KiB detector input per
object, 64 KiB per literal, and 512 nonempty literals per object. The reader uses
a 60-second batch budget, cancellation and caller-supplied shared call/resource
limits; individual network waits are at most 10 seconds and can finish after the
remaining batch deadline, in which case the result stays incomplete. Both pinned
offline engines (Kingfisher 1.4.0 and TruffleHog 3.92.5) must finish. No credential
validation, verification request, detector download or network update is used.

Only redacted evidence, opaque HMAC locators, counts and safe read receipts enter
the snapshot. HMAC exact-value fingerprints use the same process key as the other
content readers, allowing repeated detections to merge without retaining the
value. The union of detected values scrubs identity and location fields across
the completed collection before caching/export; progress carries counts only,
and this optional scan does not capture live AI access. Denied, malformed,
changed, partial, unsupported, empty or incompletely scanned content stays
`UNKNOWN`; it cannot prove secret absence. A `PASS` covers only the selected
observed supported literals, and a `FAIL` indicates potential exposure without
proving the credential is valid or usable.

Native field contracts: [Pod v1](https://kubernetes.io/docs/reference/kubernetes-api/core/pod-v1/),
[ConfigMap v1](https://kubernetes.io/docs/reference/kubernetes-api/core/config-map-v1/),
and [RBAC resourceNames](https://kubernetes.io/docs/reference/access-authn-authz/rbac/#referring-to-resources).


`scopes` are namespace names or `*`; cluster-scoped inventory is read once under
the first selected scope. Namespaced endpoints are constructed separately for each
namespace. A returned object from another namespace is malformed evidence.
When explicit namespaces are selected, the namespace objects themselves are read
by name and emitted in the corresponding selected scopes; `*` uses the paginated
namespace list. This lets quota and policy checks match the correct namespace.
Namespaces are administrative containers, never IP subnets.

| Authentication | Fields in `auth` |
| --- | --- |
| Local kubeconfig | `method: kubeconfig`, optional `kubeconfig`, `context`; official loader uses current context and supports trusted exec helpers |
| In cluster | `method: in_cluster` or `in_cluster: true`; service account token and CA via official loader |
| Direct bearer | `server`, `token` or `token_file`, optional `ca_cert` |
| Client TLS | `server`, `client_cert`, `client_key`, optional `ca_cert` |
| Inline kubeconfig | `method: inline` or `kubeconfig`, `kubeconfig_data` mapping or YAML string, optional `context`; token or inline certificate material |
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
| Namespace limits | `resourcequota`, `limitrange`; native specs in each selected namespace |
| Network declarations | `service`, `endpointslice`, `ingress`, `networkpolicy` |
| Admission | `admission_configuration`; validating/mutating webhook configurations with `kind` and native `failurePolicy`, rules and selectors |
| Admission policies | `admission_policy`; ValidatingAdmissionPolicy/Binding and MutatingAdmissionPolicy/Binding objects with `kind` and `apiVersion`, listed only for the resources that admissionregistration.k8s.io resource discovery advertises (v1, then v1beta1/v1alpha1) |
| Discovery | `api_discovery`; served API groups plus `policy_engines` (Kyverno `kyverno.io`, Gatekeeper `*.gatekeeper.sh` groups, which show CRD presence and not enforcement) |
| OpenShift | `securitycontextconstraint`; SCCs (users, groups, host/privileged flags), listed only when `security.openshift.io` is served |
| Metadata only | `secret_metadata`, `configmap_metadata`; name, namespace, labels, type and service-account annotations through PartialObjectMetadataList/Table negotiation |
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

### Facts read by the privilege-escalation selectors

| Selector or check | Collected fact |
| --- | --- |
| `k8s_sa_used_by_pending_pod`, `k8s_node_hosting_pod_of_source` | `pod`: `spec.serviceAccountName`, `spec.nodeName`, `status.phase`. Pending pods without `nodeName` are kept. |
| `k8s_sa_named_in_scc_users`, `openshift_namespace_has_sa_with_host_scc` | `securitycontextconstraint`: `users`, `groups`, `allowPrivilegedContainer`, `allowHost{PID,Network,IPC,DirVolumePlugin}`. RBAC `use` on SCCs comes from the RBAC inventories. |
| `k8s_secret_holds_cloud_credential`, `k8s_secret_holds_remote_cluster_credential` | `secret_metadata`: name, labels (for example `argocd.argoproj.io/secret-type=cluster`) and type. Data key names are not collected. The API only exposes them in the full Secret object, which carries the values, so they are never read. Operator-supplied `metadata_evidence.secret_metadata` may carry `type`, and evidence that carries `data`/`stringData` is rejected. |
| `source_bound_to_aggregated_clusterrole` | `clusterrole.aggregationRule.clusterRoleSelectors` |
| Admission guardrails (`k8s_admission_control` blockers) | `admission_policy`, `admission_configuration`, `api_discovery.policy_engines`, namespace `pod-security.kubernetes.io/*` labels |

A denied read gives `denied`, a failed discovery gives `unknown`, and only an absent API gives `not_applicable`. None of these is reported as an empty inventory.

### Read-only RBAC for the collecting identity

Every call is `GET`. A list needs the `list` verb. Namespace objects read by name need `get`. Discovery (`/apis`,
`/apis/<group>/<version>`, `/version`) needs non-resource `get`, which the default `system:discovery` binding grants.
No ClusterRole manifest ships in the repo. This is the minimal one:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: peaso-readonly}
rules:
  - apiGroups: [""]
    resources: [pods, nodes, namespaces, serviceaccounts, services, endpoints, persistentvolumes, persistentvolumeclaims, replicationcontrollers, podtemplates, resourcequotas, limitranges, configmaps]
    verbs: [get, list]
  - apiGroups: [rbac.authorization.k8s.io]
    resources: [roles, clusterroles, rolebindings, clusterrolebindings]
    verbs: [list]
  - apiGroups: [apps]
    resources: [deployments, daemonsets, statefulsets, replicasets]
    verbs: [list]
  - apiGroups: [batch]
    resources: [jobs, cronjobs]
    verbs: [list]
  - apiGroups: [networking.k8s.io]
    resources: [ingresses, ingressclasses, networkpolicies, servicecidrs, ipaddresses]
    verbs: [list]
  - apiGroups: [gateway.networking.k8s.io]     # when Gateway API is installed
    resources: [gatewayclasses, gateways, httproutes, grpcroutes, tlsroutes, tcproutes, udproutes, referencegrants, backendtlspolicies]
    verbs: [list]
  - apiGroups: [storage.k8s.io]
    resources: [storageclasses, csidrivers, csinodes, volumeattachments]
    verbs: [list]
  - apiGroups: [cilium.io]  # when installed
    resources: [ciliumbgpadvertisements, ciliumbgpclusterconfigs, ciliumbgppeerconfigs, ciliumbgppeeringpolicies, ciliumcidrgroups, ciliumclusterwidenetworkpolicies, ciliumegressgatewaypolicies, ciliumendpoints, ciliuml2announcementpolicies, ciliumloadbalancerippools, ciliumlocalredirectpolicies, ciliumnetworkpolicies, ciliumnodes, ciliumpodippools]
    verbs: [list]
  - apiGroups: [crd.antrea.io]  # when installed
    resources: [clustergroups, clusternetworkpolicies, egresses, externalippools, groups, networkpolicies]
    verbs: [list]
  - apiGroups: [crd.projectcalico.org]  # when installed
    resources: [bgpconfigurations, bgppeers, globalnetworkpolicies, globalnetworksets, hostendpoints, ippools, networkpolicies, networksets]
    verbs: [list]
  - apiGroups: [gateway.envoyproxy.io]  # when installed
    resources: [backends, backendtrafficpolicies, clienttrafficpolicies, envoyproxies]
    verbs: [list]
  - apiGroups: [k8s.cni.cncf.io]  # when installed
    resources: [network-attachment-definitions]
    verbs: [list]
  - apiGroups: [k8s.nginx.org]  # when installed
    resources: [transportservers, virtualserverroutes, virtualservers]
    verbs: [list]
  - apiGroups: [k8s.ovn.org]  # when installed
    resources: [clusteruserdefinednetworks, egressfirewalls, egressips, egressservices, userdefinednetworks]
    verbs: [list]
  - apiGroups: [metallb.io]  # when installed
    resources: [bgpadvertisements, bgppeers, ipaddresspools, l2advertisements]
    verbs: [list]
  - apiGroups: [networking.istio.io]  # when installed
    resources: [destinationrules, gateways, serviceentries, sidecars, virtualservices, workloadentries]
    verbs: [list]
  - apiGroups: [policy.linkerd.io]  # when installed
    resources: [authorizationpolicies, httproutes, meshtlsauthentications, networkauthentications, serverauthorizations, servers]
    verbs: [list]
  - apiGroups: [projectcalico.org]  # when installed
    resources: [bgpconfigurations, bgppeers, globalnetworkpolicies, globalnetworksets, hostendpoints, ippools, networkpolicies, networksets]
    verbs: [list]
  - apiGroups: [projectcontour.io]  # when installed
    resources: [httpproxies]
    verbs: [list]
  - apiGroups: [route.openshift.io]  # when installed
    resources: [routes]
    verbs: [list]
  - apiGroups: [security.istio.io]  # when installed
    resources: [authorizationpolicies, peerauthentications]
    verbs: [list]
  - apiGroups: [traefik.containo.us]  # when installed
    resources: [ingressroutes, ingressroutetcps, ingressrouteudps, serverstransports, serverstransporttcps, traefikservices]
    verbs: [list]
  - apiGroups: [traefik.io]  # when installed
    resources: [ingressroutes, ingressroutetcps, ingressrouteudps, serverstransports, serverstransporttcps, traefikservices]
    verbs: [list]
  - apiGroups: [policy.networking.k8s.io]      # when installed
    resources: [adminnetworkpolicies, baselineadminnetworkpolicies, clusternetworkpolicies]
    verbs: [list]
  - apiGroups: [discovery.k8s.io]
    resources: [endpointslices]
    verbs: [list]
  - apiGroups: [admissionregistration.k8s.io]
    resources: [validatingwebhookconfigurations, mutatingwebhookconfigurations, validatingadmissionpolicies,
                validatingadmissionpolicybindings, mutatingadmissionpolicies, mutatingadmissionpolicybindings]
    verbs: [list]
  - apiGroups: [security.openshift.io]       # OpenShift only
    resources: [securitycontextconstraints]
    verbs: [list]
  - apiGroups: [policy]                       # clusters older than 1.25 only
    resources: [podsecuritypolicies]
    verbs: [list]
  # secret_metadata only. Kubernetes RBAC cannot limit list to metadata, so this rule also lets the
  # identity read Secret values. The collector only negotiates metadata, but leave the rule out
  # (and the secret_metadata inventory) when the identity must not hold that right.
  - apiGroups: [""]
    resources: [secrets]
    verbs: [list]
  - nonResourceURLs: [/apis, /apis/*, /version]
    verbs: [get]
```

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

## Azure check extension

`peaso/checks/azure_extended.py` adds 32 pure checks over storage lifecycle,
infrastructure encryption, VM SSH/Trusted Launch/managed disks/host encryption,
disk export controls, network declarations, AKS upgrade/Defender configuration,
SQL audit retention/alert exclusions/TDE, App Service TLS/FTP/CORS/client
certificates/logging/debugging, vault metadata and Defender plan tiers.
Missing, denied and malformed facts are UNKNOWN. Explicit disabled/unsafe settings
can fail even when unrelated fields were not collected. Non-applicable Linux,
blob-service and system-database scopes are handled explicitly. SQL retention zero
means unlimited; optional client certificates do not pass a required-certificate
baseline. Configuration evidence does not establish runtime enforcement, sensor
coverage, reachability, rotation history or effective access.

`reviewed_azure.json` records 41 pinned upstream references: 27 ported and 14
pending related predicates. Pending cases include VM scale-set unions, guest
configuration/runtime SSH, NIC-to-VM joins, endpoint-specific eligibility and
diagnostic log routing. Those differences do not claim upstream equivalence.
The native registry owner merges the shard and derives framework controls/versions
from the pinned source manifest; references are not certification claims.
`tests/test_peaso_checks_azure_extended.py` verifies every new check's pass/fail,
missing/malformed/denied behavior, input purity, collection status propagation and
applicability/enum/retention boundaries.

The cloud-fixture worker's fresh Azure CLI regression after ARM reconciliation
found the exact newly created resource group, NSG and VNet, retained an offline
snapshot and rendered Markdown, then verified removal of all its fixtures.
Its sanitized frozen summary recorded 9,146 resources and 8,027 findings; these
counts reflect that bounded run, not complete tenant coverage. A subsequent
minimal root deny-assignment read with `atScope()` succeeded and returned no
assignments, correcting the unfiltered endpoint's HTTP 400.

Final integration verification on 2026-10-10: the focused collector/check/legacy
suite passed 310 tests, and `.venv/bin/python -m pytest -q` passed 2,385 tests
with one skipped in 22.83 seconds. The registry includes all 32 extension checks;
27 upstream references are merged as supported and non-equivalent references
remain explicitly pending. Hosted workers set the server-owned `hosted` flag
before invoking collectors, and fake DNS-change tests verify that a private
second resolution is rejected before an API connection is constructed.

## ImagePolicyWebhook admission-file evidence

The `admission_configuration_file` inventory reads the API server Pod's declared
`--admission-control-config-file` through its exact ConfigMap volume projection.
It joins the Pod UID, namespace, volume mount, projected key, ConfigMap UID and
resourceVersion. The ConfigMap must be immutable, must predate the Pod, and must
have server field-ownership timestamps for both the selected key and immutable
flag that predate the Pod. Missing or newer ownership evidence remains UNKNOWN.
This guards against a replacement ConfigMap or a mutable configuration changed
after the admission plugin loaded its startup configuration.

The collector performs only the Pod LIST and a GET of the referenced ConfigMap.
It retains plugin names and the ImagePolicyWebhook kubeconfig **path**, normalizing
`configuration.imagePolicy.kubeConfigFile` for the check. It never fetches the
referenced kubeconfig, Secret objects, host files, container logs or exec/proxy
subresources. Unrelated ConfigMap values are omitted from snapshots. Oversized,
duplicate-key, aliased, multi-document or malformed YAML remains unavailable.

This inventory verifies a configuration declaration. It does not prove webhook
availability or image-signature enforcement. Static Pod mirror records,
HostPath/Secret/projected volumes, subPath snapshots, external plugin files and
mutable ConfigMaps remain UNKNOWN because their currently loaded contents cannot
be proved by these API reads. These limitations apply even when the surrounding
Pod and admission-plugin flags were collected successfully.

Kubernetes references: [ImagePolicyWebhook configuration](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/#imagepolicywebhook)
and [immutable ConfigMaps](https://kubernetes.io/docs/concepts/configuration/configmap/#immutable-configmaps).


## Native Azure detection feeds and tenant diagnostic exports

`azure_detection_telemetry` reads only aggregate counts, ingestion/event times and
bounded operation names from Azure Monitor Logs. It requests the separate
`https://api.loganalytics.io/.default` audience and calls the fixed
`https://api.loganalytics.azure.com` endpoint. Direct ARM tokens are never reused
for Logs. It does not retain raw log events, caller identities or request payloads.

The explicit `options.compliance_policy.azure_attack_detection` and `.sw12`
reviews identify approved source/workspace/table/window combinations. Reviews
select requirements; they never supply observed routing or positive query facts.
The collector independently GETs workspace identity, pages native diagnostic
settings and executes source-filtered aggregate queries. Queries are generated
from validated identities and table names, not user-provided KQL. One query per
workspace/source/table is shared across applicable checks and both contracts.
Measured failures remain UNKNOWN for the affected source without poisoning an
independently measured detection. An absent review is unavailable evidence.

Subscription activity uses `_SubscriptionId`, individual resources use the exact
`_ResourceId`, and tenant AuditLogs/SigninLogs use `AADTenantId`. Tenant IDs are
bound to the authenticated credential and an actual subscription GET, with the
same scan/customer context on the measured rows. `TenantId` is not substituted:
for many Azure Monitor tables it identifies the workspace. Storage account
sources resolve to their exact blob/file/queue/table service before diagnostics
and data-plane filtering. Legacy versus dedicated workspace destinations remain
distinct. Partial HTTP 200 results, malformed aggregates, future timestamps,
foreign identities, denied pagination and unsupported routing stay unavailable.

Native route support includes subscription activity, tenant AuditLogs/SigninLogs,
Storage service tables, Key Vault AZKVAuditLogs or legacy AzureDiagnostics,
Container Registry repository events and FunctionAppLogs. Custom/DCR/Defender
routes require their own adapters. An enabled action group does not establish
receiver delivery; tested-action and serverless-canary requirements retain their
independent evidence requirements. Declaring this inventory is not a claim that
all 27 detection-feed controls have complete native evidence in every environment.

`entra_diagnostic_setting` reads tenant AADIAM diagnostic settings and resolves
configured destination identities through independent ARM GETs. It omits receiver
secrets and unrelated resource properties. Two CIS export controls evaluate once
per verified tenant, including when several selected subscriptions share it.
Missing credential/customer/tenant bindings cannot redirect a subscription check
to another tenant. Configuration export does not establish broad audit-event
coverage, retention reachability or actual delivery.

Hosted intake accepts these bounded, explicitly scoped operator reviews and a
separate Logs token. Native readings always supply the factual evidence. On
2026-10-15, an isolated own-account fixture produced three real AzureActivity
events through the native aggregate path. Both temporary diagnostic settings and
resource groups were deleted, and both Log Analytics workspaces were permanently
purged from the deleted-workspace inventory. These results prove that feed path;
they do not prove every ATT&CK detection or receiver delivery.

References: [Logs query endpoint and request format](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/api/request-format),
[Logs authentication](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/api/access-api),
[AuditLogs tenant identity](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/auditlogs),
[tenant diagnostic setting schema](https://learn.microsoft.com/en-us/azure/templates/microsoft.aadiam/2017-04-01/diagnosticsettings),
and [permanent Log Analytics deletion](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/delete-workspace).

### Native identity, guest reports and database joins

An explicitly selected control collects its dependencies and requested graphs.
It does not implicitly collect every network and IAM graph. Default full scans
retain their complete inventory plan. A real three-control Azure MFA scan used
5 calls after this correction, compared with 32 before it; actual denied Graph
permissions still produced unresolved findings.

`compliance_policy.sw13` supplies dated, authorized MFA requirements, never proof
that MFA was enforced. The native supported positive path requires an enabled
all-user, all-application policy requiring MFA, without unsupported conditions
or exclusions. Authentication strengths are joined to their independent Graph
definitions. Registration alone does not prove enforcement. Unsupported policy
semantics and missing tenant authority remain `UNKNOWN`.

`compliance_policy.sw18` selects exact Guest Configuration baseline names,
versions, parameters and report freshness. The User Rights and time-source
controls read the exact latest assignment report. Time synchronization also
requires detailed actual source and drift measurements; a generic `Compliant`
report is insufficient. Legacy flat reviews retain precedence, and unrelated
flat reviews can coexist with an independently scope-validated `sw18` review.

`compliance_policy.sw25` accepts the two guest-review check IDs. Monthly review
uses an empty requirements object; regular review requires `maxReviewAgeDays`.
The native path joins guest creation, supported group scope, recurrence,
completed instances and dated individual decisions. It never invents a
`completedDateTime` field. Dynamic scopes and unresolved role/PIM reviews remain
unresolved.

The native database join uses the distinct SQL, MySQL and PostgreSQL firewall
and administrator schemas. `compliance_policy.sw15.allowAzureServices` approves
or rejects the documented zero-address firewall sentinel; it does not supply
firewall observations. Administrator checks bind the native principal and
tenant IDs and do not attempt a database login. Actual empty server inventories
produce `NOT_APPLICABLE`; denied or partial reads do not establish absence.


The APIM native path supports the built-in Azure Monitor logger routed to a
Dedicated GatewayLogs workspace. `compliance_policy.sw24` selects the exact
subscription, APIM services, approved API coverage, positive sampling minimum,
and a bounded UTC observation window. It contains no observations or KQL.
Verbosity evaluates the actual API/revision overrides and destination route.
HTTP and method coverage additionally require native aggregate gateway receipts
bound to service, API and revision; configured logging alone never proves
receipt delivery. The aggregate stores counts, timestamps and a request
correlation hash, without headers, payloads or raw request IDs. Identical receipt
queries share the scan cache. Unsupported logger credentials, legacy tables,
workspace APIs, absent traffic, denied or incomplete reads remain `UNKNOWN`.
Configuration-only selection makes no Logs query. Real owned subscription
inventory was empty during the live test, so positive gateway outcomes are
verified with actual API-shaped collector-to-engine cases, not claimed as live.


## Native directory, Intune and managed-instance evidence

Directory membership uses each actual directory user's paged Microsoft Graph `transitiveMemberOf` response. Only group objects contribute membership, and incomplete pages, foreign tenant identity or an unresolved credential/tenant binding remain UNKNOWN. The all-user predicate is unchanged; a directory inventory alone cannot prove membership.

SQL Managed Instance administrator evidence joins each real managed instance to its native `administrators` collection, validates child IDs and Active Directory administrator tenant identity, and records complete empty collections explicitly. It does not substitute SQL logical-server administrators for managed-instance administrators.

Intune diagnostic routing joins the tenant's discovered diagnostic categories and settings to actual destination workspace metadata in the selected subscriptions. Its existing SW16 owner review selects the expected categories; it cannot supply observed routing or delivery. No setting or workspace is created or modified. Missing owner review, inaccessible workspace, unsupported route, partial category coverage or unresolved tenant binding yields UNKNOWN. This path establishes configured routing only, not successful log ingestion.

The VM system-update assessment path reads native instance-view assessment data. A fresh successful zero-missing assessment can establish the narrow system-update predicate. Assessment time is not installation time: PCI installation-age requirements remain UNKNOWN without their required independent installation observations. Existing SW17 owner-review intake remains scope bound.

### Native Azure ARM policy evidence

Three checks accept narrowly scoped native evidence: Automation DSC (`azure_vm_1_2_8_10_1bd35d0`), Application Gateway predefined SSL policy (`azure_application_gateway_app_ensure_http_is_redirected_to_https_e598c17`), and Azure Files recovery backup (`azure_storage_file_share_10_3_3_15_f2d7075`). They share existing bounded ARM readers and preserve incomplete, denied, foreign or ambiguous evidence as UNKNOWN/DENIED.

Owner intent uses `options.compliance_parameters.azure_arm_metadata` with an exact single selected subscription `scope` and `status: collected`. Optional `dscNodes` contains `requiredNodeIds` and `maxHeartbeatAgeHours`; `approvedPredefinedSslPolicyName` selects the approved native AppGwSslPolicy name. Inputs describe requirements, never observed statuses or collection completeness. Existing policy authority, scope, freshness and unrelated parameters are preserved.

DSC joins complete Automation account/node inventories, native node configuration, compliance status and fresh heartbeat. AppGateway joins the complete gateway/classic Front Door universe with full native gateway SSL-policy/profile references; it does not establish TLS handshake or HTTP redirect behavior, and applicable classic Front Door remains UNKNOWN. Azure Files joins the complete share and Recovery Services vault inventories, every vault's protected-item pages, exact source share and same-vault backup policy identity; conflicting same-ID observations cannot be silently discarded. These paths do not prove restoration behavior or historical backup success.

Schemas: [DSC nodes](https://learn.microsoft.com/en-us/rest/api/automation/dsc-node/list-by-automation-account?view=rest-automation-2024-10-23), [Application Gateway](https://learn.microsoft.com/en-us/rest/api/application-gateway/application-gateways/get?view=rest-application-gateway-2025-05-01), [Backup protected items](https://learn.microsoft.com/en-us/rest/api/backup/backup-protected-items/list?view=rest-backup-2026-02-01).

### Native current certificate policy (metadata only)

Selecting `azure_c5_cry_08_01b` reads the complete in-scope vault inventory, pages `GET /certificates?api-version=2025-07-01`, and calls `GET /certificates/{name}?api-version=2025-07-01`. The unversioned GET identifies the latest version in its returned versioned `id`. The existing current-certificate reader validates the exact vault origin, parent scope, certificate name and version. Its new `key_vault_certificate_current` mode retains only the current response's issuer name and public key policy fields. The API field `policy.key_props.crv` maps explicitly to the frozen evaluator's `policy.key_props.curve` with mapping provenance; a fabricated API `curve` field is not accepted as evidence. No secret GET, private key, key-listing value, certificate export or cloud write is performed.

This is a native metadata path with certain FAIL, not a complete control PASS. A current issuer, key type, RSA size or EC curve contrary to approved policy can produce FAIL. Conforming metadata remains UNKNOWN until separate `certificate_issuance_evidence` establishes the required current procedure, identity verification, secure issuance and trusted CA verification over the assessment period. Native inventory never manufactures these process attestations. The positive integration test supplies this separate evidence explicitly; it is a synthetic contract test, not a claim of live attestation.

Missing policy fields, a foreign vault/certificate, unresolved current version, incomplete pagination and permission failure preserve UNKNOWN/DENIED. The legacy `key_vault_certificate` path keeps its existing projection and behavior. This does not establish live endpoint bindings, issuance age or certificate rotation.

Primary API shape: [Certificates Get, 2025-07-01](https://learn.microsoft.com/en-us/rest/api/keyvault/certificates/get-certificate/get-certificate?view=rest-keyvault-certificates-2025-07-01), including optional version/latest semantics, `policy.issuer.name`, `key_props.kty`, `key_size` and `crv`. Permissions remain certificates/list and certificates/get, or their existing RBAC equivalents.


### Explicit Azure AKS workload reads

The optional AKS bridge supplies current admitted Pod image declarations and Service port declarations to the existing signed Azure checks `azure.gap.kubernetes_cluster_container_use_allowed_images` and `azure.gap.kubernetes_cluster_service_listen_to_allowed_ports`. ARM configuration alone cannot provide these facts. No Kubernetes credential is obtained from Azure; provide an existing short-lived, read-only Kubernetes token and public CA certificate explicitly. Do not put credentials in `options`.

For example, in a private connector/auth file, add:

```json
{"aks_workloads":[{"cluster_id":"/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/rg/providers/Microsoft.ContainerService/managedClusters/cluster","server":"https://cluster-123.hcp.eastus.azmk8s.io","ca_cert_data":"-----BEGIN CERTIFICATE-----\nREPLACE_WITH_PUBLIC_CA\n-----END CERTIFICATE-----\n","token":"REPLACE_WITH_EXISTING_READ_ONLY_TOKEN"}]}
```

These are explicit authentication inputs alongside the existing Azure credentials. The example placeholders must be replaced. Inline kubeconfig execution helpers, local credential files, automatic default contexts, arbitrary proxy settings, insecure TLS and cluster credentials obtained through Azure action endpoints are unsupported. The bridge uses direct HTTPS/443 only; server must exactly match the selected ARM cluster's current `fqdn` or `privateFQDN`. Ports, paths, query strings, fragments, userinfo, trailing dots and IDN hosts are rejected. Hosted scans additionally retain the existing public-address restriction; a private AKS endpoint requires a local runner with appropriate connectivity.

Select the two check IDs through the ordinary public scan request. The policy is explicitly normative. Under `options.compliance_parameters`, add:

```json
{"azure_aks_workloads":{"subscriptions":[{"scope":"/subscriptions/11111111-1111-1111-1111-111111111111","images":{"mode":"registries","allowed":["approved.example"],"immutableImages":false,"containerKinds":["containers","initContainers","ephemeralContainers"]},"service_ports":{"cluster_id":"/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/rg/providers/Microsoft.ContainerService/managedClusters/cluster","evidence_ref":"owner-approved-network-policy-v1","services":[{"namespace":"default","name":"app","allowed":[{"port":443,"protocol":"TCP"}]}]}}]}}
```

An absent image or Service approval remains UNKNOWN; no registry, image, port or deployed workload is automatically approved. Digest/immutable policies also require the actual running container image ID already returned by the Pod API; missing status remains UNKNOWN. Policies contain no inventory, observed status, UID or completeness claims. Policy input is limited to 50 KB; at most16 explicit contexts and16 policy subscriptions are admitted. Existing frozen policy namespaces are preserved.

Before transmitting a Kubernetes token, the collector requires the current verified Azure tenant, an exact native subscription/tenant binding, complete AKS discovery and exact ARM GET resource/type/name. Every AKS in the selected subscription must have an explicit binding. Arc inventory must be complete and empty because this adapter does not collect Arc workloads. It obtains the `kube-system` namespace UID, performs complete all-namespace lists with stable native list resourceVersion across continuation pages, then verifies the same UID again. A cluster UID cannot be reused for two ARM resources. A wrong endpoint, missing binding, unknown tenant, failed UID postcheck, denied page, repeated cursor or explicit budget limit never becomes complete empty evidence.

The public collection planner exposes the ARM parents (`subscription`, `aks_cluster`, `arc_kubernetes_cluster`) without enabling additional checks. The adapter reuses the existing read-only Kubernetes native page reader and workload redaction. Pod environment literal values and executable arguments do not enter snapshots. Inline bearer credentials remain authentication inputs; snapshots contain only resource IDs, native UIDs, the exact server origin and a public CA fingerprint. Kubernetes requests share the Azure scan's call/retry/page/resource/deadline budget. The SDK client explicitly disables environment proxies and redirects, verifies server TLS, and deletes its temporary public CA file when closed.

Required read permissions: Azure subscription reads, `Microsoft.ContainerService/managedClusters/read` and `Microsoft.Kubernetes/connectedClusters/read`, with the existing metadata Reader role. The generic existing AKS/Arc collectors may also read their metadata children. Kubernetes RBAC needs `get` on the `kube-system` Namespace and `list` on Namespaces, Pods and Services across all namespaces. Optional explicit `limit_range` inventory adds only a native LimitRange LIST; it supplies no admission-history/runtime attestation. No Secret, log, exec, proxy, TokenReview, credential-listing or mutation endpoints are called. The adapter does not create grants or resources.

The image rule can assess multiple bound AKS clusters. The existing Service rule has a single-cluster policy contract, so multi-cluster Service assessment stays UNKNOWN while independently complete image evidence remains usable. Prefer one selected subscription per policy capture: the frozen policy metadata has one scope per check. The predicates are unchanged. These checks assess declarations/current image IDs, not admission enforcement, application listeners, traffic or image vulnerability. The CPU/LimitRange historical-admission, AppArmor runtime support and effective UID/GID requirements remain unresolved by this adapter; no timestamps, runtime booleans or owner approvals are manufactured. Empty observations retain the signed predicate's existing semantics. There is no live AKS validation claim in the private SDK-shaped tests.

Primary API contracts: [Azure AKS2024-05-01 specification](https://raw.githubusercontent.com/Azure/azure-rest-api-specs/main/specification/containerservice/resource-manager/Microsoft.ContainerService/aks/stable/2024-05-01/managedClusters.json), [Kubernetes consistent list pagination](https://kubernetes.io/docs/reference/using-api/api-concepts/#retrieving-large-results-sets-in-chunks), [Kubernetes API access and TLS](https://kubernetes.io/docs/concepts/security/controlling-access/).


### AKS admitted read-only root filesystem declarations

The same explicit `auth.aks_workloads` bridge now supplies the six complete inventories required by the signed control `azure_aks_cluster_aks_cluster_rbac_enabled_c41a0cb`: `aks_pod`, `aks_deployment`, `aks_statefulset`, `aks_daemonset`, `aks_job` and `aks_cronjob`. Despite its historical RBAC label, the frozen predicate assesses `securityContext.readOnlyRootFilesystem` on admitted regular, init and Pod ephemeral containers. It does not attest Azure/Kubernetes RBAC, effective runtime state or the contents of writable volumes. No additional owner approval criterion or credential field is introduced.

The exact all-namespace LIST endpoints are `/api/v1/pods` (`v1`, `PodList`), `/apis/apps/v1/deployments` (`apps/v1`, `DeploymentList`), `/apis/apps/v1/statefulsets` (`apps/v1`, `StatefulSetList`), `/apis/apps/v1/daemonsets` (`apps/v1`, `DaemonSetList`), `/apis/batch/v1/jobs` (`batch/v1`, `JobList`) and `/apis/batch/v1/cronjobs` (`batch/v1`, `CronJobList`). Each returned object must match its API version and native kind, have an unambiguous UID/resourceVersion and belong to a namespace in the complete namespace list. Kubernetes RBAC therefore requires all-namespace `list` on these six resources in their respective API groups, alongside the existing Namespace GET/LIST. The adapter adds no Azure IAM action and performs no credential retrieval or Kubernetes write.

One ARM GET, TLS-bound client and before/after `kube-system` UID bracket cover all selected lists per cluster. Existing complete AKS/Arc inventory, exact tenant/subscription identity and explicit credentials for every selected managed cluster remain prerequisites; any unresolved Arc cluster, absent credential, denied/partial page, budget limit, malformed list or changed UID prevents a complete control assessment. The existing conservative collection transaction invalidates all active workload inventories on such a failure. Complete empty inventories retain the frozen predicate's PASS semantics; an unavailable inventory never becomes an empty one.

Only native identity and container name/read-only-root flags are retained for these six projections. Environment variables, commands, arguments, image/pull secrets and secret references are omitted. Absent optional init/ephemeral arrays in an otherwise complete valid native response are represented as empty lists with explicit provenance recording the absent paths. Explicit null or malformed arrays remain UNKNOWN. Regular containers are required and nonempty. An omitted native securityContext or readOnlyRootFilesystem flag retains Kubernetes' documented default false and causes FAIL. A narrow evaluator purity repair copies the regular-container list before combining optional lists, so sealed snapshots remain unchanged; no predicate condition or default is changed.

These SDK-shaped collector-to-signed-engine tests demonstrate declared settings, including false/omitted flags, init and ephemeral containers, scope errors and incomplete reads. They are not a live AKS or universal-account compliance claim. Primary schemas: [Kubernetes security context default](https://github.com/kubernetes/api/blob/v0.34.1/core/v1/types.go), [Deployment](https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/deployment-v1/), [CronJob](https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/cron-job-v1/), and [complete consistent LIST pagination](https://kubernetes.io/docs/reference/using-api/api-concepts/#retrieving-large-results-sets-in-chunks).

Native typed LIST responses can omit `kind` and `apiVersion` on individual items. The adapter derives only absent fields from the exact endpoint and already validated List kind/version; explicit conflicting or null item fields still produce UNKNOWN. Namespace UID, object UID/resourceVersion, pagination and TLS/ARM identity checks remain mandatory. Individual GET responses retain their explicit generation checks. This follows the [Kubernetes server serialization contract](https://github.com/kubernetes/kubernetes/pull/127361#issuecomment-2353199198), and does not relax collection completeness or add permissions.


## Optional selected Azure source and secret content

The metadata Reader setup above does not grant private registry, storage data,
App Configuration data or Synapse/DevOps content access. Before selecting an
optional content check, use the [per-service permission table](secret-content-permissions.md#additional-locally-integrated-azure-content-readers).
It links exact resource/commit/version selectors and minimum read roles for
Blob/File sources, DevOps files/pipelines, App Configuration values, Data Factory
and Synapse declarations. Private ACR images need the separately documented
pull permission. A credential limited to an ARM bearer token cannot acquire
the extra data-plane token audiences. These readers do not create grants or
follow protected secret references; they remain default-off and require named
check selection plus `content_secret_scans`.

Optional selected [Log Analytics and Application Insights message samples](peaso-azure-selected-log-samples.md) require their separate query read permissions. Metadata Reader access alone does not establish message access; the local reader covers only selected preceding-hour samples, not full retained history.

Optional selected [Databricks notebook source](peaso-azure-databricks-notebook-secrets.md) needs separately assigned workspace read authorization. Optional [current-container log samples](peaso-k8s-selected-log-secrets.md) need namespace-scoped `pods/log` read access. Both are off unless selected by exact check and target; no permission or infrastructure is created by a check.

Optional [ML Command-job literals](peaso-azure-selected-ml-secrets.md) use job metadata reads. The separate [ML environment/code asset readers](peaso-azure-selected-ml-assets-secrets.md) inspect returned inline Conda text or one exact associated source file. Code-file reads additionally need scoped Blob/File data authorization; ARM Reader and stored datastore credentials do not provide it. These checks require their exact named selection and `content_secret_scans: true`; package installation, source execution and role changes are excluded.

The storage-account blocking SAS-expiry policy declaration uses the existing full ARM account read and requests no extra permissions. It checks the declared Block action and positive interval, not issued tokens or exempt SAS types; client validity requirements remain a remediation consideration.

Optional [selected Function declarations](peaso-azure-selected-function-declarations.md) check the Application Insights setting and automatic major4 runtime channel. These sensitive settings reads require exact named checks, targets, content consent and site-scoped `Microsoft.Web/sites/config/list/action`. They do not invoke secret detectors or prove delivery or the resolved host build.

Ordinary [Storage perimeter associations and Query-linked Table CMK declarations](check-review/azure-nsp-query-cmk-setup-20261020.md) use scoped management-plane Reader access, including subscription, NSP/profile/association, workspace/link and Storage metadata reads. They require neither content downloads nor Key Vault data access and make no network or key-configuration changes.

Optional [selected Kubernetes metadata inspection](peaso-k8s-selected-metadata-secrets.md) inspects exact object labels and annotations with separately selected content consent and narrowly scoped GET permissions.
