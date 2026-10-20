# Azure ML and Databricks selected secret sources

The local Blob/File, ACR and selected log readers inspect explicitly chosen objects, immutable images or message samples. They do not associate those bytes with an ML job, environment or Databricks notebook. The current Databricks account reader collects workspace/metastore metadata; it cannot export notebook source.

This review adds one **unregistered proposal**: `azure.review.machine_learning.selected_command_job_secret_indicators`, in the existing **Secrets** group, severity **high**, with no numbered compliance mappings. It reads only returned Command-job command text and literal environment variables. Production collector, registry, hosted selector and UI integration remain pending root admission. All prior accepted readers and shared integration files remain unchanged.

| Surface | Current content support | Native association and remaining work |
| --- | --- | --- |
| Databricks ARM/account metadata | Metadata only | Account workspace/metastore joins do not return notebook bytes. |
| Exact notebook SOURCE export | Missing native reader | Bind ARM workspaceId/workspaceUrl, authenticated workspace principal, exact path/object ID and NOTEBOOK type before export. No whole-workspace scan. |
| Notebook/code copy in Blob/File | Existing exact selected object reader | A manually selected copy does not prove its notebook origin, export time or current association. |
| ML workspace metadata | Metadata only | workspaceId, tenantId, storageAccount and containerRegistry declarations do not identify source files or image digests. |
| Selected Command-job command/env | New unregistered proposal | Native subscription/workspace/job binding; returned public literals only. Referenced code, environments and images remain uninspected. |
| ML code asset source | Missing native association | Code-version GET returns codeUri, not source bytes. Resolve only explicitly selected permitted storage objects; never follow arbitrary URI/SAS or enumerate a source folder. |
| ML environment inline condaFile | Missing native declaration reader | A useful next ARM-only block: exact environment version and bounded returned condaFile. This dispatch implements only the Command-job reader. |
| ML environment build context/Dockerfile | Existing selected objects; missing association | contextUri/dockerfilePath do not automatically authorize reading a directory or prove the selected object's relationship. |
| ML environment image | Existing selected immutable ACR images; missing association | Native image tags and workspace registry declarations do not prove repository/digest or what ran. External registries remain unsupported. |
| Other job fields/types | Missing native projection | Inputs, parameters, Pipeline/Sweep/AutoML/Spark declarations and expanded references are outside the new check. Unsupported job discriminators remain UNKNOWN. |
| Application log copies | Existing selected log samples | Fixed table/AppId samples do not cover complete ML/Databricks logs or establish source identity. |
| Key Vault, Databricks secret scopes, ML datastore/workspace/notebook credentials | Deliberately excluded intended stores | Reading an intended credential store is not leak detection. No new secret-value, notebook-token, listKeys/listSecrets, decrypt or write permissions are requested. |

## Proposed selected Command-job setup

After separate admission, request the exact named check, `content_secret_scans: true`, and `selected_azure_ml_command_jobs`, an array of 1–4 exact `{resource_id}` targets. Each target must be an unambiguous native job ARM ID inside an explicitly selected subscription. No URL, endpoint, code URI, query, key or new credential field is accepted. Job identifiers are case-sensitive even though the ARM parent identity is case-insensitive.

```json
{
  "content_secret_scans": true,
  "selected_azure_ml_command_jobs": [
    {"resource_id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/review/providers/Microsoft.MachineLearningServices/workspaces/selected/jobs/JobCase"}
  ]
}
```

| Native operation | Minimum read | Audience |
| --- | --- | --- |
| Exact subscription GET, `2022-12-01` | `Microsoft.Resources/subscriptions/read` | `https://management.azure.com` |
| Exact ML workspace GET, `2026-03-01` | `Microsoft.MachineLearningServices/workspaces/read` | Same ARM audience |
| Exact case-sensitive job GET, `2024-04-01` | `Microsoft.MachineLearningServices/workspaces/jobs/read` on the selected job | Same ARM audience |

Use the customer's existing supported Azure credential. ARM Reader includes these read actions; no Contributor, Owner, execution, storage, image-pull or new data-plane grant is needed for this declaration check. The workspace's native tenantId must match the authenticated tenant and subscription tenant. This bounded proposal requires a GUID workspaceId and `Succeeded` provisioning state; other native identity shapes are conservatively unresolved. The GET response is a point-in-time declaration, not an atomic deployment or execution attestation.

A complete result requires a nonempty returned command, an explicit supported environment map and both pinned offline engines completing. An explicitly empty environment map can still accompany a scanned nonempty command. Missing/malformed maps, unsupported types, secret references and recognized masked values prevent clean PASS. A coherent supported literal hit from a completed engine remains FAIL with incomplete coverage when another source portion or detector is unavailable. `codeId` and `environmentId` become opaque declared-reference fingerprints; no asset existence or source-read claim follows from them. Inputs, parameters, services, outputs and tags are not scanned by this check.

Bounds are 4 targets, 12 selected native GETs, 2 MiB per response, 8 MiB total native bytes, 256 KiB projected command/env content, 128 environment entries and a 120-second checked native/scanner deadline. Existing caller call/cancellation budgets also apply. Reads are uncached, streamed in bounded chunks, accept only full identity-encoded HTTP 200 JSON and reject redirects, native errors, continuation/partial markers and duplicate JSON keys. SDK token acquisition has its own timeout/retry behavior; the checked deadline does not promise hard cancellation of in-flight OAuth. No source, command, notebook or container is executed. Both Kingfisher 1.4.0 and TruffleHog 3.92.5 run offline without credential verification. Only typed evidence, HMAC identifiers and deduplicated redacted matches survive; transient matches join the existing final metadata scrub before cleanup.

The logging witness exercises the real stdlib HTTP serializer/response parser with global debug enabled, through actual AzureTransport token handling, while replacing only the wire socket with inert native HTTP bytes. Content uses no Azure SDK response-logging pipeline and each native connection sets debug level zero. Azure HTTP-policy and identity loggers are enabled in the witness; message/auth/error values must remain absent from captured logs. The credential SDK itself is represented by an inert TokenCredential: SDK-internal OAuth telemetry, custom credential transports and third-party logging policies remain outside this content-reader proof and root-owned authentication integration.

## Databricks authentication and private access

A future exact notebook reader can use an already assigned workspace principal with native notebook/folder CAN READ (shown as CAN VIEW in the UI), the `workspace` API scope and the documented Entra Databricks resource `2ff814a6-3304-4ab8-85cb-cd0e6f879c1d`. ARM read access and the current account token do not establish notebook authorization. Databricks also supports its own OAuth M2M, which is a separate connector-auth integration.

The documented ARM Contributor/Owner management-token fallback can onboard a principal as workspace admin. This audit does not propose or perform that fallback, workspace provisioning, role grants or header-based onboarding. Derive the standard per-workspace host only from the exact authenticated ARM response, verify its workspace ID, and reject caller endpoint overrides. Front-end Private Link can restrict workspace REST API access; the collector would need existing network/DNS reachability to that native host. No alternate URL or new network infrastructure is authorized here.

`get-status` identifies the native object and type; `export?format=SOURCE&direct_download=false` returns base64 source with a documented 10 MB service limit. A future reader must impose a smaller local bound and reject directories and unsupported formats. The documented `modified_at` and size fields apply to files, not guaranteed notebook versions; repeated object status cannot prove unchanged notebook cells. Report only the captured point-in-time source, not atomic version consistency or executed code. Notebook source, outputs, files, Git folders and run output are distinct surfaces.

AML workspace private endpoints do not make ARM declarations equivalent to data-plane access. Source Storage/ACR and workspace data planes have separate network and authorization requirements. The existing Blob reader needs Storage Blob Data Reader at the intended container/conditions; optional FileREST OAuth requires Storage File Data Privileged Reader backup semantics, which bypass file ACLs. ACR exact-image pulls need AcrPull in classic mode or Container Registry Repository Reader with appropriate repository conditions in ABAC mode; no catalog lister is needed for exact selection. None of those reads automatically proves an ML source association.

Primary contracts: [Command jobs GET](https://learn.microsoft.com/en-us/rest/api/azureml/jobs/get?view=rest-azureml-2024-04-01), [ML workspace GET](https://learn.microsoft.com/en-us/rest/api/azureml/workspaces/get?view=rest-azureml-2026-03-01), [code version GET](https://learn.microsoft.com/en-us/rest/api/azureml/code-versions/get?view=rest-azureml-2026-03-01), [environment version GET](https://learn.microsoft.com/en-us/rest/api/azureml/environment-versions/get?view=rest-azureml-2026-03-01), [ML permissions](https://learn.microsoft.com/en-us/azure/role-based-access-control/permissions/ai-machine-learning), [Databricks workspace GET](https://learn.microsoft.com/en-us/rest/api/databricks/workspaces/get?view=rest-databricks-2026-01-01), [notebook status/export](https://docs.databricks.com/api/workspace-objects/v1/export), [workspace service principal auth](https://learn.microsoft.com/en-us/azure/databricks/dev-tools/auth/azure-sp), [Entra token and onboarding distinction](https://learn.microsoft.com/en-us/azure/databricks/dev-tools/auth/aad-token-manual), [native ACLs](https://learn.microsoft.com/en-us/azure/databricks/security/auth/access-control/), [Databricks Private Link](https://learn.microsoft.com/en-us/azure/databricks/security/network/concepts/privatelink-concepts), [AML Private Link](https://learn.microsoft.com/en-us/azure/machine-learning/how-to-configure-private-link?view=azureml-api-2), [FileREST OAuth](https://learn.microsoft.com/en-us/azure/storage/files/authorize-oauth-rest), [ACR read roles](https://learn.microsoft.com/en-us/azure/container-registry/container-registry-rbac-built-in-roles-directory-reference) and [excluded datastore secrets](https://learn.microsoft.com/en-us/rest/api/azureml/datastores/list-secrets?view=rest-azureml-2026-03-01).

The paired JSON report records exact source hashes, native fixture origins, focused test receipts and remaining proof limits. This is a finite source-surface review, not a claim that every Azure service or code location is covered.
