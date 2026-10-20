# CSPM platform security review — 2026-10-19

Local source review and mocked regressions only. No live customer systems, production accounts, paid model invocations or deployment were used. Severity describes potential impact under the stated prerequisites, not a confirmed production compromise.

## Third pass — high availability impact: tiny kubeconfig could exhaust API workers

`yaml.safe_load` prevents Python object construction but permits aliases and recursive/shared graphs. The kubeconfig validator accepted valid cluster/user/context sections while ignoring extra top-level metadata. `credential_values` subsequently reparsed and recursively walked every metadata value when creating/updating a connector. The traversal had no graph deduplication or structural budget and ran in the API process, outside scan quotas and worker deadlines.

A local reproduction used 836 bytes of YAML with 24 levels of doubled aliases in an otherwise valid kubeconfig. Validation accepted it. Traversing its 33,554,431 repeated leaf references took 66.151 seconds locally. Increasing a few alias levels increases the traversal exponentially; repeated mapping leaves also accumulate an enormous credential tuple before redaction. A signed-in user able to submit a connector could therefore occupy API threads/CPU or exhaust API memory. Deployments requiring a successful connector access check additionally require the attacker to complete that check for their submitted credential/server. No large-memory/OOM payload or production request was run.

Fixed with a data-only credential YAML parser that rejects all aliases and bounds bytes, nodes and depth before constructing the document. Kubeconfig validation and the redactor's YAML fallback share it. Credential extraction additionally tracks visited containers and bounds structure, so cyclic/shared in-memory objects cannot trigger repeated expansion. Strings in credential arrays are now included in secret extraction rather than silently skipped. Ordinary embedded tokens, certificates and multiple contexts remain supported; kubeconfig YAML aliases are intentionally unsupported.

Regressions use an unexpanded 31-level alias document, a cyclic alias, depth/node limits, shared/cyclic Python containers, and a complete hosted connector request. Unsafe YAML receives HTTP 422 before DNS lookup or storage. Test payloads remain tiny; they do not expand the attack graph.

## Third pass — high availability impact for directly exposed APIs: request limit bypass

The API checked only the caller's `Content-Length` header. Missing lengths defaulted to zero, so chunked HTTP uploads bypassed the advertised 16 MiB limit. FastAPI could consume and decode the unbounded body before authentication dependencies ran. An unauthenticated client reaching an API instance without a stricter upstream body limit could exhaust its memory using oversized JSON uploads. This is conditional on direct exposure or permissive ingress: the hosted AWS gateway's own payload cap limits this particular path. No claim of bypassing that AWS gateway cap is made.

Fixed with ASGI middleware that counts actual bytes before routing or JSON/Pydantic decoding. It rejects an oversized declared length without reading the body, stops receiving once actual bytes cross 16 MiB, rejects malformed/duplicate/conflicting lengths and replays valid uploads once to the router. Existing origin/host checks still run first. The protection applies to local and hosted API instances independently of proxy behavior.

Regressions exercise missing, chunked and understated lengths; malformed numeric/duplicate/ambiguous framing; exact-limit valid bodies; early termination without reading the remaining upload; and a complete unauthenticated API request exceeding the real 16 MiB cap. They use bounded local ASGI messages and do not send traffic to a deployed service.

## Second pass — high: AWS log reader bypassed the shared collector's tenant boundary

The normal collector rejected customer roles that could be assumed without an External ID. Attack Analysis's `_target_session` did not perform this check at all. The connector access checker identified an unprotected trust policy but continued to assume the role and read IAM/EC2 configuration anyway. An authenticated attacker could select a known victim role ARN trusting the shared collector and use their own workspace External ID. If that role omitted the External ID condition, Attack Analysis could read its CloudTrail events or permitted S3 log objects. This needs a misconfigured customer trust policy; it is not a bypass of an exact customer External ID condition. The normal scan's existing guard did not protect these other entry points.

The existing guard also tested only an absent ID, which misses `StringLike` conditions accepting every CSPM workspace's IDs. Its probe duration differed from the real exchange; the access checker additionally used a different session name. Trust policy conditions on these parameters could make a probe misleading.

Fixed all three entry points with a shared fail-closed guard. Before using customer credentials, the same collector/role/session parameters must receive explicit AWS AccessDenied for both an absent External ID and a random unrelated ID in the issued namespace. Success, timeouts, malformed responses and other errors block customer reads. Probe credentials are discarded. Customer-supplied credential contexts retain their existing behavior. The normal collector's probes still use its call budget, cancellation and deadline checks. This adds one STS denial probe per hosted role compared with normal collection previously.

Reproduction tests simulate unconditioned, wildcard and exact trust policies and transport failure. They verify zero customer reads from the access checker and log reader unless both denial probes pass. Native collector Stubber tests verify the same protected scan path. No victim account was contacted.

## Second pass — high: revoked admins could finish delayed permission grants

Workspace management routes checked admin membership before database writes. Invitation creation then performed a separate Cognito directory lookup. If an owner revoked/demoted the requesting admin after authorization, that request could still create a fresh admin invitation or promote another member after revocation, leaving persistent access. Invitation revocation and member removal had the same stale authorization window. This requires an already-authorized admin request racing a subsequent revocation; an arbitrary outsider cannot initiate it.

Fixed invitation creation and all membership mutations with database-level authorization fencing. SQLite checks the actor inside the same immediate transaction as the mutation. DynamoDB condition-checks the actor's current admin role in the write transaction; self-demotion/removal includes the condition on its own write because DynamoDB cannot separately condition-check and update the same item. Every HTTP membership mutation passes the authenticated actor. Operator/internal store calls without an actor remain trusted operations.

Regressions exercise both SQLite and a mocked DynamoDB service, including a complete HTTP invitation request whose directory lookup revokes the caller before the pending write resumes. The request now returns 403 and creates no backdoor invitation. Tests also cover delayed promotion/removal/revocation after removal or demotion to read/write access, and legitimate self-demotion/removal.

## High: hosted Kubernetes access checks could select platform credentials

The hosted connector validator accepted `in_cluster`, `in-cluster`, `kubeconfig` or `context` with an unrelated public server/token. The access-check route invoked `_new_api` directly, without the hosted restrictions used by full collection. The SDK could therefore select the server's mounted service account or default kubeconfig rather than the submitted credentials. Checks also missed the hosted transport's DNS pinning. This is a credential/tenant boundary failure when the API runtime has ambient Kubernetes credentials. The shipped AWS runtime is not known to have those Kubernetes credentials; no production exploitation was attempted.

Fixed with one shared `hosted_auth` validator, enforced by HTTP validation, the client factory and collector. Hosted probes explicitly enable the public-address, DNS-pinned transport. Ambient authentication methods and file-based credential selection are rejected before SDK initialization. Safe inline configurations resolve directly to their embedded credentials.

## High-impact execution hazard: file-backed kubeconfig helpers

Uploaded inline kubeconfigs already rejected exec helpers, but local/default file-backed configurations still reached `kubernetes.config.new_client_from_config`, which supports credential plugins. That SDK path can execute a command specified by a kubeconfig. Local file-based helpers were previously an intentional supported feature; exploiting this requires control over a loaded file, or a runtime configuration exposing ambient kubeconfig selection. This review does not claim a pre-authentication RCE through the already-validated inline upload path.

All CSPM kubeconfig paths now use bounded safe parsing and extract only embedded tokens/certificates and the selected cluster. The collector never calls the SDK kubeconfig loader. Every user and cluster entry, including unused ones, is validated. Exec/auth-provider plugins, credential-file references, proxies, insecure TLS and unknown credential settings are rejected. Server, CA, token/certificate and optional TLS server name remain supported. Multi-file kubeconfig merging is rejected. Explicit local in-cluster authentication remains an operator feature; hosted callers cannot select it.

## High: stale DynamoDB invitation could restore revoked admin access

`respond_workspace_invitation` read an invitation, then deleted its key with only `attribute_exists(PK)` before creating membership from the old role. If an owner revoked an admin invitation and issued a read invitation between those operations, an in-flight acceptance could consume the new invitation and create an admin membership using stale data. A stale decline could also consume a new invitation.

The transaction now requires the current invitation's role, creation timestamp, recipient email and inviter to match the snapshot used for membership. Changed/reissued invitations fail atomically with HTTP 409. SQLite already performs its read and response in one transaction.

## Critical trust-boundary risk: unrestricted AI command execution

The installed Chack Codex backend constructs commands with `--dangerously-bypass-approvals-and-sandbox`. Running this in a temporary directory with an environment allowlist does not stop agent-generated commands from reading the worker's filesystem, other process environments or platform metadata endpoints. A compromised/prompt-injected agent could reach privileges of the platform worker, potentially crossing tenants. No live prompt-injection attack or model execution was performed; this is a confirmed absence of process isolation, not a claimed successful LLM exploit.

Mitigation: AI invocation now fails closed unless a deployment-owned isolation launcher is configured. The check occurs before credential-file creation and subprocess launch. Scans retain their deterministic findings. Settings and scan forms report missing isolation separately from missing Codex access; local AI-enabled launches require both.

**Initial mitigation:** the initial change did not implement an isolation runtime. A subsequent hosted implementation now exists in `peaso/ai/fargate.py`, `task_runtime.py`, `model_relay.py` and `infra/aws/ai_runtime.tf`; see [hosted isolation](ai-review/hosted-isolation.md). Deployment and an isolated live Codex smoke remain required acceptance steps. Unconfigured deployments still run no agents. A configured executable is an operator trust boundary, not proof that the executable provides isolation. Do not configure a pass-through script, shell or ordinary Python binary as the launcher.

### Isolation launcher contract

Set `PEASO_AI_ISOLATION_LAUNCHER` to an absolute executable path owned by root or the runtime user, without group/world write permissions. The launcher is trusted deployment configuration, never an HTTP or connector option. Invocation is:

```text
LAUNCHER --workspace PRIVATE_DIRECTORY -- EXECUTABLE -m peaso.ai.runner STAGE
```

The launcher must provide a real container/VM/OS sandbox and retain these capabilities:

- Mount that invocation's workspace: its scan JSON, indexed evidence database/reader and `credentials.json`. Allow workspace output, scripts and temporary SDK files. Provide a read-only Python/Node/Codex/cloud-SDK runtime. Do not expose platform state, encryption keys, other scan workspaces, host credential files or the container/host management socket.
- Isolate process inspection and signaling: no parent process environment/memory access, host PID namespace or inherited platform descriptors. Clean environment alone is insufficient.
- Permit the model backend and assigned read-only cloud API destinations. Block platform metadata/credential endpoints and platform internal services. Cloud SDKs must use the supplied credential entries, never platform defaults. A cloud account reachable through a configured private endpoint needs an explicitly scoped network route; do not enable unrestricted host networking.
- Separate model backend authentication from agent tool commands. Chack/Codex auth files and tokens must not become readable by arbitrary agent-generated shell commands. A container around the entire runner alone does not enforce that separation.
- Apply CPU/memory/PID/runtime limits and terminate all isolated work when the launcher is killed or the invocation ends. Do not leave detached jobs behind.

The API must report the same deployment capability as the analyzer. Compose passes the configured launcher path to the analyzer; the executable and isolation runtime must be supplied by the deployment. Hosted deployments can now select the supported role-free Fargate backend instead of a local executable launcher. It must be wired and live-validated as described in the hosted isolation guide; otherwise AI remains unavailable. Installing a token does not override the isolation requirement.

## Scope and limits

Reviewed authentication/refresh flow, API-key restrictions, workspace authorization, artifact tenant prefixes/caches, connector validation, cloud client construction, subprocesses and frontend rendering/copyable commands. The second pass also traced shared AWS role use across scans, connector probes and interactive log reads; GCP service-account/federation credential construction; Azure token audience/origin separation; and archive/file/command handling. No separate pre-authentication account takeover, SQL injection or stored XSS was confirmed in these reviewed paths. This is not an exhaustive assurance claim or a substitute for a deployed penetration test. Ordinary SDK/profile authentication outside kubeconfigs remains subject to the operator's trusted local configuration.

Regression tests cover unsafe hosted methods, missing DNS-pinned probe flags, local and uploaded kubeconfig helper rejection, safe inline credential selection, stale invitation acceptance/decline, and AI launch refusal without isolation. Other tests cover tenant isolation and existing collector/AI behavior using mocked cloud/model calls.

Second-pass validation: 283 distinct backend tests passed. The collector/workspace/access-check/second-pass group initially passed 150 tests; expanding the second-pass module from 24 to 42 cases passed all 42. Another 115 tests passed across the first-pass security regressions, Attack Analysis, hosted storage, API authentication, API keys and worker diagnostics. Python compilation and `git diff --check` also passed. All cloud interactions in these tests were stubs or local mocks; these results do not constitute AWS deployment validation.

Third-pass validation: 509 distinct backend tests passed. The security/API/authentication/credential-redaction group initially passed 154 tests; the added conflicting-framing case then passed in the complete 18-test resource-bound module. Another 354 tests passed across Kubernetes/Azure collectors, the bounded Kubernetes transport, AKS, Azure DevOps Git and Databricks. Python compilation and `git diff --check` passed. No frontend source changed in this pass, and no production exploitation or deployment was performed.
