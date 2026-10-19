# Peaso privilege-escalation map (`peaso.privesc`)

`peaso.privesc` reads a collected snapshot and the technique catalog
(`peaso/privesc/catalog/<provider>/*.yaml`, schema in `docs/peaso-privesc-schema.md`)
and produces a **Privilege Escalation Map**: which principals can turn their current
permissions into which other identities or admin scopes. It calls no cloud API and
does not change the snapshot.

```python
from peaso import privesc
result = privesc.analyze(snapshot)        # catalog_dir=None -> peaso/privesc/catalog
result["findings"], result["graph"], result["coverage"], result["stats"]
privesc.queries.reach_admin(result["graph"])
```

## How it works

1. **Provider model** (`effective_permissions/{aws,gcp,azure,k8s}.py`). Each model normalises the snapshot once into principals, target inventories and exact permission checks:
   - **AWS**:
     - inline, managed and group policies;
     - case-insensitive Action/NotAction globs and Resource/NotResource;
     - explicit Deny overrides an Allow;
     - `Condition` blocks are **evaluated** (`aws_conditions.py`, three-valued) against the request context of the technique: the principal (ARN, account, tags, org id, `${aws:username}`/`${aws:userid}` substitution in `Resource`), the action and service (`iam:PassedToService` from the technique's receiving service, `iam:AssociatedResourceArn`), the target (`aws:ResourceTag/*`, resource account) and keys that a direct call does not carry (`aws:SourceArn`/`SourceAccount`/`CalledVia` are absent). `IfExists`, `Null`, negated operators, `ForAllValues`/`ForAnyValue` and `aws:RequestedRegion` for global services are handled. A condition proven true keeps the edge `derived`; one proven false drops the edge (Allow) or ignores the statement (Deny); an undecidable one (MFA age, source IP, time, request tags) keeps the edge `conditional` (status MANUAL) and the granting statement is cited with `condition_evaluated: "undecided"`;
     - permission boundaries are intersected;
     - SCPs are evaluated at every level of the organization path (account, OUs, root): every level must Allow and a Deny at any level wins. The path comes from `organization_parent {ChildId, ParentId}` items, `organization_account.ParentId`, or `scp_policy.InheritedPolicies`. Without the path, only the SCPs attached to the account are evaluated and edges are conditional (`inherited_scps_not_evaluated`, coverage `only directly attached SCPs evaluated`). When SCPs were not collected at all, edges are conditional (`scp_not_evaluated`);
     - resource control policies (`rcp_policy` items, or `scp_policy` items typed `RESOURCE_CONTROL_POLICY`): their Deny statements apply to requests on resources of the attached account and its OUs/root, for the RCP services only (S3, STS, KMS, SQS, Secrets Manager, ECR, OpenSearch Serverless, Cognito Identity, DynamoDB, CloudWatch Logs). A proven deny drops the edge and an undecidable one makes it conditional (`rcp_conditional_deny`). When the account's SCPs were collected but RCPs were not, coverage reports `rcp_policy not evaluated` and the edges are not downgraded;
     - session policies are not modelled. They only narrow an assumed session, and whoever controls the principal can get a session without one;
     - `aws:PrincipalOrgID` is decided when `organization_account` gives the org id and lists the principal's account;
     - resource-based policies, where collected: `lambda_function.Policy`, `bucket.Policy`, `kms_key.Policy`, `sns_topic` / `sqs_queue` attribute policies, `secret.Policy.ResourcePolicy` and `ecr_repository.Policy`. In the same account, either the identity or the resource policy may grant. Cross-account access needs both. For KMS, identity policies count only when the key policy grants or delegates to the account. `NotPrincipal` is inverted, and an explicit Deny on either side wins. Principals named directly by a resource policy are added to the source prefilter, so a grant that exists only in a resource policy is still found;
     - requirements that share a multi-valued placeholder (`{target.resource_arn}`, `{target.attached_resource_arn}`, `{target.host_resource}`, `{target.artifact_arn}`, `{target.consumer_input_arn}`) must all hold on the same resolved resource. The first evidence ref is `{"shared_resource": <arn>}`;
     - `{source.assumable_role_arn}` stands for every role the source can already assume. A role qualifies when its trust policy admits the source and either names the source ARN in the same account or the source's identity policy allows `sts:AssumeRole` on it;
     - pivots of type `aws_stackset_administration_role` are existing roles that trust `cloudformation.amazonaws.com`. Selector `assumable_by_pivot_role` keeps the roles that such a pivot can assume, in any account, and excludes the pivot itself;
     - the `ecr_tag_immutability` blocker is evaluated from `ecr_repository.imageTagMutability`. The edge is dropped when every repository the source can write is `IMMUTABLE` and the source cannot call `ecr:PutImageTagMutability`;
     - trust policies are indexed by service, ARN, account, federated principal and public.
   - **GCP**:
     - allow bindings inherited through org > folder > project > resource;
     - custom and predefined roles come from the `iam_role` items. A small builtin table covers basic roles and the key IAM roles. Any other uncollected role is listed in coverage;
     - IAM Conditions (CEL, `gcp_conditions.py`, three-valued) are evaluated per target resource for the decidable subset: `resource.name` (`==`, `!=`, `startsWith`, `endsWith`), `resource.type`, `resource.service`, `request.time` against `timestamp(...)`, `&&` / `||` / `!`. A binding whose condition is false now (an expired `request.time < timestamp(...)`) is inactive and skipped (coverage `conditions`). A condition true for the target (or a future expiry) gives a derived grant. A condition false for the target removes that binding for it. Anything else (`resource.matchTag`, `request.time.getHours()`, `api.getAttribute`, unsupported syntax) keeps the edge conditional (`binding_condition`) with the expression in the evidence ref (`expression`). `resource.name` is compared against every plausible name of the target: project id and number; SA by `projects/<p>/…/<email>`, `projects/-/…/<email>` and unique id. It is decided only when all of them agree;
     - deny policies are evaluated. When they were not collected for a scope, edges are conditional;
     - selector `gcp_implicit_delegation_chain` follows `iam.serviceAccounts.implicitDelegation` transitively, up to 10 hops. It reaches the SAs that a delegate can call getAccessToken, signBlob or signJwt on. The delegates themselves are not targets, and their emails are recorded as `delegate:<email>` conditions;
     - GKE: `gke_cluster` items become `k8s_cluster_admin` entities. They also scope `k8s_service_account` targets that use `k8s_sa_has_token_secret` or `k8s_sa_in_cluster`, where `{target.scope}` is `projects/<p>/locations/<l>/clusters/<c>`. When a K8s snapshot of that cluster is passed in `related_snapshots`, the targets are its real KSAs, with the same node ids as the K8s map. For the token-secret selector these are the KSAs named by `kubernetes.io/service-account-token` Secret metadata. Without a related snapshot, each cluster gets one `gke-ksa:<variant>:<cluster>` aggregate node with conditional confidence (`k8s_snapshot_not_joined`). When the related snapshot has no secret metadata, that node is unknown (`k8s_secret_metadata_not_collected`);
     - source selector `gcp_workspace_admin_role` (`super_admin` or an admin roleId / roleName) reads `workspace_user {primaryEmail, isAdmin}`, `workspace_role {roleId, roleName, isSuperAdminRole}` and `workspace_role_assignment {roleId, assignedTo}`. When these facts are missing, the technique is not evaluated and a coverage entry is added. The scope rule `org` on `gcp_scope_owner` targets keeps only organization nodes.
   - **Azure**:
     - role assignments × role definitions, covering Actions/NotActions and DataActions;
     - scope inheritance root > MG > subscription > RG > resource;
     - transitive group membership;
     - ABAC conditions on role assignments: in the documented form `((!(ActionMatches{'a'}) [AND !(ActionMatches{'b'} …)]) OR (…)) [AND (…)]`, a condition only constrains the actions its negated `ActionMatches` names. Any other action of the role stays derived. A named action, or a condition in any other form, is conditional (`role_assignment_condition`) with the expression in the evidence ref (`condition`);
     - PIM: only `directory_role_assignment` (active, including activated PIM assignments) grants a role. `directory_role_eligibility_schedule` gives `entra_pim_eligible_role`, which is always conditional (`pim_activation_required`, plus `pim_eligibility_scope_restricted` for an AU/object scope). Revoked, canceled or failed schedules are ignored. When `directory_role_eligibility_instance` was fully collected, an eligibility without a current instance (expired or not started) is ignored;
     - deny assignments are evaluated. When not collected, edges are conditional;
     - resource managed identities (system and user assigned);
     - Entra directory roles and their scopes;
     - `{source.controlled_user}` (alias `{target.user}`) is the user object the source modifies. For an `azure_user` source it is the source itself (`dir:<id>`). For any other source it is unresolved, so the edge is conditional (`controlled_user_not_identified`).
   - **Kubernetes**:
     - Role/ClusterRole rules with aggregation;
     - apiserver `ResourceMatches` semantics (`*`, `res/sub`, `*/sub`);
     - `resourceNames` restrict targets to the named objects. create/list/watch/deletecollection never match a rule restricted by `resourceNames`, except create on a subresource (`serviceaccounts/token`, `pods/exec`), which names the parent object;
     - RoleBinding namespaces. `namespace: "*"` requires a ClusterRoleBinding;
     - cluster-scoped resources;
     - cloud identities taken from SA annotations (IRSA, GKE WI, Azure WI);
     - kiam/kube2iam: the namespace annotation `iam.amazonaws.com/permitted` (a regex, full match) or `iam.amazonaws.com/allowed-roles` (JSON globs) is matched against role ARNs and names. The candidates are the roles of the related AWS snapshots plus the pod annotations `iam.amazonaws.com/role`. An invalid regex makes the edge conditional;
     - with `related_snapshots`, IRSA trust, GKE Workload Identity and Azure FIC selectors are verified against the cloud snapshots. Each `cloud_identity` node is also joined to the real IAM principal by a cross-snapshot edge with technique `cloud-identity-join`.
2. **Evaluator** (`evaluator.py`). Before the techniques, every principal's admin-equivalent scopes are computed. For each technique:
   - expand `all_of` plus one `any_of` group;
   - classify each requirement as static, pivot or per-target;
   - filter the target inventory with the static selectors. The result is cached as a *candidate set*;
   - find candidate sources through an inverted index (requirement key → principals that may hold it), then run exact checks;
   - apply the source-dependent selectors and the target scope rule;
   - check the entry's machine-checked `preconditions` (see below).

   Sources skipped before any check:
   - **service-managed identities** (AWS service-linked roles, Google service agents, Microsoft first-party SPs) are never sources: only the owning service holds their credentials. An entry opts in with `source_selector.include_service_managed: true`. Counted in `stats.skipped_service_managed_sources`;
   - **admins**: a source that already administers every scope the technique's targets can live in (restricted to the scopes its scope rule allows) is skipped; its `admin-equivalent` edge says it all. Counted in `stats.skipped_admin_source_evaluations`; `include_admin_sources=True` evaluates them.

   Performance:
   - A `Resource: "*"` requirement never materialises one result per target. It returns a symbolic "every candidate" result that the graph builder aggregates. So does a path whose identity, boundary and SCP statements are all resource-independent (one representative check stands for every target without a resource policy).
   - Sources with the same model memo key (AWS: same policy set, boundary and account, and no principal-dependent policy or trust) are evaluated once per technique alternative when nothing in it names the source (`stats.memoized_source_evaluations`).
   - AWS `{target.arn}` checks over a whole candidate set only test targets inside an Allow pattern's literal ARN prefix (bisection on a sorted index), plus targets with a resource policy and roles whose trust names the source.
   - The memo also covers dynamic selectors that do not depend on the source (`model.memo_safe_selectors`). Per-target requirements whose template depends on the target only through its scope (`{target.account}`) are checked once per scope (`model.scope_only`).
   - AWS `check_targets`: targets outside every narrow statement's patterns share one representative check, and narrow patterns are matched by bisection on a sorted ARN index.
   - Combining the grants of several requirements is deduplicated per grant object.
   - The garbage collector is paused during `analyze()`.

   Measured: the real 1x AWS estate (313 principals) in about 0.3 s; the synthetic benchmark (`tests/fixtures/privesc/synthetic_aws.py`) at 10x (3,156 principals) in about 1.6 s, 40x in about 18 s, and 100x (31,506 principals) in about 123 s (evaluate 77 s, graph 43 s) with 1.9 GB peak RSS. The 100x benchmark runs with `PEASO_PRIVESC_BENCH=1`.

   **Preconditions** (`preconditions: [id | {id, description}]`, registry `schema.PRECONDITIONS`): facts about the target (or the source) that the technique needs and the snapshot can prove. Each one keeps the targets that satisfy it, drops those that do not, and turns targets with missing facts into `unresolved:` placeholders (UNKNOWN, never FAIL). Registered ids: `ec2_instance_running`, `ssm_managed_instance` (SSM agent `Online`), `ecs_container_instance_exists`, `ecs_task_definition_exists`, `eks_cluster_exists`, `target_in_other_account`, `source_in_org_management_account`, `k8s_eks_cluster` (node `providerID` `aws://`, an `*.k8s.aws`/`*.amazonaws.com` API group or the `kube-system/aws-auth` ConfigMap; a kind/GKE/AKS cluster is not EKS) and `k8s_openshift_cluster` (an `*.openshift.io` API group in `api_discovery`). The validator rejects unknown ids and ids of another provider.
3. **Graph builder** (`graph.py`). Turns reaches into nodes, edges and one finding per (technique, source). It applies these rules:
   - **Edge dedup**: there is exactly one edge per (source, target). Each technique that reaches the pair is one entry in `technique_details`, with its own confidence, evidence, conditions and mitigation. Findings stay per technique and point to their edges through `evidence.edge_ids`. `stats.distinct_paths` counts the deduplicated edges and `stats.findings` counts per-technique findings.
   - **Aggregation**: targets are aggregated when there are many of them. Admin-equivalent edges are added.
   - **Pruning**: an entity target is dropped when a broader scope of the same kind is already reached.
   - **Suppression**: an edge is suppressed when its source already administers the target scope (counted in `stats.suppressed_admin_edges`). Pass `include_admin_sources=True` to keep these edges.
   - **Group identity and labels**: candidate sets are shared by techniques with the same target kind and static selectors, but a group node's id carries a hash of the technique's `aggregate_as` template (and of the source when the template names it), and its label is rendered from that template with `{target.namespace}`, `{target.account}`, `{target.scope}`, … replaced by the group's scope. A full-scope group lists every candidate of the scope (the source itself is never its own target).
   - **Shared placeholders**: `unresolved:` and `unknown:` placeholders carry no members, so every source holding the technique's permissions reaches them the same way. Each placeholder is reached once per technique by the group of its holders (`agg:sources:…`, one UNKNOWN finding per group); a holder drops placeholders in scopes it administers and, for scope-entity targets, scopes below another scope it reaches. A reach to several placeholders is one node `unresolved:<cset>:scopes:<hash>` with `scopes: [...]`. On the real 78-project GCP scan this took the graph from 421,119 edges (415,683 unknown) to 5,807 (371 unknown) with the 5,436 derived/conditional edges unchanged.

### Exact granting permissions in the inspector

Each technique records the permissions its source satisfied alongside their granting policies or roles. AWS matches include the policy ARN and name, statement index/Sid, Allow actions, resources, and native conditions. Azure matches include assignment and definition IDs, scope, inherited principal/group, actions/dataActions and exclusions. GCP matches include the binding scope, role and matching permission patterns. Kubernetes matches include the binding, namespace and exact RBAC rule. Native field names and conditions retain their original syntax in the inspector.

`admin-equivalent` uses the same evidence: an AWS `Action: *` / `Resource: *` grant names the policy and statement; GCP and Azure identify the specific IAM/role-assignment permission establishing administrative authority, or the assigned Entra Global Administrator role; Kubernetes names its wildcard rule and binding. The administrative description is generated from that match. Conditions and guardrails retain their original confidence.

Bound/shared requirements preserve their individual permission matches before combining grants. Permission matches remain complete even when the separate native-reference sample is capped. Finding and principal APIs preserve recorded matches when adding catalog metadata. The inspector fetches admin findings too and uses each technique's recorded finding ID. Older stored assessments that lack exact matches show the recorded source and identify the missing match; a new assessment is needed for the additional evidence.

### Missing data is never a silent absence

| Situation | Effect |
|---|---|
| Collection `denied` / `partial` / `not_collected` for a required type | `coverage` entry; techniques reaching that inventory get an `unknown:<candidate set>:<scope>` aggregate target with `unknown` confidence |
| Guardrail not collected (SCP, GCP deny policy, Azure deny assignment) | Edge downgraded to `conditional`, condition `scp_not_evaluated` / `deny_policies_not_evaluated` / … |
| Selector whose facts are not in the snapshot (verdict `None`), or that matches a target only with `unknown` confidence (e.g. a role trusting `lambda.amazonaws.com` when Lambda functions were not collected), or a target reached only through missing facts (e.g. an unresolvable `{target.consumer_input_arn}`) | The target set is **never** expanded to every principal. Those targets are not members: each technique source reaches one `unresolved:<candidate set>:<scope>` placeholder (`label: "Unresolved: <aggregate label>"`, `underlying_count: 0`, `members: []`, `unknown` confidence, `unresolved_reason`, `facts_needed`). The source must still hold every per-target action on some resource. Coverage `kind: "selector"` (`not_evaluated` / `unresolved`) names the facts needed (`schema.FACTS_NEEDED`). This applies to static and source-dependent selectors |
| `attached_to_service` / `via_resource_type` host inventory | An inventory that is authoritatively complete (`collected`, including 0 items, or `empty`) for the target's scope means no such workload carries the identity: **no edge**. Only a `denied` / `partial` / missing collection, an item whose identity cannot be read, or a host type that is not modelled yields `unknown`. Hosts modelled: AWS Lambda, EC2 (instance profiles), Service Catalog, CodeBuild (`codebuild_project` `serviceRole`), Glue jobs (`Role`, name or ARN), Redshift clusters (`IamRoles`), RDS instances (`AssociatedRoles`); every region of the account must be complete. GCP Compute instances, Cloud Run services (`template.serviceAccount`), Cloud Functions (v2 `serviceConfig.serviceAccountEmail`, v1 `serviceAccountEmail`), Dataproc clusters and GKE node pools (unset / `default` = the project's default compute SA `<number>-compute@developer.gserviceaccount.com`; v1 functions default to `<project>@appspot.gserviceaccount.com`); an Autopilot cluster without listed pools keeps the project partial. Azure per subscription: a typed collection (`vm`, `app_service`, `aks_cluster`, `storage_account`, `vault`, `sql_server`, `policy_assignment`) or a complete `resource_graph` (top-level types and `GRAPH_TRACKED_CHILDREN`; a child type whose parent type has no resource at all is also decided). A tenant-scoped (directory-only) managed identity needs every visible subscription to be decided, and the subscription listing to be complete. On the real Azure scan (az-snap-v2) this took unknown edges from 102 to 36 with the derived set unchanged |
| Precondition facts missing (e.g. `ssm_managed_instance` not collected, cluster flavour not determined) | Target becomes an `unresolved:` placeholder: UNKNOWN, never FAIL. A precondition proven false (stopped instance, kind cluster for an EKS technique) drops the target |
| IAM condition undecidable from the snapshot (MFA, source IP, time, request tags) | Edge `conditional`, finding status MANUAL, granting statement cited with `condition_evaluated: "undecided"` |
| Service-managed identity | Never a target nor a source: AWS service-linked roles (path `/aws-service-role/`), Google-managed service agents (`service-<n>@gcp-sa-*`, `*-robot`, `<n>@cloudservices` / `@cloudbuild`), Microsoft first-party service principals (`appOwnerOrganizationId` of a Microsoft tenant). They are kept only when the entry sets `target.include_service_managed: true`, or (GCP) selects them via `attached_to_service`, or (Azure) models them with the `microsoft_first_party_sp` condition/blocker. They stay as sources |
| Requirement whose facts are missing entirely (e.g. Graph app permissions) | Coverage `kind: "requirement"`; the principals that may satisfy it are grouped into one `principal_group` aggregate source with `unknown` edges |
| Invalid catalog entry | Dropped (never half-evaluated), coverage `kind: "catalog"`, `status: "invalid"` |

Confidence levels:
- **derived**: every fact was evaluated.
- **conditional**: a condition, an unevaluated guardrail, an approximated builtin role, or a pivot that may need creating.
- **unknown**: required facts are missing.

## Cross-snapshot analysis

```python
privesc.analyze(k8s_snapshot, related_snapshots=[aws_snapshot, gcp_snapshot])   # K8s cloud identities -> IAM principals
privesc.analyze(gcp_snapshot, related_snapshots=[gke_k8s_snapshot])              # GKE techniques -> real KSAs
```

Related snapshots are only read and never fetched. An EKS cluster (`eks_cluster` in the AWS snapshot) becomes a `k8s_cluster_admin:<cluster arn>` entity labelled "EKS cluster <name> (cluster-admin)"; when a K8s snapshot of that cluster is related (its `metadata.cluster_id` or item `provenance.cluster_id` is the cluster ARN, the `k8s-cluster:<sha256>` digest of the API endpoint, or a unique cluster name), a `cloud-identity-join` edge links it to the K8s map's `k8s_cluster_admin:<cluster_id>` node. A GKE cluster is matched to a K8s snapshot by `provenance.cluster_id`, which can be the GKE full path, `//container.googleapis.com/...`, a `gke_<project>_<location>_<name>` context, or a unique cluster name. Joined principals appear as nodes with `attrs.related_snapshot: true` and `provider` set to their own cloud. The output adds `stats.cross_snapshot_edges` and `stats.related_snapshots`; every other key is unchanged.

**Engine contract (stable).** `privesc.analyze(snapshot, related_snapshots=[...])`:
- `snapshot`: the primary snapshot (its provider's catalog is evaluated; findings, graph and coverage are for it).
- `related_snapshots`: the other snapshots of the same scan / connector set (any order; `None` or `[]` = no join). They
  are read only; the primary itself and snapshots of providers the model does not join are ignored (K8s joins
  aws / gcp / azure; GCP and AWS join k8s; Azure joins nothing yet). The engine should pass every other-provider
  snapshot of the scan; it is cheap to pass unrelated ones (unmatched clusters simply do not join).
- Result shape is identical to a single-snapshot run. Extra: `stats.related_snapshots` (providers used),
  `stats.cross_snapshot_edges` (edges with an endpoint in a related snapshot: K8s cloud-identity joins, GCP container.*
  techniques reaching KSAs of the joined cluster, EKS cluster-admin joins), node `attrs.related_snapshot: true`, and
  an aggregate whose members all come from the related snapshot carries that snapshot's `provider` (e.g. `k8s`).
- For a joined view run it once per primary (K8s with the clouds as related, and each cloud with the K8s snapshots as
  related); edge and node ids are stable across runs, so the two graphs can be merged by id.

**Node cloud identities.** With a related cloud snapshot the K8s `k8s_node_cloud_identity` selector resolves each node's
identity: GKE node-pool `config.serviceAccount` (node label `cloud.google.com/gke-nodepool`, providerID `gce://`;
unset / `default` = `<project number>-compute@developer.gserviceaccount.com`), EKS instance-profile roles of the
`aws:///<az>/<instance id>` instance, AKS `identityProfile.kubeletidentity` of the cluster whose `nodeResourceGroup` is
in the `azure://` providerID. Identities are `cloud:gke_node:<email>` / `cloud:eks_node:<role arn>` /
`cloud:aks_kubelet:<client id>` nodes joined to the cloud principal. Node source: derived for its own node. Pod
creators (IMDS technique): derived when some node exposes metadata (GKE `GCE_METADATA`, EC2 IMDSv1 allowed or hop
limit >= 2, AKS), `conditional` (`node_metadata_concealed`) on GKE `GKE_METADATA` / IMDSv2 hop limit 1, and
`conditional` (`node_metadata_access_not_verified`) when the mode is unknown; the hostNetwork technique is not limited
by the GKE metadata server or the hop limit. Without the cloud snapshot the target stays an `unresolved:` placeholder.

**K8s managed subjects.** `K8sModel.managed_source` marks provider / control-plane subjects that are never escalation
sources (counted in `stats.skipped_service_managed_sources`; no admin-equivalent edge) but remain targets: reserved
`system:` / `eks:` users and groups (except `system:authenticated`, `system:unauthenticated`, `system:anonymous`,
`system:serviceaccounts[:<ns>]`, `system:nodes`), known control-plane users (`kube-apiserver`, `kubelet`,
`kubelet-bootstrap`, `kubelet-nodepool-bootstrap`, `kube-controller-manager`, `kube-scheduler`, `kube-proxy`,
`aksService`, ...), and ServiceAccounts of `kube-system`, `gke-managed-*`, `gmp-system`, `gmp-public`, `gke-connect`,
`aks-command`, `aks-istio-*` or an addon-manager / `kubernetes.azure.com/managedby` labelled namespace, or carrying a
`components.gke.io/*` marker, when every binding naming them is provider-created (`kubernetes.io/bootstrapping`,
`addonmanager.kubernetes.io/mode`, `eks.amazonaws.com/component`, `components.gke.io/*`, or a `system:` binding of a
`system:` role). A user-created binding naming such a subject keeps it a source, and a user bound to a managed role is
an ordinary source. `Model.managed_source` defaults to `service_managed` for the cloud providers.

## Engine integration

The engine (`peaso/engine.py`, not owned by this module) adds a category `"privesc"`:

```python
# CATEGORIES = (..., "privesc")
graphs = {"network": ..., "iam": ..., "privesc": {"nodes": [], "edges": []}}
if "privesc" in selected_categories:
    from peaso import privesc
    pe = privesc.analyze(snapshot)
    findings.extend(pe["findings"])                 # category "privesc", status FAIL / UNKNOWN
    coverage.extend(pe["coverage"])                 # level "privesc"
    coverage.append({"level": "check", "check_id": "privesc", "type": "privesc", "scope": "selected_scopes",
                     "status": "unknown" if any(c["status"] != "partial" for c in pe["coverage"]) else "evaluated",
                     "by_status": dict(Counter(f["status"] for f in pe["findings"])),
                     "reason": "Catalog-driven privilege-escalation paths; see coverage level privesc."})
    graphs["privesc"] = pe["graph"]
    report_stats["privesc"] = pe["stats"]
```

Notes for the integration:
- **Status values**: finding `status` is `FAIL` (derived or conditional) or `UNKNOWN` (facts missing). These are upper-case like the other engine findings.
- **`resource_id`**: the source principal id (an ARN, a GCP member such as `user:a@x.com`, an Entra object id, or `k8s:<cluster>:sa:<ns>:<name>`). An aggregated unknown source uses `agg:sources:<technique>:<hash>`. Because these ids are not inventory ids, the engine's resource lookup skips them.
- **Required collections**: `REQUIRED_TYPES[provider]["privesc"]` should include:
  - AWS: `iam_user`, `iam_group`, `iam_role`, `iam_policy`, `scp_policy`, `lambda_function`, `instance`
  - GCP: `project`, `folder`, `iam_policy`, `iam_role`, `service_account`, `iam_deny_policy`, `instance`
  - Azure: `subscription`, `resource_group`, `management_group`, `role_assignment`, `role_definition`, `deny_assignment`, the `directory_*` types, the typed resource endpoints and `resource_graph`
  - K8s: `role`, `clusterrole`, `rolebinding`, `clusterrolebinding`, `serviceaccount`, `namespace`, `pod`, `node`
- **Catalog**: the catalog is loaded once per process (lru_cache). `privesc.catalog()` returns `{entries, errors, warnings, files, excluded}`.

## API route

`peaso/server/app.py` currently restricts `GET /api/scans/{id}/graphs/{kind}` to `Literal["network", "iam"]`. Two changes are needed:
- Add `"privesc"` to the literal and to the bundle's `graphs` / `graph_projections` maps.
- Do not pass this graph through `project_graph`: it is already aggregated, and dropping an aggregate would remove every member reached through it. Either return the complete graph or truncate whole edges.

Response: `{"nodes": [...], "edges": [...]}` exactly as below.

Suggested query endpoints. Each is a thin wrapper over `peaso.privesc.queries` on the stored graph:

| Route | Function |
|---|---|
| `GET /api/scans/{id}/privesc/admins?max_depth=6&include_unknown=true` | `reach_admin(graph, max_depth=, include_unknown=)` |
| `GET /api/scans/{id}/privesc/paths?source=<id>&target=<id>&max_depth=6&limit=10` | `shortest_paths(graph, source, target, ...)` |
| `GET /api/scans/{id}/privesc/broad?min_targets=50` | `broad_reach(graph, min_targets=)` |
| `GET /api/scans/{id}/privesc/principals/{principal_id}` | `principal_card(graph, principal_id, findings)` |

All traversals are bounded by `max_depth` and keep visited sets, so they are safe on cyclic graphs.

## UI contract (exact JSON shapes)

### Principal / entity node

```json
{"id": "arn:aws:iam::111111111111:user/alice", "label": "alice", "type": "aws_user", "provider": "aws",
 "scope": "111111111111", "kind": "principal",
 "attrs": {"arn": "arn:aws:iam::111111111111:user/alice", "account": "111111111111", "name": "alice"}}
```

`kind` takes one of these values:
- `principal`: a real identity.
- `entity`: an admin scope or another target that is not an identity. Its `type` is `aws_account_admin`, `gcp_scope_owner`, `azure_scope_owner`, `k8s_cluster_admin`, `entra_role` or `azure_dataplane_admin`, and `attrs.admin` is true for admin scopes.
- `aggregate`: see the next section.

Entity ids are `<type>:<scope>`, for example `azure_scope_owner:/subscriptions/…/resourcegroups/rg1` or `gcp_scope_owner:projects/p1`.

### Aggregate node

```json
{"id": "agg:aws_role:8aa5e4f516:111111111111:conditional", "kind": "aggregate", "type": "aws_role", "provider": "aws",
 "scope": "111111111111", "label": "Roles trusting ec2.amazonaws.com with an instance profile in 111111111111",
 "underlying_count": 3, "members": ["arn:aws:iam::111111111111:role/ec2-0", "..."],
 "member_sample": [{"id": "...", "label": "ec2-0", "type": "aws_role", "provider": "aws", "scope": "111111111111", "kind": "principal"}],
 "confidence": "conditional", "candidate_set": "aws_role:8aa5e4f516", "subset": false}
```

Aggregate id patterns:

| Id pattern | Meaning |
|---|---|
| `agg:<cset>:<scope>:<conf>` | Every candidate of that scope |
| `agg:<cset>:<scope>:sub:<hash>:<conf>` | A subset of more than 5 members |
| `agg:<cset>:*:<conf>` | Every candidate in more than 10 scopes |
| `unknown:<cset>:<scope>` | Inventory unavailable. `underlying_count` is null and `members` is `[]` |
| `unresolved:<cset>:<scope>` | Selector facts missing: `label` "Unresolved: …", `underlying_count` 0, `members` `[]`, `unresolved: true`, `unresolved_reason`, `facts_needed` |
| `unresolved:<cset>:scopes:<hash>` | The same for several scopes at once: `scope` `"*"`, `scopes` lists them, `unresolved_reason` / `facts_needed` join the per-scope reasons |
| any of the above `+ ":<hash>"` | The technique's own group (its `aggregate_as` differs from the shared candidate set's label) |
| `agg:sources:<technique>:<hash>` | A source group with `type: "principal_group"`: principals that *may* satisfy a technique whose facts are missing |

Expanding aggregates:
- An edge into an aggregate reaches every member.
- A member of a `principal_group` acts through that group's edges with unknown confidence.

### Edge

```json
{"id": "e:fb963a15efba", "source": "arn:aws:iam::111111111111:user/alice",
 "target": "agg:aws_role:8aa5e4f516:111111111111:conditional",
 "techniques": ["aws-ec2-passrole-runinstances"], "confidence": "conditional",
 "evidence_refs": [{"policy": "arn:aws:iam::111111111111:user/alice#inline/alice-inline", "policy_name": "alice-inline",
                    "policy_type": "inline", "statement": 0, "sid": null, "effect": "Allow"}],
 "findings": ["privesc:aws-ec2-passrole-runinstances:arn:aws:iam::111111111111:user/alice"],
 "technique_details": [{"id": "aws-ec2-passrole-runinstances", "title": "Launch an EC2 instance with a passed instance profile",
                        "severity": "critical", "confidence": "conditional", "evidence_refs": [{"policy": "..."}],
                        "conditions": ["scp_not_evaluated"], "mitigation": "Restrict iam:PassRole ...",
                        "finding": "privesc:aws-ec2-passrole-runinstances:arn:aws:iam::111111111111:user/alice"}]}
```

Edge fields:
- There is one edge per (source, target). `techniques` lists every technique that produces it, and `confidence` is the best one among them.
- `technique_details` holds one entry per technique, sorted by confidence (strongest first). It is the only place where the evidence, conditions and mitigation of each technique stay separate.
- The technique `admin-equivalent` marks a source that already administers the target scope.
- The technique `cloud-identity-join` marks a cross-snapshot edge from a `cloud_identity` to the principal it resolves to in a related snapshot. It has no finding.
- The shape of `evidence_refs` depends on the provider:

| Provider | `evidence_refs` fields |
|---|---|
| AWS | `{policy, policy_name, policy_type, statement, sid, effect}` |
| GCP | `{policy, role, binding, condition, expression}` (`expression` only for conditional bindings) |
| Azure | `{assignment, role, scope, via, condition}` (`condition` only for ABAC assignments); PIM `{eligibility, directory_scope}` |
| K8s | `{binding, role, namespace}` |

### Finding (report shape)

```json
{"id": "privesc:aws-ec2-passrole-runinstances:arn:aws:iam::111111111111:user/alice", "category": "privesc",
 "check_id": "aws-ec2-passrole-runinstances", "title": "Launch an EC2 instance with a passed instance profile",
 "provider": "aws", "service": "ec2", "resource_id": "arn:aws:iam::111111111111:user/alice", "scope": "111111111111",
 "severity": "critical", "status": "FAIL", "frameworks": ["HackTricks Cloud Best Practices"],
 "remediation": "Restrict iam:PassRole on EC2 roles ...",
 "evidence": {
   "technique": {"id": "...", "title": "...", "source": "src/pentesting-cloud/...#iampassrole-ec2runinstances",
                 "source_revision": "a53b46392c", "summary": "..."},
   "source": {"id": "...", "label": "alice", "type": "aws_user", "provider": "aws", "scope": "111111111111", "kind": "principal"},
   "targets": [{"id": "agg:...", "label": "...", "type": "aws_role", "kind": "aggregate", "scope": "111111111111", "underlying_count": 3}],
   "target_count": 3,
   "granting_statements": [{"policy": "...", "statement": 0, "effect": "Allow"}],
   "conditions": ["scp_not_evaluated"],
   "confidence": "conditional",
   "edge_ids": ["e:fb963a15efba"],
   "technique_conditions": [{"id": "passrole_condition_key", "description": "..."}],
   "blockers_not_evaluated": ["vpc_sc_perimeter"]}}
```

Finding fields:
- `targets` holds at most 50 entries. `target_count` counts every underlying target.
- `blockers_not_evaluated` and `technique_conditions` appear only when they are non-empty.

### Coverage entry

```json
{"level": "privesc", "provider": "aws", "kind": "guardrail", "scope": "111111111111", "status": "denied",
 "reason": "scp_policy not evaluated", "impact": "Edges are conditional: service control policies may deny them"}
```

`kind` takes one of these values:
- `collection`
- `guardrail`
- `targets`
- `selector`
- `source_selector`
- `blocker`
- `requirement`
- `roles`
- `catalog`
- `provider`

### Stats

```json
{"provider": "aws", "techniques": 153, "principals": 10000, "sources_evaluated": 10000, "reaches": 140, "nodes": 143,
 "edges": 294, "edges_by_confidence": {"derived": 294, "conditional": 0, "unknown": 0}, "findings": 280,
 "suppressed_admin_edges": 0, "admin_principals": 0, "catalog_errors": 0,
 "skipped_service_managed_sources": 0, "skipped_admin_source_evaluations": 0, "memoized_source_evaluations": 0,
 "distinct_paths": 290, "multi_technique_edges": 12, "max_techniques_per_edge": 3, "technique_edge_pairs": 306,
 "cross_snapshot_edges": 0, "related_snapshots": [],
 "timing_seconds": {"model": 0.04, "evaluate": 0.13, "graph": 0.27, "total": 0.45}}
```

### Query results

- `reach_admin` returns:
  ```json
  [{"principal", "label", "type", "admin", "admin_label", "distance", "confidence", "next"}]
  ```
  Results are sorted by distance, then confidence.
- `shortest_paths` returns:
  ```json
  [{"source", "target", "length", "confidence", "steps": [{"from", "to", "via": "edge|membership", "techniques", "confidence", "edge"}]}]
  ```
- `broad_reach` returns:
  ```json
  [{"principal", "label", "reached", "admin", "aggregates"}]
  ```
- `principal_card` returns:
  ```json
  {"principal", "outgoing", "incoming", "techniques", "granting", "member_of_aggregates", "may_act_as", "is_admin", "findings"}
  ```

## Validation

```bash
python3 scripts/peaso_validate_privesc_catalog.py               # errors, warnings, keys unknown to the evaluator
python3 scripts/peaso_validate_privesc_catalog.py --permissions # + actions missing from *_permissions_cat.yaml
python3 scripts/peaso_validate_privesc_catalog.py --json
python3 -m pytest tests/test_peaso_privesc*.py -q
```

The validator checks unique ids, known fields, target kinds, selector keys, placeholders and requirement fields. It also checks that each hacktricks-cloud source file exists, which it skips when the checkout is absent. It lists every key the evaluator does not know and exits with status 1 if any entry is invalid. It also reports these errors:
- a `{target.*}` placeholder that cannot resolve on an entity target kind. For example, `{target.arn}` on `aws_account_admin` would otherwise silently turn every edge into unknown. The allowed placeholders per kind are listed in `schema.ENTITY_TARGET_PLACEHOLDERS`;
- a gcp `k8s_service_account` target without `k8s_sa_has_token_secret` or `k8s_sa_in_cluster`.

`--permissions` treats the mangled form of GCP service-prefixed permissions in `gcp_permissions_cat.yaml` (`iam.googleapis.com-workloadIdentityPools.create`) as equal to the real IAM name (`iam.googleapis.com/workloadIdentityPools.create`). It accepts `cloudidentity.groups.memberships.create` as an evaluator pseudo-permission (`PSEUDO_PERMISSIONS`).

## Known approximations

- **AWS**:
  - Inherited SCPs need the OU path (`organization_parent`) or `InheritedPolicies`. When neither is present, edges are conditional.
  - Resource policies are read only for the collection types listed above. Conditions in them are not evaluated and make the edge conditional. Resources with more than 200 resolved values per shared placeholder are truncated.
  - `ecr_tag_immutability` treats `*_WITH_EXCLUSION` mutability as overwritable.
  - Optional inventories that are not collected yet make their techniques unresolved placeholders (UNKNOWN), never FAIL: ECS container instances and tasks (`ecs_container_instance` / `ecs_task`, or `ContainerInstances` / `Tasks` on `ecs_cluster` items; ECScape co-location is only proven with them), `iam_saml_provider` / `iam_oidc_provider` (orphaned federation trusts), `emr_cluster` (EMR runtime roles), `servicecatalog_portfolio` with LAUNCH constraints (AssociatePrincipalWithPortfolio) and PCA Connector for AD connectors (`aws_directory_domain_admin` targets). Organization facts come from `organization_account`; without it, member-account and CreateAccount techniques are unknown.
- **GCP**:
  - Service accounts and GKE clusters live in projects: an uncollected `service_account` / GKE inventory at folder or organization scope is not an inventory gap.
  - Group membership (Cloud Identity) is not expanded.
  - Predefined roles that were not collected contribute nothing and are listed in coverage. `roles/editor` and other basic roles are approximated and their edges are conditional.
  - `{target.host_resource}` is modelled for compute instances only.
  - Workspace admin facts (`workspace_user`, `workspace_role`, `workspace_role_assignment`) are not collected yet, so the super-admin technique is reported in coverage only. GKE token-secret targets are `unresolved:` placeholders without a joined K8s snapshot that has Secret metadata.
- **Azure**:
  - Graph app-role GUIDs are not mapped to names, so `directory_app_role_assignment` needs `appRoleValue`.
  - When the management-group hierarchy is missing, MG-scoped grants are conditional.
  - Restricted administrative units are treated as conditional.
  - First-party service principals are only recognised when `directory_service_principal` items carry `appOwnerOrganizationId` (the collector's `$select` does not request it yet).
- **K8s**:
  - cloud-identity joins (IRSA trust, GKE WI, AKS FIC) need `related_snapshots`. Without them those edges are unknown or conditional. EKS access-entry techniques target the AWS-side EKS cluster-admin entity (`eks_cluster` with accessConfig.authenticationMode);
  - EKS (`aws-auth`) and OpenShift techniques carry `k8s_eks_cluster` / `k8s_openshift_cluster` preconditions: on a cluster proven to be another flavour they are not applicable, and without `api_discovery` / node / ConfigMap facts they are UNKNOWN;
  - a namespaced Role on `serviceaccounts/token` satisfies TokenRequest for the SAs of its namespace;
  - the legacy-token technique targets only SAs named by a `kubernetes.io/service-account-token` Secret (`secret_metadata`); without Secret metadata it is UNKNOWN;
  - a ServiceAccount named only by a binding subject (not in the SA inventory) is a target only of `k8s-rbac-dangling-serviceaccount-reference` (create it) and of impersonation; pods, TokenRequests and token Secrets need an existing SA.

## Azure terminal disclosure effects (catalog v7)

Seven previously held HackTricks techniques have an additive, metadata-only
reviewed-evidence adapter. Their target is `azure_verified_authority` with outcome
`bounded_authority` and effect `terminal_configuration_disclosure`: permission to
potentially disclose the configured credential on one exact resource. A target is
terminal. It grants no Entra identity, third-party administration, Service Fabric
administration, or permission to start another escalation path. Historical IDs
that mention administration retain their source spelling; the admitted effect is
only the documented terminal disclosure.

**The standard Azure collector does not collect these reviewed proofs.** Ordinary
resource inventory, a boolean challenge fact, or an action grant alone leaves the
technique UNKNOWN. This is reviewed-input support, not native collector coverage.
No third-party service is contacted and no credential value is needed. The seven
metadata adapters still require an external reviewer/importer to establish the
configured-credential and customer-reference joins. Do not count these techniques
as live cloud tests or as automated discovery of configured credentials.

| Technique ID | Exact source permission and resource |
| --- | --- |
| `azure-app-services-read-configured-third-party-credentials` | `Microsoft.Web/sourcecontrols/read` on provider-global `/providers/Microsoft.Web/sourcecontrols/{name}`. Authorization scope is `/`; a subscription role does not cover it. |
| `azure-audit-cluster-client-certificate-theft-data-plane-admin` | Data action `Microsoft.KeyVault/vaults/secrets/getSecret/action` on the exact backing vault secret, with the complete cluster/certificate/secret metadata join below. |
| `azure-service-linker-read-connection-configuration-to-exfiltrate-the-backing-secret` | `Microsoft.ServiceLinker/linkers/read` and either `listConfigurations/action` or `generateConfigurations/action` on the same linker. |
| `azure-spring-apps-config-server-bindings-secret-exposure` | Control action `Microsoft.AppPlatform/Spring/apps/read` on an app, control action `Microsoft.AppPlatform/Spring/apps/bindings/read` on a binding, or data action `Microsoft.AppPlatform/Spring/configService/read` on configService. Resource types cannot substitute for one another. |
| `azure-spring-apps-microsoftappplatformspringapmslistsecretkeysaction` | Control action `Microsoft.AppPlatform/Spring/apms/listSecretKeys/action` on the exact APM resource. |
| `azure-sre-agent-microsoftappagentsdataconnectorslistsecretsaction` | Control action `Microsoft.App/agents/dataconnectors/listSecrets/action` on the exact data connector. |
| `azure-sre-agent-microsoftappagentslistsecretsaction` | Control action `Microsoft.App/agents/listSecrets/action` on the exact agent. |

The normative per-technique preconditions and action alternatives are in
`peaso/privesc/azure_disclosure_effects.json`. The evaluator requires effective
source RBAC independently of the reviewed proof, preserving control/data-plane
separation and deny-assignment handling. Unknown effective permission is
insufficient. Conditional grants remain conditional.

An import supplies two complete, nonduplicated collection envelopes:

- `azure_privesc_challenge_evidence`, scoped to the exact target ARM resource ID;
  provider-global source controls use `/` instead.
- `azure_disclosure_source_metadata`, at the same scope, containing exactly one
  matching `TechniqueId`/`ResourceId` row. This row must retain `ResourceType`,
  `SecretConfigured: true`, an opaque `CredentialReferenceId`, the owning
  `CustomerTenantId`, and a nonempty `EvidenceRef`. The tenant must equal the
  snapshot's `metadata.tenant_id`. Its `_provenance` must contain
  `source: reviewed_metadata_only`, `read_only: true`, `values_omitted: true`, and
  `observed_at` equal to the challenge fact's `EvidenceObservedAt`.

The challenge fact must bind the existing source principal through `SourceId`,
`TargetKind: azure_verified_authority`, exact `TargetId` and `TargetScope`,
`EffectType: terminal_configuration_disclosure`, `Status: verified`,
`VerifiedPreconditions: true`, and every normative `VerifiedConditionIds` value.
It repeats the metadata row's `CredentialReferenceId`, `CustomerTenantId`, and
`EvidenceRef`. `ActionResources` maps each required action of a complete
alternative to a one-element list containing that exact authorization scope.
`EvidenceObservedAt` must be timezone-aware and no more than 15 minutes before the
snapshot's `created_at`; future observations are rejected. Missing, stale,
contradictory, duplicate, denied, or partial inputs do not produce a conditional
disclosure edge. Keys that contain credential values, including nested
`password`, `token`, `secret_value`, `private_key`, and `access_key`, are rejected.
References are opaque review identifiers, never secret values.

The exact resource must also exist with the correct ARM type in a complete
`resource_graph` collection for its subscription, and that subscription must
appear once in complete subscription inventory. A provided subscription
`tenantId` must match the snapshot tenant. Provider-global source controls use a
reviewed `SourceControls_Get` projection instead: `_provenance.source_operation`
must be `SourceControls_Get`, `ProviderGlobal` must be true, and `NativeResource`
must retain the exact native `id`, `type`, and `name` from that endpoint. A
subscription-scoped record cannot stand in for this global object.

Service Fabric additionally requires current Resource Graph cluster and vault
identities. `CertificateLink` names `ClusterId`, `VaultId`, `SecretVersionId`,
`CertificateVersionId`, and the cluster's exact SHA-1 `CertificateThumbprint`.
The vault's native `properties.vaultUri` must match both versioned HTTPS IDs; the
cluster's native `properties.certificate.thumbprint` must match the certificate.
A complete `azure_disclosure_certificate_metadata` collection scoped to that
vault must retain the exact native certificate `id`, `sid` secret-version link,
`x5t` thumbprint, `parent_id`, and `policy.key_props.exportable: true`. Its
`_provenance` requires `source_operation: Certificates_Get`, the exact versioned
certificate `request_uri`, `read_only: true`, `values_omitted: true`, and the same
observation time. The ordinary certificate collector omits `sid` and this policy,
so it cannot satisfy that join. Public certificate metadata is sufficient; no
secret-get request or private key is used by the analyzer. These facts establish
only the backing-secret disclosure effect, not acceptance of the certificate by
a cluster or any usable administrative session.

The historical v7 catalog adds seven entries while preserving all previous 253 YAML files
and their 1,227 entries byte for byte. Previous catalog bindings continue to
resolve only their original entries; a v6 report cannot acquire new disclosure
techniques when opened with the newer runtime. The previous source audit remains
archived and the additive v7 audit records 4,081 validated references.


Spring APM `listSecretKeys` returns names of sensitive properties, such as
`connection-string`, rather than their secret values. Its historical catalog
entry is retained for source provenance, but runtime evaluation suppresses the
credential-disclosure effect and reports `sensitive_property_names_only` as
unsupported evidence. This remains true for imported reviewed metadata that
asserts a configured secret. Listing property names never proves possession of
secret values or control of another principal. The response contract is the
[Microsoft APM List Secret Keys API](https://learn.microsoft.com/en-us/rest/api/azurespringapps/apms/list-secret-keys?view=rest-azurespringapps-2023-12-01).


A subsequent primary API review also disables the reviewed Spring binding,
Service Linker and two legacy SRE disclosure effects. Spring app secret values
are write-only and generated binding properties omit secrets; configuration
content is a distinct data plane. Linker can return a Key Vault reference,
nonsecret configuration or a nullable value. The exact legacy SRE agent and
`dataconnectors` operation families have not been verified against the public
`connectors` endpoint and cannot inherit its response semantics. These five
historical entries, including APM, remain in immutable source history but
produce explicit unsupported coverage, never resolved disclosure edges.

In the reviewed catalog, unchanged from the pinned d72a1bed production baseline, the five API secret-value interpretations are exclusion records, not active evaluator entries. The full active catalog contains 633 entries; catalog validity does not establish live validation for every entry.

The two retained reviewed paths are the exact provider-global SourceControls
OAuth endpoint and exportable Fabric certificate secret linkage. Neither has
an ordinary native proof adapter in this release. Imported metadata must retain
its credential, tenant, resource, version and freshness bindings. Fabric's
RBAC-based proof additionally requires the native vault property
`enableRbacAuthorization=true`; access-policy mode or an unknown mode cannot
establish Secrets_Get through role dataActions. Certificate metadata alone
does not imply client administrator authority. No secret values are persisted.

### Optional native Service Fabric disclosure metadata

Setting `options.native_disclosure_metadata: true` enables a metadata-only adapter for the Service Fabric certificate technique. It adds the ordinary subscription and Resource Graph prerequisites. This optional scan reads cluster certificate thumbprints, lists Key Vault certificates, resolves the current certificate and GETs its exact version, and lists metadata for backing secret versions. It never calls Secrets_Get or retrieves a secret/private-key value. Only explicitly selected credentials are used.

The adapter emits a positive, source-bound configuration witness only when ARM and Key Vault successfully authenticate the same exact object ID and tenant, the source principal exists in the model, the vault uses Azure RBAC, the current exportable certificate thumbprint matches the cluster, and its exact backing secret version is present and enabled. Certificate and secret version IDs, opaque credential reference, tenant and scan-generated credential/customer IDs are joined independently by the evaluator. Effective `getSecret` permission is still required by the signed predicate. Configuration presence does not establish a usable secret, application administration or downstream identity control.

The collector needs read-only `Microsoft.ServiceFabric/clusters/read`, `Microsoft.KeyVault/vaults/certificates/read` and `Microsoft.KeyVault/vaults/secrets/readMetadata/action`, in addition to the ordinary inventory reads. The last two are Key Vault data actions. It does not grant these permissions or issue write operations. Denied, incomplete, foreign, expired, disabled, non-exportable or inconsistent evidence remains unknown. Optional positive coverage is explicitly partial; missing proofs never certify global absence. No adapter for the other six V7 techniques is implied.

The five existing semantic guards remain active: APM property names, Spring redacted/write-only or cross-plane metadata, Linker references/non-secret configuration, and both unverified legacy SRE endpoint/action interpretations cannot create a disclosure edge. Their immutable historical catalog entries remain visible with explicit unsupported reasons. Opting into this Fabric adapter does not reactivate them.

References: [Get Certificate](https://learn.microsoft.com/en-us/rest/api/keyvault/certificates/get-certificate/get-certificate?view=rest-keyvault-certificates-2025-07-01), [Get Secret Versions](https://learn.microsoft.com/en-us/rest/api/keyvault/secrets/get-secret-versions/get-secret-versions?view=rest-keyvault-secrets-2025-07-01), [Key Vault data actions](https://learn.microsoft.com/en-us/azure/role-based-access-control/permissions/security), [APM sensitive-property names](https://learn.microsoft.com/en-us/rest/api/azurespringapps/apms/list-secret-keys?view=rest-azurespringapps-2023-12-01).

The native certificate projection records the exact version GET separately from the policy source. If Azure omits policy from the exact-version response, policy from the current GET is retained only when certificate version ID, backing secret version ID and public thumbprint all match the exact response. Provenance identifies the current policy request explicitly. Contradictory policies and disabled, expired or not-yet-valid exact certificate metadata cannot establish a witness; the evaluator independently rechecks these joins.


Current V19 catalog status: 1,234 active entries (AWS 537, Azure 325, GCP 282,
Kubernetes 90). Seven active IDs have explicit runtime semantic holds and five
Azure disclosure interpretations remain suppressed because the exact API
semantics do not prove credential-value disclosure. These are separate states,
not a global pending count. Source coverage, passing fixtures and historical
live receipts establish different facts; no exhaustive live-test completion or
missing-implementation count follows from catalog membership. The historical
held-eleven figure and 1,227-entry catalogs describe earlier revisions.
