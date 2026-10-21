# PEASO privilege-escalation technique catalog — schema v1

## AWS challenge evidence contract

The v3 AWS challenge entries use `target.selector.aws_challenge_fact: <technique-id>`.
The selector must equal the entry ID. `aws_verified_authority` is a terminal,
service or external authority target; it is never an IAM principal or account
administrator. An entry targeting `aws_role` or `aws_user` uses the same selector
but can name only an existing IAM identity. These entries require an exact
`aws_privesc_challenge_evidence` collection before they can resolve a target.

Each evidence item has `TechniqueId`, `SourceArn`, `TargetKind`, `TargetId`,
`TargetAccount`, `Status` (`verified`, `incomplete`, or `disproven`), and
`VerifiedPreconditions` (boolean). The collection scope begins with the target
account ID. For a verified item, the producer must prove the per-entry collector
facts, the source's authorization on the exact resource, the target join, and
all runtime or external prerequisites stated in the entry. `TargetId` is the
exact role/user ARN or service/external resource ARN. Items with a different
source, target, technique, or account cannot match. A missing collection or
incomplete evidence yields UNKNOWN/unresolved. A complete collection without a
matching item, or a `disproven` item, yields no path. A verified item yields at
most a conditional path and is shown as MANUAL; it never gives a definite
finding from configuration alone. The evidence producer must include provenance
and must not set `VerifiedPreconditions` merely because an API grant exists.

The EC2 changed-user-data route uses a source-dependent precondition on this
collection. Its record must name `TechniqueId=aws-ec2-modifyinstanceattribute-userdata`,
`SourceArn`, `TargetKind=aws_role`, `TargetId`, `TargetScope`, `TargetRoleId`,
`TargetProfileArn`, `TargetProfileId`, and `InstanceArn`. It also requires
`Status=verified`, `VerifiedPreconditions=true`, `UserDataRunsOnRestart=true`,
`RoleCredentialsReachable=true`, a nonempty `EvidenceRef`, and timestamps
`EvidenceObservedAt` and `EvidenceExpiresAt` no more than 15 minutes apart.
For a running instance, include `StopProtectionDisabled` as a boolean; when
false, the source must be authorized to disable stop protection. The producer
must verify guest restart behavior and credential availability for that exact
instance. A new user-data script, IAM grants, or an instance profile alone
cannot establish those facts. No script or credential value is stored.

For the AWS App Runner, Lambda, and CodeBuild direct IAM-user-key routes, a
verified item also needs `CredentialResourceArn`, `AccessAction`,
`CredentialSubjectArn`, `CredentialKind=aws_iam_user_access_key`,
`CredentialUsable`, `CredentialReadSucceeded`, and
`CredentialAuthenticatedAsSubject`. To establish an actual privilege gain,
record `NewEffectiveAction` and `NewEffectiveResource`, with
`SourcePreviouslyDenied=true` and `TargetAccessAfterAllowed=true` from the
same reviewed comparison. A `codebuild:BatchGetBuilds` item must also name
`CredentialObservedInBuildArn` under the authorized project. These fields
are evidence metadata; do not store the key or secret value.

The catalog's `requires` actions select one documented branch per technique.
The evidence item must validate every additional permission and condition for
that branch, including exact resource scope; a wildcard `requires.resource`
alone does not establish the path.

`aws_challenge_foothold` is a source-only principal kind for anonymous,
runtime, local-host, application and endpoint footholds. A node is synthesized
per account and foothold class, and an entry restricts the class with
`source_selector.source_id_glob`. It has no IAM policy or API permissions. The
evidence item uses that node ID as `SourceArn` and must prove control of the
specific runtime, file, application account, public identity pool or endpoint.
Its role target is accepted only when the same evidence identifies that exact
role and every authentication and scope-down precondition. The synthetic node
does not claim that a real attacker has that foothold before the proof exists.

Read-only, defensive attack-path analysis. Each entry says: *if a SOURCE principal
effectively holds these permissions (on these resources), it can obtain the
privileges of these TARGET principals.* The engine evaluates entries against an
immutable snapshot and draws principal → principal edges, with the granting
policy/binding as evidence and the mitigation that cuts the edge. Entries contain
**no commands, payloads, or execution steps** — only preconditions, the reachable
target set, and mitigation. Catalog files are designed to be maintained upstream
in hacktricks-cloud.

Location: `peaso/privesc/catalog/<provider>/<service>.yaml` (provider ∈ aws, gcp, azure, k8s).
Each file is a YAML list of techniques.

```yaml
- id: aws-ec2-passrole-runinstances          # globally unique, kebab-case, provider-prefixed
  provider: aws
  service: ec2
  title: Launch an EC2 instance with a passed instance profile
  source: src/pentesting-cloud/aws-security/aws-privilege-escalation/aws-ec2-privesc/README.md#iampassrole-ec2runinstances
  source_revision: 6bdd8e89e6               # hacktricks-cloud commit read
  summary: One sentence of what the source gains (no how-to steps).

  requires:                                  # permissions the SOURCE must effectively hold
    all_of:                                  # every item required
      - action: iam:PassRole
        resource: "{target.arn}"             # resource the permission must cover; placeholders below
      - action: ec2:RunInstances
        resource: "*"
    any_of: []                               # optional: list of alternative groups; ≥1 group must fully match
      # - [ {action: ec2:RunInstances}, ... ]
  # For K8s use {verb, resource, subresource?, api_group?, namespace: "{target.namespace}"|"*"}
  # For Azure use {action: Microsoft.X/y/write, data_action?: bool, scope: "{target.scope}"}
  # For Entra ID use {entra_permission: microsoft.directory/... } or {entra_role: <template id/name>}

  target:
    kind: aws_role                           # vocabulary below
    selector:                                # ALL conditions must hold for a principal to be reachable
      trust_allows_service: ec2.amazonaws.com
      has_instance_profile: true
    scope: same_account                      # same_account | same_project | inherited_scope | same_namespace | cluster | tenant | org | any
    aggregate_as: "All roles trusting ec2.amazonaws.com in {account}"   # label for collapsed entity node

  conditions:                                # documented caveats, shown on the edge as evidence.technique_conditions; not machine-checked (use preconditions) and they do not change confidence
    - id: passrole_condition_key
      description: iam:PassedToService / iam:AssociatedResourceArn conditions may restrict this
  blockers:                                  # facts that remove the edge if present
    - scp_or_boundary_deny
  confidence: derived                        # authored floor: derived | conditional; evaluator downgrades at runtime only from facts (pivots, unresolved targets, missing data, failed preconditions)
  severity: high                             # critical when target set can include admin-equivalent principals
  mitigation: Restrict iam:PassRole Resource to specific roles and add iam:PassedToService.
  references: []                             # optional extra URLs (official docs)
  notes: ""                                  # accuracy caveats; when the target set is limited and why
```

## Target kinds
aws: `aws_role`, `aws_user`, `aws_group`(membership), `aws_identity_center_permission_set`, `aws_account_admin`(entity)
gcp: `gcp_service_account`, `gcp_user`, `gcp_scope_owner`(entity: project/folder/org IAM control), `gcp_workspace_user`
azure: `azure_managed_identity`, `azure_service_principal`, `azure_user`, `azure_scope_owner`(entity: subscription/RG/MG RBAC control), `entra_role`(e.g. Global Administrator)
k8s: `k8s_service_account`, `k8s_user`, `k8s_group`, `k8s_node`(node credentials), `k8s_cluster_admin`(entity), `cloud_identity`(workload identity → IAM principal of the cloud)

## Selector vocabulary (extend only via the evaluator's registry; validator rejects unknown keys)
- `trust_allows_service: <svc principal>` · `trust_allows_principal_of_source: true` (role trust includes source/its account)
- `has_instance_profile: true` · `attached_to_service: lambda|ec2|ecs|glue|sagemaker|codebuild|...`
- `same_as_source: true` (self-escalation: e.g. iam:CreatePolicyVersion on own policy → source becomes admin)
- `resource_permission_covers_target: <action>` (target must be within the Resource/scope of that permission)
- `gcp_actas_granted_on_target: true` · `gcp_sa_in_scope_of_permission: true`
- `azure_identity_assignable_in_scope: true` · `azure_aci_assignable_uami: true` · `entra_role_assignable: <role>`
- `k8s_sa_in_namespace: "{source.namespace}"|"*"` · `k8s_node_hosting_pods_with_sa: true`
- `any_principal_in_scope: true` (e.g. GCP/Azure/K8s setIamPolicy-like control → `*_scope_owner` entity)

## Placeholders
`{target.arn}` `{target.email}` `{target.id}` `{target.scope}` `{target.namespace}` `{source.account}` `{account}` `{project}` `{scope}`

## Accuracy rules (reviewer enforces)
1. The target set must be exactly what the technique reaches — never "all principals" when it is limited (AWS EC2/Lambda/etc. only reach roles trusting that service; GCP compute+actAs reaches SAs where actAs is held; K8s pod-create reaches SAs in that namespace).
2. Effective permission semantics are the evaluator's job (deny, SCP, boundary, conditions, inheritance); entries list required permissions and resources, not evaluation logic.
3. One entry per distinct permission combination. Alternative permission sets reaching the same target → `any_of` groups or separate ids.
4. Techniques that only read data, disrupt, or persist without gaining another principal's privileges are OUT of scope (they belong to Least Privilege / Exposure).
5. If HackTricks is ambiguous or outdated, verify with official provider docs and record in `notes`; drop with a line in `peaso/privesc/catalog/<provider>/_excluded.yaml` (`{source, reason}`) instead of guessing.

## Extensions (schema v1.1, backward compatible)

Every v1 entry keeps its exact meaning. The extensions below are opt-in; the validator rejects them where the
evaluator would not honour them (never silently ignored). The standalone JSON Schema
`peaso/privesc/privesc-technique.schema.json` (draft 2020-12, generated from the registries in `schema.py` with
`python -m peaso.privesc.schema --write-json-schema`) describes the whole format for contributors;
`validate_entry` remains the authority for cross-field rules (placeholder registry, entity-kind placeholders,
outcome/kind consistency, bind rules, expansion size). `tests/test_peaso_privesc_schema_ext_jsonschema.py` checks
that every catalog file passes both.

### 1. Nested boolean requirements (all providers)
Any item of `all_of`, or of an `any_of` group, may itself be a group node `{all_of: [...]}` or `{any_of: [...]}`
(exactly one key, optional `notes`, depth <= 4). Inside a nested `any_of` each alternative is a requirement, a group
node, or a list (a conjunction). The evaluator expands `requires` to disjunctive normal form (cartesian product,
at most 64 alternatives; more is a validation error) and evaluates each alternative exactly like a v1
`all_of + any_of[i]` alternative.

```yaml
requires:
  all_of:
    - action: iam:PassRole
      resource: "{target.arn}"
    - any_of:                                   # (CreateFunction) AND (Invoke OR (UrlConfig AND InvokeUrl))
        - action: lambda:InvokeFunction
        - - action: lambda:CreateFunctionUrlConfig
          - action: lambda:InvokeFunctionUrl
    - action: lambda:CreateFunction
```
Use `schema.expand_requires(requires)` / `schema.flatten_requirements(requires)` instead of reading
`all_of`/`any_of` directly.

### 2. `request_context` on AWS requirements (machine-checked)
Condition-key values the technique's own API request carries. They feed the three-valued condition evaluator for
every Allow/Deny statement on the path (identity policies, permissions boundary, SCPs, RCPs, resource policies),
so a condition that would otherwise be "undecidable -> conditional" becomes proven or refuted.

```yaml
- action: iam:AttachUserPolicy
  resource: "{source.arn}"
  request_context:
    iam:PolicyARN: {admin_managed_policy: true}  # AdministratorAccess or a proven customer-managed admin policy
- action: iam:CreateRole
  request_context:
    iam:PermissionsBoundary: {absent: true}     # the attacker does not attach a boundary
    aws:TagKeys: {values: [team, env]}          # multi-valued key carrying all listed values
    aws:RequestTag/team: {chosen: true}         # the requester controls the value
- action: lambda:AddPermission
  request_context:
    lambda:Principal: {source_principal: true}   # grant the current IAM user or role
```
A string is one value; a list is a choice of one value (best verdict over the choices, at most 16 combinations);
`{values: [...]}` a multi-valued key; `{absent: true}` / `{chosen: true}` a provably missing / requester-chosen key.
`{admin_managed_policy: true}` is valid only for `iam:PolicyARN`. It tries AdministratorAccess and same-account
customer-managed policies whose collected default version grants `Action: "*"` on `Resource: "*"` without conditions
or explicit denies. A restriction to another policy does not satisfy this administrator path.
`{source_principal: true}` is valid only for `lambda:Principal` and checks a grant to the current IAM user or role.
For an existing IAM user, group, or role, the evaluator also checks its managed-policy attachment count against
the quota recorded in `iam_account_summary` when available. If the quota is full, a permitted detach step makes the
path conditional; without it the attachment path is excluded. Reattaching a policy already on the principal does
not add permissions. Without a recorded quota, a principal with ten or more attached policies stays unresolved.
Values are literals (no placeholders). Edges note the choice used (`request_context_<key>=<value>` condition).
Without `request_context` the v1 context is used (e.g. `iam:PassedToService` inferred from the target selector).
Only AWS evaluates it; GCP IAM Conditions and Azure ABAC conditions remain evaluated as before.

### 3. `bind`: requirements that must hold on ONE common resource (all providers)
Requirements with the same `bind: <snake_case>` name in an alternative must all be granted on one resource the
source picks (typically one it creates), not each on any resource. Bound requirements cannot depend on the target or
a pivot (`{source.*}`, `{account}` and literal patterns are fine).
```yaml
- action: lambda:CreateFunction
  resource: "arn:aws:lambda:*:{source.account}:function:*"
  bind: function
- action: lambda:InvokeFunction
  resource: "arn:aws:lambda:*:{source.account}:function:*"
  bind: function
```
AWS builds candidate ARNs from the requirement patterns and the granting statements' Resource patterns and keeps the
grant only when one candidate is proven for every bound requirement (evidence `{bound_resource: <arn>}`; explicit
denies on that ARN apply). When no common resource is proven (or for GCP/Azure/K8s, which keep scope-level
semantics) the edge stays but is downgraded to `conditional` with `bound_resource_not_verified`: `bind` never
raises confidence and never removes an edge that v1 would draw unless a deny provably applies.

### 4. Generic id / name selectors (all providers, evaluator-implemented)
- `target_id_glob: <glob|[globs]>` - target node id (ARN, `serviceAccount:` email, Azure object id,
  `k8s:<cluster>:sa:<ns>:<name>`) matches one of the case-insensitive globs.
- `target_name_glob: <glob|[globs]>` - target display name matches.
- `exclude_target_id_glob: <glob|[globs]>` - drop matching targets.
- `source_selector.source_id_glob: <glob|[globs]>` - the source id matches.
Globs are literal (no placeholders); they are always evaluable (they read only the inventory) and are static
(cached per candidate set). Use them for well-known identities: `"*-compute@developer.gserviceaccount.com"`,
`"*@appspot.gserviceaccount.com"`, `"*@cloudbuild.gserviceaccount.com"`, `"arn:aws:iam::*:role/aws-reserved/*"`,
`"k8s:*:sa:kube-system:*"`.

### 5. `target.outcome` and `target.grants`: what the source obtains
`outcome` states whether the source *becomes* the target identity or *gains* a permission set:

| outcome | meaning | allowed target kinds |
|---|---|---|
| `identity` | becomes the target principal (mechanism unspecified; default for principal kinds) | principal, non-group |
| `credentials` | obtains credentials / tokens / a session of the target (access keys, passwords, SA tokens, AssumeRole) | principal, non-group |
| `workload_execution` | runs code in a workload carrying the target identity (passed role, attached SA / managed identity) | principal, non-group |
| `impersonation` | acts as the target through an impersonation / delegation API (K8s impersonate, GCP getAccessToken via delegation) | principal or group |
| `membership` | joins the target group and inherits its grants (default for group kinds) | group kinds |
| `permission_grant` | the source's own permissions grow (policy / role edit or assignment; default for entity + `same_as_source`) | entity or `same_as_source` |
| `role_activation` | activates / assigns a privileged role or permission set (PIM, Identity Center; default for `entra_role`, IC permission sets) | entity or `same_as_source` |
| `scope_control` | gains IAM control of a scope -> every principal in it (default for other entity kinds) | entity or `same_as_source` |
| `application_admin` | administers a managed service's application plane (default for `aws_service_plane_admin`) | entity kinds |
| `blocker_removal` | lifts guardrails named in `target.removes_blockers` (default for `k8s_admission_control`) | `k8s_admission_control` |

`grants: [..]` optionally names the permission set / role obtained (`AdministratorAccess`, `roles/owner`,
`Global Administrator`, `cluster-admin`); it is documentation shown on the edge. Edges' `technique_details` and
findings' `evidence.technique` carry `outcome` (plus `outcome_inferred: true` when not authored) and `grants`.

### Expressing "to whom" (summary)
- passed role / actAs: requirement `iam:PassRole` / `iam.serviceAccounts.actAs` on `{target.arn}` / `{target.email}`
  (or selectors `resource_permission_covers_target`, `gcp_actas_granted_on_target`); AWS `iam:PassedToService` is
  derived from the target selector and can be overridden with `request_context`.
- identity attached to a resource: `attached_to_service`, `via_resource_type` + `{target.resource_arn}`,
  `{target.host_resource}` (Azure), `k8s_node_hosting_pods_with_sa`.
- any principal trusting service X: `trust_allows_service`, `trust_allows_federated`, `trust_allows_oidc_*`.
- a specific built-in admin role: `entra_role_assignable: <name|template id>`, entity kinds, `target_id_glob`.
- cross-provider identity: `cloud_identity` (K8s -> cloud) and `k8s_*` kinds from cloud providers (`EXTRA_KIND_PROVIDERS`).

### 6. Chain-gated sources: `source_selector.source_reaches_kind` (all providers)
`source_reaches_kind: <target kind>` keeps a technique only for sources that are of that kind or that reach a node of
that kind through other edges of the same run (graph closure, fixpoint). A source that only reaches it through a chain
is downgraded to the weakest confidence along the best chain, with condition `source_reaches_<kind>_via_chain`. Use it
for "needs a foothold on a node first" techniques:

```yaml
source_selector: {source_reaches_kind: k8s_node}
```

### 7. Kubernetes additions
- Requirements: `verb_prefix: <prefix>` (instead of `verb`; matches custom verbs such as `escalate`-like CRD verbs;
  no `*`), and `resource_match: any` (any resource of `api_group`, or of every group when omitted; needs `resource: '*'`
  or no `resource`, no `subresource` / `resource_name`).
- Target selectors (all evaluated from collected facts, never Secret data):
  `k8s_sa_used_by_pending_pod`, `k8s_node_hosting_pod_of_source` (kind `k8s_node`), `k8s_sa_namespace_absent`,
  `k8s_sa_named_in_scc_users` (OpenShift SCC `users[]`), `k8s_secret_holds_cloud_credential: true|aws|gcp|azure|any|[..]`
  (kind `cloud_identity`, one node per Secret, always conditional `secret_content_not_verified`),
  `k8s_secret_holds_remote_cluster_credential: true|'key=value'|[..]` (kind `k8s_remote_cluster`).
- Source selector `source_bound_to_aggregated_clusterrole: true|cluster` (bound to an aggregated ClusterRole; `cluster`
  = through a ClusterRoleBinding only).
- Guardrail removal: target kind `k8s_admission_control` (one entity per cluster) with mandatory
  `removes_blockers: [admission_policy | pod_security_admission | admission_webhook | kyverno_policy | gatekeeper_constraint]`
  and outcome `blocker_removal`:

```yaml
target:
  kind: k8s_admission_control
  selector: {any_principal_in_scope: true}
  scope: cluster
  removes_blockers: [admission_webhook]
```

### 8. AWS `aws_service_plane_admin`
Entity kind (one per account) for administering a managed service's own application plane (Amazon Connect,
Managed Grafana, QuickSight, Supply Chain, Amplify backend). `selector.service_plane` is mandatory
(`amplifybackend | connect | grafana | quicksight | scn`); placeholders `{target.scope}`, `{target.account}`,
`{target.resource_arn}`, `{target.arn}`. Collected application resources (`aws_facts_ext`: Grafana workspaces,
QuickSight users, Supply Chain instances, Amplify apps with Gen 1 backend environments) become one target each; accounts
whose resources were not collected keep one unresolved placeholder (`not_collected`).
- Amplify Admin placeholders (`amplifybackend` targets only, derived from the collected app ARN
  `arn:<p>:amplify:<r>:<a>:apps/<AppId>`): `{target.amplifybackend_backend_arn}` =
  `arn:<p>:amplifybackend:<r>:<a>:/backend/<AppId>/*` and `{target.amplifybackend_token_arn}` =
  `arn:<p>:amplifybackend:<r>:<a>:/backend/<AppId>/challenge/*`. `amplifybackend:CreateToken` / `GetToken` require
  both (AWS Service Authorization Reference, `servicereference.us-east-1.amazonaws.com/v1/amplifybackend`);
  `amplify:GetApp` stays on `{target.resource_arn}` (the app ARN). An unparseable or uncollected app keeps the
  placeholder unresolved.

### 9. GCP additions
- `gcp_external_principal_evidence: true` with `gcp_external_plane` (kind `gcp_external_principal`, outcome
  `credentials`) requires a unique complete `gcp_external_principal_evidence` record. The record binds
  `TechniqueId`, `SourceId`, `AccessPermission`, and `ActionResource` to one exact target-plane resource and
  `TargetPrincipalId`. It must prove the cloud action succeeded, the credential is current and usable, the
  observed authenticated principal is that target, and the same named permission on the same target resource
  was denied to the source before the action but allowed after authentication. Missing, partial, duplicate,
  stale, ambiguous, or unverifiable records produce no target and no unknown-principal path. The proof's
  `PriorAccessCheckedAt < ActionObservedAt <= AfterAccessCheckedAt <= EvidenceObservedAt <= snapshot.created_at`
  must hold within a 15-minute window, and `CredentialExpiresAt` must be later than the snapshot.
  For the Agent Registry service redirect technique, the record also names the quota project, the exact
  Service and unchanged projected URN, the existing Binding and auth provider, the old and capture URLs,
  the victim identity and binding-aware invocation, and the credential received at the controlled endpoint.
  Invocation and capture must follow the Service update and precede the successful target-plane test.
- `gcp_agentregistry_skill_evidence: true` (kind `gcp_verified_authority`, outcome `bounded_authority`)
  needs one complete reviewed record for the exact customer-created Agent Registry Skill, quota project,
  consumer and floating Skill reference. The record binds the old, replacement, and consumer-resolved
  revisions, the consumer's runtime principal, and one downstream permission and resource that the source
  was denied before the replacement but the consumer used afterward. A create-only path needs revision
  creation and quota-project use; an explicit pointer update additionally needs Skill update permission.
  Pinned revisions, Agent Platform Skill Registry references, missing execution, partial evidence, and
  duplicate records create no authority target.
- `gcp_resource_self_grant: true` (kind `gcp_verified_authority`, outcome `permission_grant`) can use a unique,
  complete `gcp_resource_self_grant_evidence` record. `TargetResource` names the exact resource governed by the
  changed IAM or row-access policy; `GrantedResource` names the same resource or an exact descendant where the new
  permission was tested.
  The record binds the technique and source, the policy-write `AccessPermission`, exact `GrantedPermissions`,
  `GrantedPrincipalId = SourceId`, prior absence, accepted mutation, and `AfterPermissionAllowed` on
  `GrantedResource`. A parent policy write alone cannot produce a child permission path without this exact
  child-resource evidence. BigQuery row-policy self-grants also require the documented create, set-policy,
  table-read, and query-job permissions; the reviewed grant must name the acting principal on the exact table.
  Selected resource kinds also have prospective paths when the exact resource, complete native IAM policy,
  source's policy-write permission, absent prior access, organization policies and deny rules are available.
  These include Secret Manager secrets, Pub/Sub topics and subscriptions, Cloud KMS keys, standard Artifact
  Registry repositories and Analytics Hub data exchanges and listings. The Analytics Hub paths read Cloud Asset
  resource names and native IAM policies; the listing path also checks its parent exchange policy because
  exchange bindings can grant listing access. A missing policy or unresolved inherited access stays unknown.
  A reviewed exchange or listing mutation additionally binds the same resource and subscription permission in the
  before and after tests, the accepted self-binding, and a recent check that the binding remains present.
- `gcp_bounded_access_gain: true` with one `gcp_bounded_mechanism` (kind `gcp_verified_authority`, outcome
  `bounded_authority`) covers only a connection-backed BigLake table, a BigQuery remote function, an authorized
  routine, an authorized view, or one preexisting view in an authorized dataset. A unique complete
  `gcp_bounded_access_gain_evidence` record binds
  `TechniqueId`, `SourceId`, `TargetScope`, every YAML required action and its exact `ActionResources` resource,
  the mutation and intermediate object, the protected resource, and the same `GainedAction` denied before and
  allowed after the mutation through that intermediate object. Connection cases additionally bind the exact
  connection resource and service account; ACL cases bind an already existing routine or view and the
  authorization entry to the changed dataset.
  The authorized-dataset case also binds `AuthorizedDatasetResource`, `AuthorizationTargetTypes: [VIEWS]`,
  and proof that the queried view existed inside that dataset before the ACL mutation.
  The evaluator rechecks every source action on its bound resource and rejects partial, duplicate, stale, or
  mismatched evidence. The target represents indirect permission on the one protected resource, never direct
  IAM on it or possession of a connection service-account credential.
- `gcp_group_join_open_to_source: true` (kind `gcp_group`, dynamic): IAM-bound groups whose Groups Settings let the
  source join (`ANYONE_CAN_JOIN` same domain or with `allowExternalMembers`: derived; `ALL_IN_DOMAIN_CAN_JOIN` same email
  domain: conditional). Use with `requires: {}` and `source_kind: gcp_user`. Without collected Groups Settings the
  technique is a coverage note and yields no edges.
- `gcp_workspace_super_admin_with_registered_domain: true` (kind `gcp_workspace_user`) + placeholder
  `{target.domain_registration}`: Workspace super admins whose email domain is a collected Cloud Domains registration
  (`domains_registration {name, domainName}`); not collected -> unresolved placeholders.
- `gcp_image_family_consumer: true` (kind `gcp_service_account`) + placeholder `{target.image_family_project}`: SAs of
  instance templates booting from `projects/<p>/global/images/family/<f>`; requirement
  `{action: compute.images.create, resource: "{target.image_family_project}"}`.

### 10. AWS evaluator additions
- Placeholders: `{target.codebuild_sandbox_arn}` (`arn:aws:codebuild:<r>:<a>:sandbox/<project>:*` for each CodeBuild project
  running as the target role), `{target.redshift_dbuser_arn}` (`arn:aws:redshift:<r>:<a>:dbuser:<cluster>/*` for each
  cluster the role is attached to), `{target.rolesanywhere_profile_arn}` (enabled Roles Anywhere profiles listing the
  role, `rolesanywhere:ListProfiles`; unknown when profiles were not collected).
- `via_resource_type` hosts: `sagemaker_notebook_instance` and `redshift_serverless_workgroup` (through the namespace's
  IAM roles) are collected hosts; `imagebuilder_pipeline` (infrastructure-configuration instance profile),
  `sagemaker_user_profile` and `sagemaker_cluster` (HyperPod) are collected by `aws_facts_ext` and fall back to the trust
  heuristic (roles trusting the service principal, unknown) only where the inventory is partial.
- `via_resource_type: cognito_identity_pool`: `{target.attached_resource_arn}` is each
  `arn:aws:cognito-identity:<r>:<a>:identitypool/<IdentityPoolId>` whose `GetIdentityPoolRoles` `Roles`
  (authenticated / unauthenticated) names the target role. `RoleMappings` roles are not used (they apply to providers
  already configured; a provider added by `UpdateIdentityPool` gets the default authenticated role). Roles not
  collected for a pool keep it unknown (`cognito_identity_pool_roles_not_collected`).
- `consumer_input_writable_via: imagebuilder:<action>` + `{target.consumer_input_arn}`: for each pipeline of the role,
  the account-owned components its image recipe references with a version wildcard (`x`), as
  `arn:aws:imagebuilder:<r>:<a>:component/<name>/*` (a new version is a new ARN under the same name), so name-scoped
  CreateComponent grants match; derived membership. Recipes with only pinned or AWS-owned components exclude the role.
  A pipeline whose recipe was not read (`RecipeComponents` absent/denied, container recipes) falls back to the
  Region's `component/*`, conditional `imagebuilder_recipe_components_not_collected`; no pipeline inventory: unknown.
- `cognito_user_pool_covered_by`, `cognito_user_pool_group_role_covered_by`, `rolesanywhere_profile_includes_target`:
  no edge when the account's pools / trust anchors are collected and empty; resolved from the collected identity-pool
  roles, user-pool groups and Roles Anywhere profiles (`aws_facts_ext`), otherwise unknown.

### 11. Catalog implementation guard
`tests/test_peaso_privesc_schema_ext_catalog_impl.py` fails when the catalog uses a selector key, source-selector key,
target kind or placeholder that no model reads, unless `FACTS_NEEDED` documents the missing fact (the evaluator then
reports it in coverage). GCP `attached_to_service` values must be in `SERVICE_HOSTS` (collected hosts) or
`UNCOLLECTED_ATTACHMENTS` (reported as `attached_to_service <v> attachment inventory not collected`).

### 12. Azure additions
- `azure_aci_exec_running_identity: true` joins a native Container Instances group, its attached managed identity,
  a running container, and the source's exec permission on that same group. Missing runtime state stays unresolved.
- `azure_aci_existing_write_identity: true` joins the native existing group, its attached identity, running state,
  and the source's write permission on that group. Terminated groups do not qualify for in-place updates.
- `azure_aci_assignable_uami: true` checks the exact user-assigned identity's assignment right and an inventoried
  container group with write access, or a known resource group where a new group can be written. Missing identity
  or ACI inventory stays unresolved; successful deployment and token use remain conditional.
- Requirement kinds: `fabric_workspace_role: Admin|Member|Contributor|Viewer` (+ optional `fabric_workspace`, rank
  compared, groups included), `intune_permission: <resourceAction glob>` (always conditional
  `intune_scope_tags_not_evaluated`), `entra_catalog_role: <role>` + `catalog: '{target.catalog}'` (`appScopeId "/"` =
  tenant-wide), `entra_group_member: <group id|name>` (transitive). `graph_app_permission`, `entra_owner_of`,
  `entra_pim_eligible_role` and `entra_tenant_setting` facts are now part of `possible()` and cached per principal.
- Target selectors: `azure_users_assigned_to_pivot`, `azure_assignable_via_identity_holding: <action>`
  (intermediate identity, condition `via_intermediate_identity:<name>`), `azure_consumer_of_pivot:
  key_vault_reference|storage_content|app_configuration_reference|queue_trigger|service_bus_trigger|event_subscription`,
  `fabric_workspace_identity`, `intune_managed_device_user`, `entra_pim_group_eligible_for_source: true|member|owner`,
  `entra_resource_in_catalog`, `entra_access_package_auto_assignment_open_to_guest`,
  `azure_assignment_condition_uses_principal_attribute`, `attached_to_vm_joined_to_entra_domain_services`.
  `azure_host_linked_to_pivot` also handles `avd_session_host`, `automation_hybrid_worker`, `devtest_lab_compute_vm`.
- Blockers: `intune_multi_admin_approval_required`, `access_package_approval_by_other_principal`.
- Facts each selector needs are in `FACTS_NEEDED`; most are not collected yet and resolve to unknown/unresolved.

### 13. Model-evaluated blockers and K8s workload admission
`MODEL_BLOCKERS[provider]` lists blockers a provider model evaluates (`Model.blocker_verdict`). Each verdict is one of:

- `clear`: evaluated, does not apply.
- `None`: facts missing. The edge is kept with condition `blocker_<b>_not_evaluated` and a coverage note.
- `('possibly_blocked', evidence)`: an enforcing control may reject the technique. The edge is kept and downgraded to
  `conditional` with condition `blocker_<b>_possibly_enforced: <evidence>`. The finding lists it in
  `evidence.blocker_verdicts`.
- `('blocked', evidence)`: definitive. The reach is held for the lift pass. If it is not lifted, it is removed from the
  graph and reported in `stats.blocked` (technique, source, blocker ids + evidence, targets, capped at 500), with
  `stats.blocked_reaches` and a coverage note with status `blocked`. It is never dropped silently.

A verdict may be a `{target id: verdict}` map when the blocker depends on the target.

**Lift.** After evaluation, a held reach is restored when its source reaches an entity of a scope containing the
source's scope (`k8s_admission_control:<cluster>`) with a technique whose `target.removes_blockers` covers every
blocker of the reach. The entity can be reached directly or through other reaches (for example, impersonating an SA
that can relabel namespaces). The pass iterates to a fixpoint. The restored reach takes the weakest confidence of that
chain and gets condition `blocker_<b>_lifted_via_<technique id> (was: <evidence>)`. `pod_security_admission` and
`pivot_namespace_psa_enforce_baseline_or_restricted` are aliases for lifting.

**K8s blockers.** All six are model-evaluated. The workload namespace is `{pivot.namespace}` (the attacker picks the
most permissive pivot), `{target.namespace}` (per target), a literal namespace, or every namespace for `*` grants.
The admitted resources are Pods plus every requirement resource and subresource.

| blocker | `blocked` | `possibly_blocked` | `clear` | not evaluated |
|---|---|---|---|---|
| `pod_security_admission`, `pivot_namespace_psa_enforce_baseline_or_restricted` (authors: only for pods that baseline rejects: privileged, host namespaces, hostPath, added capabilities) | label `pod-security.kubernetes.io/enforce` = `baseline`/`restricted` on the namespace (API-server exemptions are not collected and are stated in the evidence) | - | label absent or `privileged` | namespace not inventoried |
| `admission_policy` | - | a Validating/MutatingAdmissionPolicy bound with `Deny` (or a mutating binding) whose `matchConstraints` / binding `matchResources` cover the workload on CREATE/UPDATE and whose namespaceSelector matches (unknown labels count as matching) | API absent (`admission_policy_api_absent`), no matching bound policy, Warn/Audit-only binding, binding without its policy | `admission_policy` not collected |
| `admission_webhook` | - | a ValidatingWebhookConfiguration webhook whose rules cover the workload and whose namespaceSelector matches (evidence includes `failurePolicy`) | no matching validating webhook (mutating webhooks are ignored: they usually inject) | `admission_configuration` not collected |
| `kyverno_policy` / `gatekeeper_constraint` | - | engine API groups served (`kyverno.io`, `policies.kyverno.io` / `*.gatekeeper.sh`); the policies themselves are not collected | engine groups absent | `api_discovery` not collected |

**Determinism.** The evaluator visits candidate sources in sorted id order (not set order), so the findings,
granting statements and graph do not depend on `PYTHONHASHSEED`. The test is
`tests/test_peaso_privesc_schema_ext_k8s_blockers.py::test_privesc_output_does_not_depend_on_the_hash_seed`.

## Schema v2: joined target predicates

Schema v2 adds three opt-in joins. Entries without these fields keep their v1/v1.1 evaluation. The Python validator enforces the cross-field rules; the generated JSON Schema lists the new vocabulary.

| Provider | Field | Required use | Result when facts are missing |
|---|---|---|---|
| AWS | `{source.assumable_role_attached_policy_arn}` and `via_assumable_role_attached_policy_covered_by: iam:CreatePolicyVersion` | `aws_account_admin`, same account, and a matching `iam:CreatePolicyVersion` requirement on the placeholder | Unresolved account; never a reachable admin path |
| GCP | `k8s_sa_used_by_running_pod: true` | `k8s_service_account`, `scope: cluster`; cannot combine with `k8s_sa_in_cluster` or `k8s_sa_has_token_secret` | Unresolved KSA target for an absent or ambiguous GKE/K8s join or missing pod inventory |
| K8s | `{source_rolebound_clusterrole}` | `resource_name` on `escalate` and `update`/`patch` of `clusterroles` in every alternative; `scope: same_namespace` and `k8s_sa_in_namespace: "{target.namespace}"` | No reachable SA when the matching binding or effective rules are absent |

The AWS join keeps each assumable role paired with its own attached customer-managed policies. It requires source permission to create a policy version and assume the role, role trust, version capacity (or permission to delete a nondefault version at capacity), and an admin-capable role after boundary and SCP checks. Unknown version capacity caps the result at `conditional`; a definitive guardrail block removes it. `iam:SetDefaultPolicyVersion` is outside this selector.

The GCP join selects only KSAs named by Running pods of a uniquely joined GKE cluster. The effective token mount must be available. A complete pod inventory with no such pod yields no target; missing inventory yields `UNKNOWN` coverage. The existing K8s selector keeps its prior semantics. The K8s join requires one RoleBinding in the target namespace and tests `escalate` plus `update` or `patch` against the same ClusterRole name; a ClusterRoleBinding alone cannot establish that namespace relationship.

## GCP v3 exact evidence paths

The 49 GCP v3 source sections use `target.selector.gcp_challenge_fact`, equal to the technique ID. The selector reads `gcp_privesc_challenge_evidence` and joins `TechniqueId`, `SourceId`, `TargetKind`, `TargetId`, and `TargetScope` to the exact candidate and acting source. The collection scope must equal `TargetScope` and be a project. Only one nonconflicting record with `Status: verified` and `VerifiedPreconditions: true` can produce a path. That path is always `conditional` (MANUAL); a complete empty or disproven record produces no path. Missing, partial, conflicting or incomplete evidence produces UNKNOWN/unresolved. The loader rejects a mismatched technique ID, a derived confidence, or an unbounded target kind. The exported JSON Schema and HackTricks Cloud validator use the same registries.

The collection is an attestation boundary. An importer must verify the technique-specific preconditions stated in the catalog, including exact resource joins, actor authority, target identity, application trust or credential presence, and any remaining conditions. `VerifiedPreconditions` must not be set from a broad IAM permission or an attached service account alone. Host, external identity, application and user-interaction starting points use an explicit `gcp_challenge_foothold:projects/{project}:{class}` source. These nodes have no IAM permissions by themselves. Workspace actors can be represented by an exact `user:{email}` in the evidence even without a GCP IAM binding. The technique-specific collection calls, permissions, fact fields and snapshot key are listed in `privesc-v3-collector-requests.md` in the challenge workspace.

## Azure challenge and adjacent-provider evidence

The Azure challenge entries use `azure_challenge_fact` or `k8s_challenge_fact`. Each selector value must equal its technique ID. The catalog loader rejects derived confidence and source-only footholds as targets. The evaluator reads the matching `<provider>_privesc_challenge_evidence` collection. A record has `TechniqueId`, `SourceId`, `TargetKind`, `TargetId`, `TargetScope`, `Status`, `VerifiedPreconditions`, and a nonempty `EvidenceRef`. `TargetScope` must equal the collection scope. Wildcards, a different source or target, a different technique, duplicate/conflicting records, and disproven facts cannot establish a path. A sole verified record in a complete collection produces only a **conditional** path. A partial or unverified source-specific record produces UNKNOWN/unresolved. When the collection is absent, the evaluator records a coverage gap without claiming that every principal can initiate the exploit. A complete empty collection produces no path.

The attestation must check the exact attacker action, permission, resource binding, target identity or bounded service authority, and the technique-specific conditions before `VerifiedPreconditions` can be true. For example, an Event Hubs SAS rule is a service authority, not an Entra identity; a tag mutation needs a named consumer and a later pull; a namespace kubeconfig needs a proved independent Kubernetes subject and effective RBAC; a public file name alone is not a credential. The exact API call, required permission, and fact shape for each challenged source are in `privesc-v3-collector-requests.md` in the challenge workspace. No collector stores secret or token bytes.

`azure_challenge_foothold` represents an anonymous HTTP or broker-token starting point with no Azure RBAC grants. The DigitalOcean and IBM rows remain precise exclusions because they need new provider models, collectors, and sync/export allowlist changes outside this task's exclusive edit paths. The Azure ML marquee source is an alias of the existing jobs-on-compute mechanism; its workspace placeholder resolves only from an inventoried ML compute resource, and partial resource inventory remains unresolved.
