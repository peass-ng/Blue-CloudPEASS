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
     - a `Condition` or a `${policy-variable}` makes the edge conditional;
     - permission boundaries are intersected;
     - SCPs are evaluated at every level of the organization path (account, OUs, root): every level must Allow and a Deny at any level wins. The path comes from `organization_parent {ChildId, ParentId}` items, `organization_account.ParentId`, or `scp_policy.InheritedPolicies`. Without the path, only the SCPs attached to the account are evaluated and edges are conditional (`inherited_scps_not_evaluated`, coverage `only directly attached SCPs evaluated`). When SCPs were not collected at all, edges are conditional (`scp_not_evaluated`);
     - resource-based policies, where collected: `lambda_function.Policy`, `bucket.Policy`, `kms_key.Policy`, `sns_topic` / `sqs_queue` attribute policies, `secret.Policy.ResourcePolicy` and `ecr_repository.Policy`. In the same account, either the identity or the resource policy may grant. Cross-account access needs both. For KMS, identity policies count only when the key policy grants or delegates to the account. `NotPrincipal` is inverted, and an explicit Deny on either side wins. Principals named directly by a resource policy are added to the source prefilter, so a grant that exists only in a resource policy is still found;
     - requirements that share a multi-valued placeholder (`{target.resource_arn}`, `{target.attached_resource_arn}`, `{target.host_resource}`, `{target.artifact_arn}`, `{target.consumer_input_arn}`) must all hold on the same resolved resource. The first evidence ref is `{"shared_resource": <arn>}`;
     - `{source.assumable_role_arn}` stands for every role the source can already assume. A role qualifies when its trust policy admits the source and either names the source ARN in the same account or the source's identity policy allows `sts:AssumeRole` on it;
     - pivots of type `aws_stackset_administration_role` are existing roles that trust `cloudformation.amazonaws.com`. Selector `assumable_by_pivot_role` keeps the roles that such a pivot can assume, in any account, and excludes the pivot itself;
     - the `ecr_tag_immutability` blocker is evaluated from `ecr_repository.imageTagMutability`. The edge is dropped when every repository the source can write is `IMMUTABLE` and the source cannot call `ecr:PutImageTagMutability`;
     - trust policies are indexed by service, ARN, account, federated principal and public.
   - **GCP**:
     - allow bindings inherited through org > folder > project > resource;
     - custom and predefined roles come from the `iam_role` items. A small builtin table covers basic roles and the key IAM roles. Any other uncollected role is listed in coverage;
     - a binding condition makes the edge conditional;
     - deny policies are evaluated. When they were not collected for a scope, edges are conditional;
     - selector `gcp_implicit_delegation_chain` follows `iam.serviceAccounts.implicitDelegation` transitively, up to 10 hops. It reaches the SAs that a delegate can call getAccessToken, signBlob or signJwt on. The delegates themselves are not targets, and their emails are recorded as `delegate:<email>` conditions;
     - GKE: `gke_cluster` items become `k8s_cluster_admin` entities. They also scope `k8s_service_account` targets that use `k8s_sa_has_token_secret` or `k8s_sa_in_cluster`, where `{target.scope}` is `projects/<p>/locations/<l>/clusters/<c>`. When a K8s snapshot of that cluster is passed in `related_snapshots`, the targets are its real KSAs, with the same node ids as the K8s map. For the token-secret selector these are the KSAs named by `kubernetes.io/service-account-token` Secret metadata. Without a related snapshot, each cluster gets one `gke-ksa:<variant>:<cluster>` aggregate node with conditional confidence (`k8s_snapshot_not_joined`). When the related snapshot has no secret metadata, that node is unknown (`k8s_secret_metadata_not_collected`);
     - source selector `gcp_workspace_admin_role` (`super_admin` or an admin roleId / roleName) reads `workspace_user {primaryEmail, isAdmin}`, `workspace_role {roleId, roleName, isSuperAdminRole}` and `workspace_role_assignment {roleId, assignedTo}`. When these facts are missing, the technique is not evaluated and a coverage entry is added. The scope rule `org` on `gcp_scope_owner` targets keeps only organization nodes.
   - **Azure**:
     - role assignments × role definitions, covering Actions/NotActions and DataActions;
     - scope inheritance root > MG > subscription > RG > resource;
     - transitive group membership;
     - an ABAC condition makes the edge conditional;
     - deny assignments are evaluated. When not collected, edges are conditional;
     - resource managed identities (system and user assigned);
     - Entra directory roles and their scopes;
     - `{source.controlled_user}` (alias `{target.user}`) is the user object the source modifies. For an `azure_user` source it is the source itself (`dir:<id>`). For any other source it is unresolved, so the edge is conditional (`controlled_user_not_identified`).
   - **Kubernetes**:
     - Role/ClusterRole rules with aggregation;
     - apiserver `ResourceMatches` semantics (`*`, `res/sub`, `*/sub`);
     - `resourceNames`;
     - RoleBinding namespaces. `namespace: "*"` requires a ClusterRoleBinding;
     - cluster-scoped resources;
     - cloud identities taken from SA annotations (IRSA, GKE WI, Azure WI);
     - kiam/kube2iam: the namespace annotation `iam.amazonaws.com/permitted` (a regex, full match) or `iam.amazonaws.com/allowed-roles` (JSON globs) is matched against role ARNs and names. The candidates are the roles of the related AWS snapshots plus the pod annotations `iam.amazonaws.com/role`. An invalid regex makes the edge conditional;
     - with `related_snapshots`, IRSA trust, GKE Workload Identity and Azure FIC selectors are verified against the cloud snapshots. Each `cloud_identity` node is also joined to the real IAM principal by a cross-snapshot edge with technique `cloud-identity-join`.
2. **Evaluator** (`evaluator.py`). For each technique:
   - expand `all_of` plus one `any_of` group;
   - classify each requirement as static, pivot or per-target;
   - filter the target inventory with the static selectors. The result is cached as a *candidate set*;
   - find candidate sources through an inverted index (requirement key → principals that may hold it), then run exact checks;
   - apply the source-dependent selectors and the target scope rule.

   A `Resource: "*"` requirement never materialises one result per target. It returns a symbolic "every candidate" result that the graph builder aggregates.
3. **Graph builder** (`graph.py`). Turns reaches into nodes, edges and one finding per (technique, source). It applies these rules:
   - **Edge dedup**: there is exactly one edge per (source, target). Each technique that reaches the pair is one entry in `technique_details`, with its own confidence, evidence, conditions and mitigation. Findings stay per technique and point to their edges through `evidence.edge_ids`. `stats.distinct_paths` counts the deduplicated edges and `stats.findings` counts per-technique findings.
   - **Aggregation**: targets are aggregated when there are many of them. Admin-equivalent edges are added.
   - **Pruning**: an entity target is dropped when a broader scope of the same kind is already reached.
   - **Suppression**: an edge is suppressed when its source already administers the target scope (counted in `stats.suppressed_admin_edges`). Pass `include_admin_sources=True` to keep these edges.

### Missing data is never a silent absence

| Situation | Effect |
|---|---|
| Collection `denied` / `partial` / `not_collected` for a required type | `coverage` entry; techniques reaching that inventory get an `unknown:<candidate set>:<scope>` aggregate target with `unknown` confidence |
| Guardrail not collected (SCP, GCP deny policy, Azure deny assignment) | Edge downgraded to `conditional`, condition `scp_not_evaluated` / `deny_policies_not_evaluated` / … |
| Selector whose facts are not in the snapshot | Candidates kept with `unknown` confidence; coverage `kind: "selector"` names the facts needed (`schema.FACTS_NEEDED`) |
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

Related snapshots are only read and never fetched. A GKE cluster is matched to a K8s snapshot by `provenance.cluster_id`, which can be the GKE full path, `//container.googleapis.com/...`, a `gke_<project>_<location>_<name>` context, or a unique cluster name. Joined principals appear as nodes with `attrs.related_snapshot: true` and `provider` set to their own cloud. The output adds `stats.cross_snapshot_edges` and `stats.related_snapshots`; every other key is unchanged.

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
| GCP | `{policy, role, binding, condition}` |
| Azure | `{assignment, role, scope, via}` |
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
- **GCP**:
  - Group membership (Cloud Identity) is not expanded.
  - Predefined roles that were not collected contribute nothing and are listed in coverage. `roles/editor` and other basic roles are approximated and their edges are conditional.
  - `{target.host_resource}` is modelled for compute instances only.
  - Workspace admin facts (`workspace_user`, `workspace_role`, `workspace_role_assignment`) and K8s Secret metadata are not collected yet. Until they are, the super-admin technique is reported in coverage only, and GKE token-secret targets are conditional aggregates.
- **Azure**:
  - Graph app-role GUIDs are not mapped to names, so `directory_app_role_assignment` needs `appRoleValue`.
  - When the management-group hierarchy is missing, MG-scoped grants are conditional.
  - Restricted administrative units are treated as conditional.
- **K8s**: cloud-identity joins (IRSA trust, GKE WI, AKS FIC) need `related_snapshots`. Without them those edges are unknown or conditional. The OpenShift SCC and EKS access-entry facts are not collected.
