# PEASO privilege-escalation technique catalog — schema v1

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

  conditions:                                # facts that make the edge conditional (confidence: conditional)
    - id: passrole_condition_key
      description: iam:PassedToService / iam:AssociatedResourceArn conditions may restrict this
  blockers:                                  # facts that remove the edge if present
    - scp_or_boundary_deny
  confidence: derived                        # derived (all facts collected) — evaluator downgrades to conditional/unknown
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
- `azure_identity_assignable_in_scope: true` · `entra_role_assignable: <role>`
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
