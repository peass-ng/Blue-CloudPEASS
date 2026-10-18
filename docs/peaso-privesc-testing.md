# Privilege-escalation validation

The evaluator is read-only: it analyzes a snapshot and never executes an escalation or reads credential values. A passing fixture proves the documented evaluator behavior; it does not certify that an exploit was executed successfully in a live account.

## Run the complete checks

From the repository root, with the test and cloud dependencies installed:

```sh
python scripts/peaso_validate_privesc_catalog.py --json
python -m pytest -q -rs tests/test_peaso_privesc*.py tests/test_privesc_sync.py
```

For source-page and heading checks, set `HACKTRICKS_CLOUD_ROOT` to checkouts of the cited book revisions. It accepts several paths separated by the operating system's path separator (`:` on Linux/macOS). Cited revisions include `0b363311`, `171e422299`, `4913b6d88c`, `a66f094ede`, `8d6a341c8a`, `6fb9ac51fd` and `a53b46392c`. Missing checkouts must be reported separately from validated source references. Set `PEASO_PRIVESC_STRICT_SOURCES=1` to make an unavailable cited revision fail validation rather than leave its references unchecked:

```sh
PEASO_PRIVESC_STRICT_SOURCES=1 python -m pytest -q tests/test_peaso_privesc_catalog_sources.py
```

The 2026-10-14 source audit checked all 4,074 catalog/exclusion references against their available exact revisions, with zero missing pages, broken anchors or unavailable cited revisions. Its catalog binding, source page hashes and per-reference results are retained in `docs/privesc-ledgers/source-validation-20261014.json.gz`.

| Test files | What they verify |
| --- | --- |
| `test_peaso_privesc_coverage_{aws,gcp,azure,k8s}.py` | Catalog IDs, provider ledgers and, when the matching source revision exists, source heading coverage. |
| `test_peaso_privesc_catalog_sources.py` | Source pages/anchors and identical behavior of Python and native safe YAML parsers. |
| `test_peaso_privesc_schema_ext*.py` | Requirement alternatives, selectors, target types, exact scopes and supported schema extensions. |
| `test_peaso_privesc_v4_all_id_proofs.py` | Per-technique positive proofs and wrong-source/target/permission counterexamples for the original additive principal paths. |
| `test_peaso_privesc_exact_principal_tranche.py`, `test_peaso_privesc_bulk_principals.py` | Fresh usable credentials, subject and authorization binding; restricted, revoked, expired or wrong-audience credentials cannot imply full principal authority. |
| `test_peaso_privesc_bounded.py` | Resource operations remain terminal effects and never become full principal control. |
| `test_peaso_privesc_scoped_credentials.py` | Existing Azure Storage SFTP users and an exact Argo CD Secret-mount path, including denied/partial inventories, scope mismatches, replaced Secrets, admission and credential lifetime. |
| `test_peaso_privesc_v4_batch.py` | Historical catalog bindings, tenant isolation and preservation of the earlier 1,004/1,052/1,126/1,224-entry catalogs. |
| `test_privesc_sync.py` | Three-way synchronization, conflicts, malformed inputs, symlinks and removal protection. |

The reviewed catalog (unchanged from the pinned d72a1bed production baseline) has 633 active entries: AWS 165, Azure 158, GCP 238 and Kubernetes 72, with 3,515 exclusion records. This is passive catalog coverage, not a count of live-validated mechanisms. The earlier 1,234-entry count belongs to the historical V19 source and must not be presented as current production coverage. The five unverified Azure API secret-value interpretations remain excluded.

## Existing Azure Storage SFTP identities

The two Storage local-user paths use the real `storage_account`, `storage_local_user` and `storage_container` inventories. The local user is a distinct `azure_storage_local_user` node; its container permissions do not grant Entra or ARM privileges.

Both paths require explicit `isSftpEnabled=true` and `isLocalUserEnabled=true`, complete unique user/account inventory, observed Blob container permission scopes, and the source action on the exact local-user ARM ID. Password regeneration additionally requires existing SSH password authentication. The write path models replacing the existing user's SSH credential. Networking and execution remain conditional. Missing, malformed, foreign or incomplete facts remain UNKNOWN; explicitly disabled SFTP is not applicable to these paths.

The model covers takeover of an existing user with its observed container rights. Creation of a new user, widening its container permissions and rights granted only by uncollected POSIX ACLs are outside these paths.

The collector uses the read-only [Local Users List API](https://learn.microsoft.com/en-us/rest/api/storagerp/local-users/list?view=rest-storagerp-2025-06-01). The distinction between local SFTP identity permissions and other identity permissions is documented in [Azure SFTP authorization](https://learn.microsoft.com/en-us/azure/storage/blobs/secure-file-transfer-protocol-support-authorize-access).

## Argo CD Secret mount

`k8s-workloads-pods-mount-argocd-cluster-credential` supports Pod, Deployment, DaemonSet, StatefulSet, ReplicaSet, ReplicationController, Job and CronJob creation. The source must have the corresponding create permission in the Secret namespace; a `resourceNames`-restricted create grant cannot authorize this path.

Secret metadata alone cannot establish credential validity or remote authorization. An externally reviewed `k8s_privesc_challenge_evidence` record must bind all of the following:

- Exact `TechniqueId`, `SourceId`, `TargetKind`, `TargetId` and source-cluster `TargetScope`.
- `SecretNamespace`, `SecretName`, `SecretUID` and `SecretResourceVersion` matching the current metadata inventory.
- `WorkloadNamespace`, `WorkloadResource`, `WorkloadApiGroup`, `WorkloadAdmitted=true` and `SecretMountVerified=true`.
- A distinct `RemoteClusterId`, an HTTPS `RemoteServer`, a verified `RemoteAcceptedAudience` matching `CredentialAudience`, and remote-cluster `CredentialScope`. A Kubernetes token audience can differ from the API server URL.
- A usable bearer token or client certificate subject, verified revocation state, and explicit accepted `EffectiveRights` with `RemoteAuthorizationVerified=true`.
- `Status=verified`, `VerifiedPreconditions=true`, a nonempty `EvidenceRef`, both condition IDs, and timezone-aware observation/expiry timestamps. Evidence must be at most 15 minutes old at snapshot capture and the credential must not have expired.

The exact inert record format is exercised in `tests/test_peaso_privesc_scoped_credentials.py`; its fixture contains no live credential. Missing, duplicated, stale, cross-namespace or mismatched records cannot produce a conditional principal edge. The result represents the stored remote credential and its verified scope, never an assumed remote cluster-admin identity. Routine scans do not fabricate reviewed evidence.

## Live testing and cleanup

The two opt-in runners below create their own fixtures. Each `--output` must be a new private directory. They retain a resource ledger and sanitized snapshots/reports, remove only session-owned resources in `finally`, and verify absence. The Kubernetes runner uses explicit private kubeconfigs for its two new local clusters. The Azure runner pins the selected subscription and tenant, records the authenticated actor, checks exact ownership tags before deleting its unique resource group, and records a 30-minute cleanup deadline. Neither runner is part of a routine CSPM scan.

```sh
# Requires Docker, kind, kubectl and an already available python:3.12-slim image.
python scripts/peaso_test_resources/k8s_argocd_live_acceptance.py \
  --kind /path/to/kind --output .cache/privesc-live/argocd-run-001

# Requires Azure CLI, project cloud dependencies and optional paramiko==4.0.0.
python scripts/peaso_test_resources/azure_sftp_live_acceptance.py \
  --subscription "$AZURE_SUBSCRIPTION_ID" --tenant "$AZURE_TENANT_ID" \
  --output .cache/privesc-live/azure-run-001
```

The 2026-10-14 Argo CD acceptance ran against two isolated local kind clusters. A restricted Pod was admitted for an actor that could create Pods but could not read Secrets. Its mounted credential read one authorized ConfigMap on the remote cluster (200), was denied listing remote Secrets (403), and verified the exact authenticated subject using SelfSubjectReview (201). The native metadata-only snapshot produced no route without the reviewed proof and one conditional route with the actual proof. Both clusters and their private Docker network were deleted, with absence verified. Source hashes and sanitized observations are retained in `docs/privesc-ledgers/scoped-live-validation-20261014.json`; this is evidence for this specific path, not all catalog entries.

The same receipt includes positive Azure SFTP acceptance using the published runner. A regenerated password and a replacement SSH key each read the owned marker and were denied writes under the existing user's `rl` container scope. The native IAM/storage snapshot and evaluator identified both techniques for the authenticated Azure actor; `include_admin_sources=True` exposed the routes for that lab administrator. The two techniques share one conditional edge to the scoped local SFTP user. The unique resource group and all its children were deleted, with absence confirmed. This does not exercise local-user creation or permission expansion as modeled principal paths.

Use a provider test session with an explicit resource ledger when a live fixture is necessary. Record the account/project/subscription/cluster, created resource IDs, expected findings and cleanup result. Read-only inventory checks create no resources and must be reported as EMPTY when no applicable resource exists; they do not replace a positive fixture. Delete only session-owned fixtures after each test and verify their absence. Retained user reports and unrelated resources must be preserved.


Current V19 catalog status: 1,234 active entries (AWS 537, Azure 325, GCP 282,
Kubernetes 90). Seven active IDs have explicit runtime semantic holds and five
Azure disclosure interpretations remain suppressed because the exact API
semantics do not prove credential-value disclosure. These are separate states,
not a global pending count. Source coverage, passing fixtures and historical
live receipts establish different facts; no exhaustive live-test completion or
missing-implementation count follows from catalog membership. The historical
held-eleven figure and 1,227-entry catalogs describe earlier revisions.

### Exact EC2 instance-profile association branches

The legacy `aws-ec2-passrole-associate-instance-profile` catalog entry and hold
set remain unchanged. A separate guarded evaluator handles only complete native
instance/association/IAM-role joins and a fresh, independently reviewed instance
control record. Without that record, routine inventory retains unresolved
coverage and cannot produce a principal edge. No profile attachment, session,
IMDS request or credential retrieval runs during evaluation.

A profile-less instance requires AssociateIamInstanceProfile; an existing stable
association requires ReplaceIamInstanceProfileAssociation or both Disassociate
and Associate. Actions are evaluated on the exact instance ARN, with PassRole on
the exact role and the actual old/new profile request context. A stopped instance
also requires StartInstances. Unknown/conditional authorization or trust cannot
establish this native witness. The role's embedded profile membership and IDs,
current association/profile IDs and enabled/applied IMDS metadata must agree.
Transitional/missing/foreign/duplicate-conflicting native facts remain unresolved.
Identical duplicate native responses may be coalesced, but contradictory instance
or association rows fail collection before generic first-row deduplication.

An imported, complete `aws_privesc_challenge_evidence` envelope at ACCOUNT/REGION
must contain exactly one matching record with TechniqueId, SourceId, TargetKind
`aws_role`, TargetId (role ARN), TargetScope, TargetProfileArn, TargetProfileId,
InstanceArn, Status `verified`, InstanceControlled=true,
ImdsRoleCredentialsReachable=true, VerifiedPreconditions=true and EvidenceRef.
Timezone-aware EvidenceObservedAt/EvidenceExpiresAt must bound snapshot creation;
maximum age and lifetime are 15 minutes. These are externally reviewed runtime
facts, never owner policy parameters or automatic collector observations.
The emitted edge remains conditional, retains the reviewed reference and branch,
and does not certify that an escalation was executed or credentials obtained.

Verification uses native botocore responses through collect_live then analyze,
including all three branches, denied and resource-mismatched permissions,
conflicting native duplicates, target profile recreation, disabled IMDS, stopped
instances without startup permission, partial native pagination and absent,
foreign, duplicated, stale or unreviewed control facts. No new AWS read grants,
write grants, fixture resources or live exploit execution are introduced.

Primary contracts: [AssociateIamInstanceProfile](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_AssociateIamInstanceProfile.html),
[ReplaceIamInstanceProfileAssociation](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_ReplaceIamInstanceProfileAssociation.html),
[DescribeIamInstanceProfileAssociations](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeIamInstanceProfileAssociations.html),
[EC2 authorization](https://docs.aws.amazon.com/service-authorization/latest/reference/list_ec2.html).

The Associate request in the detach/associate branch is evaluated after detachment:
`ec2:InstanceProfile` is absent and `ec2:NewInstanceProfile` is the destination.
This is documented by AWS's [Quick Setup SsmOnboardingInlinePolicy](https://docs.aws.amazon.com/systems-manager/latest/userguide/quick-setup-assume-role.html),
which combines Null(current profile)=true with ArnLike(new profile)=destination.
An Allow restricted to the old current profile or Null=false cannot authorize
that second request. Disassociate and Replace retain the observed old profile.
