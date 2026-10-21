# Exposure check overlap review

The review branch imports normally and registers 346 Exposure checks: 204 AWS, 66 GCP, 74 Azure, and two Kubernetes. Every ID is listed in the linked inventory by provider, resource kind, and target. Checks with shared pass/fail witnesses were compared against same-kind peers on both checks' witnesses. Matching witnesses were then inspected against their predicates, including scope, conditions, applicability, and missing facts. A matching pair of ordinary witnesses alone was not treated as a duplicate. The five checks in the table below are registered through signed installers; two later additions covering AWS selected workload command literals and GCP selected Batch script sources have unique resource kinds.

| Signed-installer check | Resource kind |
| --- | --- |
| `aws.review.s3.selected_source_secret_indicators` | `s3_selected_source_content` |
| `aws.review.codebuild.selected_inline_buildspec_secret_indicators` | `codebuild_selected_inline_buildspec` |
| `gcp.review.workbench.selected_referenced_source_secret_indicators_20261020` | `workbench_selected_referenced_source_20261020` |
| `gcp.review.dataflow.selected_package_referenced_source_secret_indicators` | `dataflow_selected_package_source` |
| `k8s.review.selected_metadata.secret_indicators` | `k8s_selected_metadata` |

Seven IDs were retired during this review and resolve to a surviving check: `aws.a.cloudwatch.cross_account_role_absent`, `aws.c2b.ecs.service_no_public_ip`, `aws.c2b.elasticache.cluster_public_subnet`, `aws.b.redshift.no_public_endpoint`, `aws.a.s3.bucket_account_public_blocks`, `azure.claude.aks_authorized_ip_ranges`, and `aws.cb.sns.policy_prohibit_public_access_perimeter`. Their upstream mappings now point to the survivors. Stored report IDs remain resolvable through aliases.

The closest remaining pairs ask different questions. AWS network checks differ by port set, IP family, instance state, profile attachment, or whether a real backend is joined. AWS policy checks differ by action, ACL permission, condition handling, or the treatment of an absent policy. GCP trust-list checks cover named principals while public-policy checks cover public members; Cloud SQL public-IP checks differ from the requirement to have a private network, and function ingress differs from invoker IAM. Azure NSG checks cover different ports and protocols; function access restrictions differ from the public network access flag. The AKS pair and the SNS policy pair with the same public-Allow predicate were retired.

A separate title-similarity pass found 94 pairs across different resource kinds. The repeated GCP IAM-policy titles apply to distinct resources such as keys, buckets, instances, topics and subscriptions. The AWS S3 account and bucket settings have separate scopes; RDS instance and cluster snapshots are separate assets. The remaining cross-kind lookalikes likewise cover distinct assets or source content, so one result cannot replace the other.

The [ID inventory](exposure-check-inventory.json) lists all 346 current IDs and the cross-fixture candidate peers. The [candidate decisions](exposure-candidate-decisions.json) give a distinguishing condition for each of the 26 remaining matching-witness pairs. These comparisons establish overlap in the reviewed predicates; they do not claim that public traffic reaches a resource.

The following 24 available checks lack a shared `pass` and `fail` pair in `peaso.checks.fixtures.CASES`. This does not mean they lack other tests. Their direct predicates were inspected for an exact same-resource duplicate:

| Check | Distinct recorded condition |
| --- | --- |
| `aws.s3.public_access_block` | Effective four-setting bucket-or-account prevention, separate from bucket-only settings, ACLs, and policy grants. |
| `aws.s3.no_public_acl` | Public group grants in the bucket ACL, separate from policy grants and preventive settings. |
| `gcp.iam.restrict_public_members` | Project IAM bindings for both public member forms, including conditional bindings. |
| `gcp.storage.public_access_prevention` | Preventive bucket setting and inherited effective organization policy, separate from actual grants. |
| `gcp.compute.no_external_ip` | Direct VM external IP declaration, separate from firewall or proxy paths. |
| `azure.storage.no_blob_public_access` | Storage-account permission for anonymous blobs, separate from container access. |
| `k8s.service.review_public_type` | Service publication settings, separate from a joined public path to a Pod. |
| `aws.cb.rds.instance_snapshot_shared_accounts_review` | Named-account restore sharing for instance snapshots, separate from sharing with everyone. |
| `aws.cb.rds.cluster_snapshot_shared_accounts_review` | Named-account restore sharing for cluster snapshots, separate from instance snapshots and everyone. |
| `aws.cb.ram.shared_with_accounts_review` | RAM shares to account principals. |
| `aws.cb.ram.shared_with_organizations_review` | RAM shares to organization principals. |
| `aws.cb.ram.shared_with_organization_units_review` | RAM shares to organization-unit principals. |
| `gcp.claude.backend_bucket.bucket_exists` | Whether a load-balancer backend names an existing bucket, separate from bucket publicity. |
| `aws.c2b.directoryservice.shared_accounts_review` | Named accounts receiving a Directory Service share. |
| `aws.claude2_a.cloudwatch.cross_account_sharing_role_absent` | Presence and trust of the CloudWatch sharing role; the weaker named-role check was retired. |
| `aws.claude2_a.config.aggregation_authorization_trusted` | AWS Config authorization of a named aggregator account. |
| `aws.claude2_a.dlm.snapshot_sharing_trusted_accounts` | DLM snapshot target accounts on applicable active policies. |
| `aws_cis_aws_resource_policy_unrestricted_principal` | Unrestricted wildcard principals across collected resource-policy families, with separate policy provenance. |
| `aws_cis_lambda_resource_policy_trusted_accounts` | Lambda invocation permission for accounts outside configured trusted IDs, separate from anonymous access. |
| `aws_cis_lightsail_bucket_private` | Lightsail bucket access rules, separate from S3 bucket settings. |
| `aws_g6_sns_no_named_cross_account_principals` | SNS access for named external accounts, separate from wildcard public access. |
| `aws.review.workload.selected_command_literal_secret_indicators` | Selected workload command literals, a resource kind with no other Exposure check. |
| `gcp_pci_bucket_56c6b1b7f813` | Public object-write rights through IAM or active ACLs. |
| `gcp_pci_bucket_7dc6cb8c2e05` | Any public bucket access except an approved exclusion, including public reads. |

The named-account trust checks can pass when no such share is recorded and can make a definite comparison when an approved trust list is supplied. A share with no approved list remains a conditional manual judgment; it is not an automatic claim that the named account is untrusted.

The public-workload and privileged-identity join passed directed tests across AWS, GCP, Azure, and Kubernetes, including specific high-impact actions classified by the same offline permission catalog used by Least Privilege. The grouped UI card explains the shared risk and retains each workload's own observed evidence and identity. The GCP backend-health read uses the existing network collector extension point and a separate `backend_service_health` collection. The review branch imports normally, resolves all seven retired IDs to active survivors, passes catalog materialization, and passes 277 focused Exposure, collector, alias, principal, and API catalog tests without bypasses. Another 44 principal tests pass after indexing attached IAM policies once per account. The Kubernetes Ingress join requires the named Service port to exist.

[PR #104](https://github.com/peass-ng/PEASSo-CSPM/pull/104) contains the implementation. It is ready for review while full CI runs. All four failures in the historical source-bridge module also reproduce on an isolated archive of current `main`. The branch additionally changes package bytes that this module pins, so its reviewed-source allowlist must be reconciled when the existing baseline is repaired. The integrity assertions were not disabled. Production has not been changed.
