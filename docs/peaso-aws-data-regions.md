# AWS data-resource Region collection

The signed `aws_account_non_eu_resource_region_detected` predicate remains unchanged. The native collector supplies its three required inventories from account-bound read-only AWS metadata. It inventories storage location signals, not object contents, customer-data classification, physical residency, replicas owned by another account, or every AWS service.

The versioned catalog is `2026-10-15.storage-locations.v1`, reviewed 2026-10-15. It covers the predicate's seven groups:

| Group | Native metadata boundaries |
| --- | --- |
| s3 | Owned general-purpose buckets and verified GetBucketLocation; regional directory buckets; S3 Tables customer and AWS table buckets; S3 vector buckets; every native owned Outpost and its S3 Outposts buckets |
| rds | DB instances, DB clusters, instance snapshots, cluster snapshots, retained instance automated backups, retained cluster automated backups |
| ec2_volume | Owned EBS volumes and snapshots |
| dynamodb | Owned tables, including each independently listed replica, and backups |
| efs | Owned file systems |
| redshift | Provisioned clusters and owned snapshots; Serverless namespaces, owned snapshots and recovery points |
| backup | Owned backup vaults and all their recovery points |

Children stored within a native storage container inherit its regional location. The catalog does not treat an endpoint, role, alias, access point or API workgroup as a separate data store. S3 Outposts reports the AWS control-plane Region; it does not assert that the Outpost's physical customer location is in that Region. AWS-managed internal storage outside the account is not enumerated. New storage services/types require a catalog revision and review; there is no claim of completeness beyond these seven declared groups and their listed native resource types.

Each scan binds STS account/partition, discovers native enabled Regions with DescribeRegions(AllRegions=True), and requires the selected Region set to equal that complete enabled set. A single-Region scan of a multi-Region-enabled account remains incomplete. Every catalog endpoint must terminate successfully in every enabled Region, even for empty inventories. Unsupported SDKs, endpoints, unavailable services, denied permissions, throttling, malformed or foreign identities, duplicate IDs, truncation, token repetition, item/call/page budgets or cancellation preserve incomplete evidence and cannot produce a complete account verdict. Missing services are never inferred empty from endpoint failure. Shared snapshots are excluded using native account filters. All applicable list APIs use the existing SDK paginator-backed Requests.pages and request cache/budgets; no separate API transport is introduced.

The three inventories share one per-account native bundle, so concurrent requests do not duplicate its reads. Existing native requests with identical session/service/Region/operation/arguments are reused by the existing cache. Complete coverage rows are emitted only after all seven groups succeeded in all enabled Regions. Subsequent snapshot item-budget truncation still marks the affected envelope incomplete.

## Explicit owner criteria

`options.compliance_parameters.aws_data_regions` is one object containing exactly:

- `scope`: `<12-digit-account>/global`.
- Nonempty bounded `authorized_by` and `document_id` declarations.
- Current, timezone-aware `observed_at` and `expires_at`.
- `approved_region_names`: a nonempty unique list of approved `eu-*` Region names.

No EU policy is invented. No observations, Complete flags, resources or endpoints are accepted as owner criteria. The collector validates this input before network requests and supplies the signed predicate's `approved_region_names` from this validated policy at top-level snapshot metadata, because the generic bulk adapter owns `metadata.parameters`. It binds criteria to the same account. These are operator declarations, not independently authenticated corporate approval evidence. Other account scans cannot reuse that policy.

## Read-only permissions

Existing IAM actions continue to apply. This producer additionally needs the catalog's metadata list/describe actions; the deployment owner must review the customer role before asserting hosted readiness. No policy or role is modified by this implementation.

`sts:GetCallerIdentity`, `ec2:DescribeRegions`, `s3:ListAllMyBuckets`, `s3:GetBucketLocation`, `s3express:ListAllMyDirectoryBuckets`, `outposts:ListOutposts`, `s3-outposts:ListRegionalBuckets`, `s3tables:ListTableBuckets`, `s3vectors:ListVectorBuckets`, `rds:DescribeDBInstances`, `rds:DescribeDBClusters`, `rds:DescribeDBSnapshots`, `rds:DescribeDBClusterSnapshots`, `rds:DescribeDBInstanceAutomatedBackups`, `rds:DescribeDBClusterAutomatedBackups`, `ec2:DescribeVolumes`, `ec2:DescribeSnapshots`, `dynamodb:ListTables`, `dynamodb:DescribeTable`, `dynamodb:ListBackups`, `elasticfilesystem:DescribeFileSystems`, `redshift:DescribeClusters`, `redshift:DescribeClusterSnapshots`, `redshift-serverless:ListNamespaces`, `redshift-serverless:ListSnapshots`, `redshift-serverless:ListRecoveryPoints`, `backup:ListBackupVaults`, `backup:ListRecoveryPointsByBackupVault`.

## Primary API references

- [ListDirectoryBuckets](https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListDirectoryBuckets.html): owned-account regional list, continuation token and dedicated s3express permission; BucketRegion may be omitted, so the collector uses a validated native BucketArn.
- [ListRegionalBuckets](https://docs.aws.amazon.com/AmazonS3/latest/API/API_control_ListRegionalBuckets.html): OutpostId is required by S3 Outposts; collection enumerates owned Outposts first, then supplies the exact native ID.
- [ListTableBuckets](https://docs.aws.amazon.com/boto3/latest/reference/services/s3tables/client/list_table_buckets.html): continuationToken, ownerAccountId and customer/aws types.
- [ListVectorBuckets](https://docs.aws.amazon.com/AmazonS3/latest/API/API_S3VectorBuckets_ListVectorBuckets.html): regional owned buckets and nextToken.
- [DescribeDBClusterAutomatedBackups](https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DescribeDBClusterAutomatedBackups.html).
- [ListBackups](https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_ListBackups.html).
- [Serverless ListNamespaces](https://docs.aws.amazon.com/redshift-serverless/latest/APIReference/API_ListNamespaces.html), [ListSnapshots](https://docs.aws.amazon.com/redshift-serverless/latest/APIReference/API_ListSnapshots.html), [ListRecoveryPoints](https://docs.aws.amazon.com/redshift-serverless/latest/APIReference/API_ListRecoveryPoints.html).
- [ListBackupVaults](https://docs.aws.amazon.com/aws-backup/latest/APIReference/API_ListBackupVaults.html).

## Macie remains a separate coverage obligation

This patch does not close `aws.pci.s3.sensitive_auth_data_findings`. ListFindings/GetFindings can supply sanitized identifier metadata, but a completed job with samplingPercentage=100 does not prove every authorized object was successfully analyzed. Native finding results can be COMPLETE/PARTIAL/SKIPPED, and finding absence is not proof of full scan coverage. Per-object discovery results live separately and can contain sensitive data; no object payload or discovery-result contents are fetched. The existing `s3_macie_region_coverage` producer remains unchanged. Macie scan coverage is not invented and PII matches are not relabeled prohibited authentication data.

References: [ListFindings](https://docs.aws.amazon.com/macie/latest/APIReference/findings.html), [GetFindings](https://docs.aws.amazon.com/macie/latest/APIReference/findings-describe.html), [DescribeClassificationJob](https://docs.aws.amazon.com/macie/latest/APIReference/jobs-jobid.html).

The S3 general-purpose list explicitly sets `MaxBuckets=1000` so accounts whose bucket quota exceeds 10,000 use the required paginated request ([ListBuckets](https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListBuckets.html)). DynamoDB ListBackups explicitly requests `BackupType=ALL`, covering USER and SYSTEM backups; AWS Backup-created copies are covered separately by vault recovery-point enumeration ([ListBackups](https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_ListBackups.html)). Duplicate recovery-point IDs within one vault list invalidate coverage. The same underlying native ARN occurring once as an EBS/RDS resource and once as its Backup-managed recovery point remains one global resource identity.

Redshift Serverless ListRecoveryPoints returns native recoveryPointId and namespaceArn. After verifying the native namespace belongs to the same account/Region, the collector constructs the canonical recovery-point ARN `arn:${Partition}:redshift-serverless:${Region}:${Account}:recoverypoint/${RecoveryPointId}` from that native ID, following [the official service authorization resource format](https://docs.aws.amazon.com/service-authorization/latest/reference/list_redshift-serverless.html). It does not invent a namespace-child ARN.

Outposts ListOutposts and S3Control ListRegionalBuckets declare native NextToken request/response fields. The helper supplies the existing Requests.pages explicit `_tokens=("NextToken", "NextToken")` fallback for those two operations; an existing SDK paginator still takes precedence. This covers ListRegionalBuckets on botocore 1.43.111, which has no paginator for that operation. Duplicate tokens and configured page limits remain incomplete UNKNOWN; no global pagination code is changed.
