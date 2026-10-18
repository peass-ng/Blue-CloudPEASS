# Native resource classification and priority tags

`aws_resource_priority_tags_present` consumes a regional `aws_tagged_resource`
inventory containing exactly four source families: EC2 instances, S3 buckets in
their measured home Region, RDS DB instances and unqualified Lambda functions.
The existing signed SW38 predicate is unchanged. This is neither an inventory
of every AWS service nor an account-wide all-Regions assertion.

The producer enumerates native resources before joining tags, including resources
which have never been tagged. It does not use Resource Groups Tagging API as an
inventory. All requests use existing scan budgets, pagination and shared query
cache. A partial page, duplicate identity, foreign ARN, unavailable parent list,
missing tag field or denied read prevents completed source coverage and leaves
the control unknown or denied. No policy observation is supplied by the owner.

| Family | Inventory and tag evidence |
| --- | --- |
| EC2 | Complete DescribeInstances plus complete DescribeTags filtered to instance resources. Every native instance is retained; absence from the complete tag set proves an empty map. A tag for an unenumerated instance makes the join uncertain. |
| S3 | Complete ListBuckets, GetBucketLocation and GetBucketTagging with ExpectedBucketOwner. Only the selected home Region receives a bucket. EU means eu-west-1; a successful empty XML LocationConstraint means us-east-1. Botocore omits that empty XML member, so HTTP 200 is required for this interpretation. NoSuchTagSet proves an empty tag map. |
| RDS | DescribeDBInstances DBInstanceArn and explicit TagList. An explicit empty array proves no tags. An omitted TagList remains unknown; no additional RDS tag permission is requested. |
| Lambda | ListFunctions unqualified FunctionArn followed by ListTags for the exact same ARN. An explicit empty Tags map proves no tags; missing/denied tags remain unknown. |

`covered_source_kinds` is emitted only after successful completion of all four
native producers in the regional envelope. It describes these completed reads;
it is not a supplied proof flag or a compliance result. Credential-like values
from the two new tag operations are redacted before the response enters the
single-flight Future/cache. A dedicated tag-subtree projection validates and
preserves the opaque EC2 NextToken for the shared paginator; it is never placed
in tag evidence or the snapshot. Redacted evidence is not treated as an absent
tag. If tag keys would disappear during sanitization (including legitimate
keys such as Code), evidence stays unknown rather than falsely reporting no
tags. Lambda checks preservation of original keys before the cache; every
family also checks its tag map against final snapshot sanitization.
The superseded initial generic redaction mistakenly stripped NextToken;
the corrected SDK regression splits classification and priority across two
pages and supplies every downstream API response even when max_pages=1.

The owner must supply an explicitly scope-bound `compliance_policy.sw38_policy`
(or its existing `by_scope` representation), with `status: collected`, the exact
`ACCOUNT/REGION` scope, and these nonempty, unique string arrays:

```json
{
  "classification_tag_keys": ["classification"],
  "priority_tag_keys": ["priority"],
  "allowed_classification_values": ["internal", "restricted"],
  "allowed_priority_values": ["high", "normal"]
}
```

These names and values are normative owner criteria, never derived from observed
tags. The existing predicate validates them. An absent, foreign or malformed
policy cannot produce PASS. Complete native empty tags produce FAIL only with
a valid owner policy. The collector does not infer business classification.

## Permission review is pending

This private candidate introduces exactly two read-only operations not present
in the published customer role: `ec2:DescribeTags` and `lambda:ListTags`.
They also require reviewed IAM action mappings before the policy generator can
accept the added collector actions. No allowlist, role, template, trust, policy
or cloud resource is changed by this candidate. It must remain stopped for
deployment until the release owner explicitly reviews those permissions and
publishes an appropriate immutable customer template. A customer role without
the required reads receives denied/unknown evidence, never false empty tags.

## Primary references

- [EC2 DescribeTags](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeTags.html)
- [EC2 DescribeInstances](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeInstances.html)
- [Lambda ListTags](https://docs.aws.amazon.com/lambda/latest/api/API_ListTags.html)
- [RDS DBInstance TagList](https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DBInstance.html)
- [S3 GetBucketLocation](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketLocation.html)
- [S3 GetBucketTagging](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketTagging.html)

Validation uses botocore-shaped positive/negative native responses through
collect_live and the unchanged engine, plus a real botocore REST-XML parser
regression for empty LocationConstraint. No cloud calls or resources are needed.
