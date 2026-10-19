# Identity closure review — 2026-10-19

All **204 input IDs** have explicit dispositions in [identity-closure-review.json](identity-closure-review.json), including their callback chains, native producers, exact field contracts, references, directed receipts and remaining limits. This review covers defensive configuration checks, including IAM, Secrets Manager, KMS, CloudTrail and alarm dependencies. It performs no offensive privilege escalation tests, live AWS calls, resource mutations, report generation in AWS, or secret verification.

| Disposition | IDs | Meaning |
|---|---:|---|
| Confirmed defect, corrected by coordinator | 30 | Two independent native producer/consumer defects affect the same alarm-family IDs |
| Bounded native contract | 5 | Four managed-policy consumers and the organization-membership alias have independent SDK-shaped positive, negative and unavailable cases |
| Unproved contract | 169 | Source attribution and existing fixture witnesses are accounted for, but exact native production and all semantic branches remain unproved |

No ID is certified semantically complete. The 3,321 attributed field observations include engine metadata, decoded policy JSON and intentional aliases; lack of a direct botocore member does not establish a defect. Existing fixture outcomes are recorded independently and never used to promote the 169 unproved contracts.

## Reproduced defects

**IDENTITY-1:** `aws_facts_gap._alarm` discarded `MetricDataQuery.AccountId`. A valid foreign-account direct metric with the same name, namespace and dimensions became indistinguishable from the local metric and produced false PASS for all 30 alarm IDs. AWS explicitly defines AccountId as the account containing the watched metric. The coordinator applied the proposed change preserving that member and binding the comparison to the local log group's account. Mixed local/foreign input and output queries remain conservative when the evaluated expression is unresolved. [AWS MetricDataQuery](https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_MetricDataQuery.html), [AWS cross-account alarms](https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_PutMetricAlarm.html).

**IDENTITY-2:** the metric-filter JMESPath object constructor manufactured `dimensions: null` when the valid native response omitted the optional dimensions map. The nested null survived the producer and all 30 callbacks returned UNKNOWN instead of PASS on otherwise complete dimensionless coverage. The coordinator applied the proposed projection normalization to preserve the documented omission. [AWS MetricTransformation](https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_MetricTransformation.html).

The exact minimal proposal remains at `/tmp/peasso-aws-review-20261019/final-closure/identity.patch`. This worker edited no shared runtime; the coordinator applied the patch. The original pre-fix receipt is preserved at `/tmp/peasso-aws-review-20261019/final-closure/identity-before-fix.log`: **226 passed, 60 strict expected failures**, with a paired observed-defect assertion and required-outcome assertion for each defect and ID. A preceding failed exploratory run exposed the real nested-null mismatch; it was not accepted as a passing receipt.

## Contracts distinguished from defects

`aws_account_configuration.Organization.OrganizationId` is intentionally produced from `DescribeOrganization.Organization.Id`, after validating the management account ID. The positive, documented not-member, and access-denied cases prove this alias for the in-scope organization-membership callback. It is not an absent native-field bug. [AWS DescribeOrganization](https://docs.aws.amazon.com/organizations/latest/APIReference/API_DescribeOrganization.html).

The subscription producer retains `TopicArn` and `SubscriptionArn`, derives safe IDs for pending subscriptions, and keeps denied inventory status. Directed tests use the actual subscription fetcher and cover confirmed, pending and denied joins across both 15-ID families. However, AWS describes `ListSubscriptions` as the requester's subscriptions: complete coverage of subscriptions owned by another account on a local topic remains **unproved**. This review does not convert that scope uncertainty into either a verified defect or complete notification assurance. [AWS ListSubscriptions](https://docs.aws.amazon.com/sns/latest/api/API_ListSubscriptions.html).

IAM documents are URL-decoded JSON projected from GAAD version and inline documents; their Statement/Action/Effect/Resource children are not direct botocore structure fields. The new bounded cases prove default-version document decoding and safe/unsafe/missing/denied behavior for four named consumers, not all IAM policy interpretation. Credential-report columns are CSV data inside GetCredentialReport.Content; their absence from a botocore structure is not a missing-field defect. [AWS GAAD](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountAuthorizationDetails.html), [AWS credential reports](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_getting-report.html).

## Reproduction and limits

Run `.venv/bin/python -m pytest tests/test_aws_identity_closure_review.py -q`. The focused gate checks native read responses through Requests, the real metric-filter/alarm/subscription producers, CloudTrail home-region details and registered callbacks. It also covers foreign account rejection, ordinary positive coverage, wrong namespace, denied reads, omitted account defaults, optional dimensions, expression uncertainty, mixed metric/output binding and organization aliases. **Final result: 410 passed in 33.59 seconds, zero failed or expected failures.** Receipt hashes are recorded in the JSON report.

The JSON records the complete input SHA-256, source pins, current source hashes, installed botocore model members and each ID's unresolved exact paths. This is bounded offline evidence: it does not prove live service behavior, all collection paths, all pagination boundaries, every policy semantic, notification delivery, or the entire compliance obligation. Canonical catalogs, framework mappings, HackTricks scope decisions, UI/network maps and central evidence ledgers remain owned by the coordinator and other workers.
