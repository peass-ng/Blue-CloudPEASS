AWS resource-policy review (2026-10-19)
=======================================

`aws_cis_aws_resource_policy_unrestricted_principal` now reviews the finite policy families in [the generated coverage inventory](aws-resource-policy-coverage.json), including nested and qualified resources. Discovery uses exact SDK operations rather than guessed names. The original SNS, SQS, Lambda-function and ECR-repository paths remain in place. Additional recipes cover storage, databases, streams, API endpoints, role trusts, service sharing and newer policy APIs. Read-only IAM mappings and the AWS policy-reference digest are recorded in `peaso/collectors/aws_resource_policy_permissions.json`.

The predicate flags wildcard principals, including AWS principal lists and broad NotPrincipal grants, unless every alternative for at least one positive, required condition establishes a caller/account/organization or network boundary. Fixed-account ARN conditions may contain resource wildcards. TLS, dates, region and negative conditions do not establish a positive grant boundary. IfExists and ForAllValues require a matching Null:false guard proving the condition key is present. Public IPv4/IPv6 ranges and their equivalent split ranges do not qualify. Explicit account, organization, VPC, endpoint, source ARN and bounded source-IP conditions are recognized.

The check examines policy declarations. Identity policies, SCPs, public-access blocks and service-specific effective authorization remain separate controls. An unconditional Deny covering an entire grant cancels it; a covering Deny outside one required caller/network boundary can confine it. Complex relevant Deny interactions produce UNKNOWN. Known unrestricted grants remain FAIL when another family is denied or pagination is incomplete; the coverage gap remains visible separately. Missing mandatory documents produce UNKNOWN, and an absent policy does not manufacture PASS. Home-endpoint resources carry account and collection-region provenance. This review is not a live account validation.

Run:

```
.venv/bin/python scripts/audit_aws_resource_policy_coverage.py
.venv/bin/python -m pytest tests/test_aws_resource_policy_coverage.py tests/test_peaso_aws_resource_policy_native.py
```

The audit requires an explicit decision for every Get/Describe policy API in the pinned SDK. [Reviewed exclusions](../peaso/collectors/aws_resource_policy_exclusions.json) distinguish identity policies, Cedar, operational policy formats and derived status APIs from IAM resource grants. They are not counted as covered resource families. The audit also checks exact IAM mappings; contract tests exercise every recipe against installed Botocore input/output shapes. SDK/API enumeration cannot prove that AWS has no new or undocumented policy surface, so upgrades and new AWS service announcements still require review.

Primary references: [AWS service authorization support](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_aws-services-that-work-with-iam.html), [IAM global condition keys](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html), [AWS programmatic action reference](https://awspolicygen.s3.amazonaws.com/js/policies.js).

Recipes unavailable in the installed SDK are omitted from the advertised role reads and produce explicit collection gaps. The generated inventory records reviewed families, not a promise that every installed SDK or AWS partition can execute every recipe. Generate the role with the same service models used by the worker.

The resource-type receipt in `peaso/collectors/aws_resource_policy_targets.json` maps 91 reviewed policy actions to 109 resource-type entries, with three additional ancestor authorization entries distinguished from attachments. Its separate IAM support-table review accounts for 42 Yes/Partial service rows: 40 have policy collection paths; Cloud9 named-identity membership and IoT certificate/identity policies do not expose wildcard IAM Principal attachments. Newer APIs absent from that table remain included in the SDK and service-authorization audit.

Every extended discovery recipe is replayed through the registered check with both an unrestricted grant and an account-constrained grant. These SDK-shape fixtures verify collection-to-predicate behavior, not live AWS acceptance. Dedicated cases cover Image Builder build versions and guardrail profiles referenced only by published guardrail versions. Positive case-insensitive conditions retain the same presence and caller-boundary requirements as their case-sensitive equivalents.
