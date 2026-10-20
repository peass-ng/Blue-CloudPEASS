# Native checks reviewed after AI disagreements

AI verdicts can reveal engine bugs, but are not ground truth. Corrections require native evidence and a regression that retains the corresponding unsafe case. AI verdicts remain attributed in finding details, alongside the scanner status.

| Native evidence | Corrected interpretation |
| --- | --- |
| Shared RDS-compatible API returns a different `Engine` | DocumentDB, Neptune and RDS controls apply only to their engine. Missing engine identity remains incomplete evidence. |
| Aurora PostgreSQL exports `postgresql` | Do not require the unsupported RDS PostgreSQL `upgrade` log category. |
| EC2 instance type has EBS optimization enabled by default | A false instance-level flag alone does not establish disabled optimization. Unavailable type metadata remains unknown. |
| IAM policy has positive `PermissionsBoundaryUsageCount` | The policy is in use as a boundary; attachment-only controls distinguish it from a permissions-policy grant. |
| SNS topic has no confirmed or pending subscriptions | Delivery feedback has no subscription endpoint to evaluate. |
| Queue is an exact configured dead-letter destination | Do not demand another chained DLQ. Names do not establish destination status; denied inverse metadata remains unknown. |
| Secret declares an AWS `OwningService` | The owning service manages rotation; do not require customer rotation rules. |
| API policy has a covering unconditional deny outside a bounded IP allowlist | Evaluate the explicit deny before claiming unrestricted internet invocation. Unrelated resources, extra conditions and incomplete coverage do not qualify. |
| KMS policy enforces an exact `kms:CallerAccount` | Recognize the account restriction; wildcard values remain unsafe. |
| Firehose trust enforces its documented account-valued `sts:ExternalId` | Recognize this service-specific confused-deputy protection. Other services and optional conditions retain their existing predicates. |
| Global CloudFront resource appears in every regional dependency inventory | Assess the global resource once, while continuing to assess each region's supported resources. |
| Federated trust pins a Cognito user-pool audience without a subject | Require manual validation of claim enforcement and the eligible user population. Audience alone does not prove safe access. IAM condition keys are case-insensitive. |

A security group open to the internet on any customer-interface port remains a failure. An AI interpretation requiring *all* ports to be open is incorrect. A later live SNS subscription count also does not retroactively invalidate an earlier captured count.

Primary references:

- [EC2 EBS optimization defaults](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebs-optimized.html)
- [IAM permissions-policy and permissions-boundary usage](https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListEntitiesForPolicy.html)
- [AWS-managed secret rotation](https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotate-secrets_managed.html)
- [Firehose trust ExternalId](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CreateFirehoseStream.html)
- [IAM condition evaluation](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition.html)
- [Explicit deny outside an IP range](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_examples_aws_deny-ip.html)
- [SQS native dead-letter source references](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_ListDeadLetterSourceQueues.html)
- [Upstream any-port security-group predicate](https://github.com/prowler-cloud/prowler/blob/master/prowler/providers/aws/services/ec2/ec2_securitygroup_allow_ingress_from_internet_to_any_port/ec2_securitygroup_allow_ingress_from_internet_to_any_port.py)

The maintenance command described in [the AI review guide](README.md#reviewing-aiengine-disagreements) can publish a new report for an existing completed scan. It retains the original snapshot and report, records reviewed adjudications and uses a tenant-bound compare-and-swap update so concurrent changes cannot be overwritten.
