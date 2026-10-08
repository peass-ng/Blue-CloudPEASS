# Pinned hardening catalog review

This review covers every control reachable from the configured root benchmarks,
including controls which return no resources in the validation accounts. It is
based on the control definitions and their SQL, not only the current findings.
The accompanying CSV records the source location, SQL hash, interpretation,
applicability exclusions, and blacklist rules for each control.

| Provider | Compliance | Perimeter | Definitions reviewed |
| --- | ---: | ---: | ---: |
| AWS | 679 | 62 | 741 |
| Azure | 476 | 14 | 490 |
| GCP | 202 | 33 | 235 |
| Kubernetes | 781 | 0 | 781 |
| Total | 2138 | 109 | 2247 |

Versions are pinned in `bluepeass/hardening_catalog.json`. Kubernetes definitions
include removed APIs and the deliberately excluded Secret-object read. Those
definitions count as reviewed, and exclusions remain explicit coverage entries.

The blacklist distinguishes three cases:

- A fundamentally invalid assessment, such as requiring every stock IAM policy
  to be attached, enabling experimental GKE alpha features, or inferring absence
  of encryption from absence of a customer-managed key.
- A resource-specific exception supported by positive query evidence, such as a
  mandatory default security group, service-owned ENI, bootstrap Kubernetes
  resource, inherited non-root settings, or immutable image digest. A missing
  evidence field never triggers such an exclusion.
- Exact duplicate query results. These collapse only when the canonical check
  produced identical resource, status, evidence, and scope. Missing or conflicting
  canonical results are retained, and source suites/control references survive.

Query errors are never blacklisted. Unsupported/removed APIs are excluded before
execution with a coverage explanation; resource reads lacking permissions remain
errors. Native exports retain the upstream assessments for diagnosis.

Customer intent cannot be inferred from an API snapshot. Public websites, shared
resources, standby capacity, retention periods, customer key requirements,
monitoring product preferences, network appliances, and multi-tenant quotas can
be legitimate or unsafe depending on the deployment. Exposure/configuration
evidence for these cases is retained unless a reviewed rule or explicit resource
exception provides enough context. No blanket suppression is based on severity,
display-name prefixes, the presence of a "managed" label, or failed reads.

## Concrete query issues and applicability evidence

`docker/query_context.py` modifies a private runtime copy of the pinned SQL. It
adds named dimensions needed for evidence-based filtering, and corrects:

- Azure security contacts: a `LIMIT 1` after grouping by subscription discarded
  correctly configured contacts in other subscriptions.
- Azure user consent: disabling self-consent is a valid stricter alternative to
  consent restricted to verified publishers.
- Cloud SQL TLS: requiring trusted client certificates is a stronger valid mode
  than encryption-only; legacy `requireSsl` also enforces encrypted connections.
- Kubernetes command settings: enabled admission defaults and comma-separated
  plugins, `command` plus `args`, and valid certificate/key filenames are assessed
  instead of requiring one literal flag spelling or a `.pem` filename.
- Kubernetes workloads: effective inherited non-root settings and immutable image
  digests are explicit evidence, rather than guesses from names or error text.

These changes do not create resources or inspect Secret values. Individual
effective privilege, trust, network exposure, credential, and encryption checks
remain in the audit. The runtime records which context/query corrections ran.

## Primary references

- [Lambda's default encryption](https://docs.aws.amazon.com/lambda/latest/dg/configuration-envvars-encryption.html)
- [CloudWatch Logs default encryption](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/data-protection.html)
- [Lambda network isolation](https://docs.aws.amazon.com/whitepapers/latest/security-overview-aws-lambda/network-isolation.html)
- [CloudFront OAC and legacy OAI](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/private-content-restricting-access-to-s3.html)
- [Azure MMA/OMS retirement and AMA migration](https://learn.microsoft.com/en-us/azure/azure-monitor/agents/azure-monitor-agent-migration)
- [Modern Azure Activity Log diagnostic settings](https://learn.microsoft.com/en-us/azure/azure-monitor/platform/activity-log)
- [GKE alpha cluster limitations](https://docs.cloud.google.com/kubernetes-engine/docs/concepts/alpha-clusters)
- [Cloud SQL SSL modes](https://docs.cloud.google.com/sql/docs/mysql/instance-settings)
- [SQL Server trace flag 3625](https://learn.microsoft.com/sql/t-sql/database-console-commands/dbcc-traceon-trace-flags-transact-sql)
- [Kubernetes admission defaults](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/)
- [Kubernetes Pod security contexts](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [Kubernetes immutable image references](https://kubernetes.io/docs/concepts/containers/images/)

Control names/titles and query references originate in the pinned Turbot mods,
which retain their Apache-2.0 licenses and source notices. Review decisions,
blacklist conditions, and compatibility code are maintained by Blue-CloudPEASS.
