# Selected ECS and Batch command literals: local proposal

This unregistered proposal adds `aws.review.workload.selected_command_literal_secret_indicators` to the existing **Secrets** group when a future adapter explicitly registers it. It scans only returned ECS `containerDefinitions[].entryPoint` and `.command` arrays, and classic AWS Batch `containerProperties.command`, on exact selected active definition ARN revisions. Existing selected configuration coverage reads the environment fields on these services and does not scan these command arrays.

Both offline detectors must complete over every selected supported field for PASS. A supported detection produces FAIL even when another field, target or detector is incomplete; missing fields, malformed native data, unsupported definitions and unresolved Batch `Ref::` elements prevent a negative result. Explicit native empty arrays establish zero returned literals only after the complete native identity, response, active-status and cardinality contract is satisfied; omitted properties never establish absence.

## Authorization and setup

The future adapter must call `prepare(options, scopes)` before credential discovery or SDK/session construction, and pass only its authorized, pinned session factory to `collect`. The check ID, an independent `content_secret_scans: true` opt-in, and the exact named grant `aws-workload-selected-command-literals-v1` are all required; selection alone provides no grant. Plans are copied, locally HMAC sealed and revalidated before authentication, with source hashes checked before authentication and before publication.

```python
# Proposed API; these imports are NOT wired into any runtime dispatcher.
scope = '123456789012/us-east-1'
options = {
    'check_id': 'aws.review.workload.selected_command_literal_secret_indicators',
    'content_secret_scans': True,
    'content_secret_scan_grants': ['aws-workload-selected-command-literals-v1'],
    'selected_aws_workload_commands': [
        {'scope': scope, 'service': 'ecs',
         'definition_arn': 'arn:aws:ecs:us-east-1:123456789012:task-definition/AuditTask:3'},
        {'scope': scope, 'service': 'batch',
         'definition_arn': 'arn:aws:batch:us-east-1:123456789012:job-definition/AuditJob:3'},
    ],
}
# plan = producer.prepare(options, [scope])  # credential-free
# collection = producer.collect(plan, authorized_session_factory)
# verdicts = [consumer.evaluate(row, collection) for row in collection['items']]
# combined = consumer.evaluate_collection(collection)  # one leak per value
```

The only workload permissions are the readonly actions `ecs:DescribeTaskDefinition` and `batch:DescribeJobDefinitions`. AWS lists no resource-level IAM support for either describe action, so their IAM grants require `Resource: "*"`; the exact revision restriction is enforced by the producer's validated selection and serialized requests, rather than by an ARN-scoped IAM statement. This local proposal does not change or deploy any customer policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {"Effect": "Allow", "Action": ["ecs:DescribeTaskDefinition", "batch:DescribeJobDefinitions"],
     "Resource": "*", "Condition": {"StringEquals": {"aws:RequestedRegion": "us-east-1"}}}
  ]
}
```

The broader IAM read grant and its region condition require deliberate acceptance by the future integrating owner; the proof exercises selectors and SDK models, not effective IAM. Regional STS `GetCallerIdentity` binds account and principal and does not require an IAM permission grant. The factory is trusted to return the authorized session and must not fetch source content or execute workloads itself.

## Native contract and result privacy

ECS requests use `DescribeTaskDefinition(taskDefinition=exact_revision_arn)`. Returned ARN, family, integer revision, `ACTIVE` status and a bounded nonempty container list with unique valid names must match; both relevant arrays on every returned container are required for complete coverage. Batch requests use `DescribeJobDefinitions(jobDefinitions=[exact_revision_arn])` with no discovery, status filter or pagination; exactly one returned definition, no continuation token, matching ARN/name/integer revision and `ACTIVE` status are required. Only `type: container` with classic `containerProperties` is supported; `ecsProperties`, `eksProperties`, `nodeProperties` and EKS orchestration are unsupported.

Array string bytes are scanned in order, separated by a newline per array, without shell expansion or parameter interpolation. Each array gets an opaque HMAC path and its fixed native field/index provenance; line numbers refer to that transient array representation. Batch `Ref::` entries are skipped and make coverage incomplete, while other literal entries may retain positive evidence. No parameter defaults, overrides, images, environment, environmentFiles, secret references, health checks, running tasks, running jobs or referenced files are inspected. An empty command declaration does not prove the image defaults are clean, and the definition says nothing about running adoption or runtime argument overrides.

Raw literals exist only transiently in SDK responses, extraction and the existing scanner helper, then local references are released; Python memory is not securely erased. Public results retain no raw ARN/name, caller identity, command, HTTP header, provider error or scanner JSON, only scope, safe field provenance, counts, HMAC locators and value-level HMAC leak observations. The same value merges across both detectors and fields through `merge_leaks`, and the pure `evaluate_collection` consumer combines it across selected definitions into one leak with distinct opaque locations; at most 1,024 distinct leaks and 4,096 locations can enter that eight-target union. Integration with the runtime's `secret_findings` remains pending. Kingfisher 1.4.0 performs detection only and TruffleHog 3.92.5 uses offline stdin with `--no-verification`, `--no-update`, no verification cache and no archive extraction; no credential validation or revocation occurs.

## Bounds and cleanup

Limits are eight exact revisions across four scopes (at most eighty characters per scope and 512 per selected ARN), twelve SDK calls including identity reads, thirty-two ECS containers per definition, 256 literal elements and 256 KiB of encoded array content per target, 128 distinct leaks and 512 locations per target. Responses are limited to 2 MiB each and 4 MiB in aggregate, independently for accepted transport bodies and serialized parsed responses, with structural depth/node bounds on parsed objects. Scanner subprocess output is bounded by the existing helper to 4 MiB per invocation; retained findings and scanner metadata have their own bounds.

Official regional HTTPS endpoint, service, operation, exact URL/body and the ECS target header are checked against SDK serialization and immediately before sending. SDK retries use one total attempt, redirects and additional sends are rejected, configured endpoints and proxies are disabled, and unsupported compressed responses are rejected. The HTTP wrapper bounds each raw read by the remaining response/aggregate byte budget before SDK parsing and closes its raw stream on success or error; an unframed response that reaches its limit cannot prove EOF and is rejected without an extra read. Framed responses use their native Content-Length and reject early EOF. SDK clients close and temporary guards/transport wrappers are removed on all paths. Scanner subprocesses receive only stdin and discarded stderr, with process-group termination and pipe cleanup provided by the existing helper.

The collection deadline is ninety seconds, checked before/after native calls, while reading response chunks and around detectors; each detector receives at most fifteen seconds and connect/read timeouts are each at most three seconds. Session factory/auth internals, SDK signing/model allocation, Kingfisher initialization/lock contention and individual synchronous reads are cooperative boundaries, so a hard whole-process deadline still requires a supervising adapter. No such process supervisor or runtime integration is claimed by this deliverable.

## Finite proof and pending integration

Run only the direct, explicitly isolated NEW-module proof:

```sh
PYTHONPATH=. .venv/bin/python tests/aws_workload_command_source_20261020_test.py
```

This standalone unittest loads the two new files by their exact paths plus the unchanged `peaso.secret_scanning` helper. It does not import the existing `peaso.collectors` or `peaso.checks` dispatchers, modify packages in `sys.modules`, disable pytest hooks, edit receipts for other sources or bypass the shared K8s route-map admission guard. The existing shared import is known to be blocked by an independent K8s network route-map change; this proof makes no engine/runtime acceptance claim. Native botocore Stubber validates positive, clean, explicit-empty, denied, missing, foreign, inactive, duplicate and partial native responses; separate extraction tests cover malformed values that Stubber correctly rejects as non-native. A fake HTTP transport also exercises actual signed SDK serialization and native parsing, with socket denial preventing live network/auth; it does not prove live AWS reachability or deployed permissions.

Pending work is explicit registration, connector option validation and pre-auth invocation, authorized session plumbing, final Secrets metadata/evidence/remediation admission, shared value-level finding integration, policy applicability validation, packaging, and engine/UI acceptance after the independent shared guard is resolved by its owner. No existing hooks, shared receipts, metadata, roles or source files are changed by this proposal. No cloud/auth run, full suite, commit, push or deployment is part of this proof.

Primary AWS references reviewed on 2026-10-20:

- [ECS DescribeTaskDefinition](https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_DescribeTaskDefinition.html): exact ARN selection and returned task definition.
- [ECS ContainerDefinition](https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_ContainerDefinition.html): entryPoint/command are optional string arrays mapped to Docker entrypoint/command.
- [Batch DescribeJobDefinitions](https://docs.aws.amazon.com/batch/latest/APIReference/API_DescribeJobDefinitions.html): exact revision selectors, returned list and pagination.
- [Batch JobDefinition](https://docs.aws.amazon.com/batch/latest/APIReference/API_JobDefinition.html): revision, status, container variants and identity.
- [Batch ContainerProperties](https://docs.aws.amazon.com/batch/latest/APIReference/API_ContainerProperties.html): optional command array and separation from other container properties.
- [Batch job definition parameters](https://docs.aws.amazon.com/batch/latest/userguide/job_definition_parameters.html): `Ref::` placeholders and submission-time overrides.
- [STS GetCallerIdentity](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html): account/principal binding with no grant required.
- [ECS service authorization](https://docs.aws.amazon.com/service-authorization/latest/reference/list_ecs.html) and [Batch service authorization](https://docs.aws.amazon.com/service-authorization/latest/reference/list_batch.html): both describe actions have no resource type in their IAM action rows.

The dedicated review receipt is `docs/check-review/aws-workload-command-source-20261020.json`; its source hashes document this finite local proof and must be regenerated after edits. They detect local reviewed-file drift and are not signatures or authentication for hostile Python processes or arbitrary external snapshots. The consumer validates supplied provenance and shape without filesystem or cloud access.
