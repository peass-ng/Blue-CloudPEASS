# Selected ECS and Batch command secret inspection

This check inspects literal command arguments returned for explicitly
selected active ECS task-definition and classic Batch job-definition revisions.
Kingfisher and TruffleHog run offline. Values are hidden, repeated matches become
one leak, and credentials are never tested against external services.

Select `aws.review.workload.selected_command_literal_secret_indicators` and provide
these collector options with matching account/Region scopes:

```json
{
  "content_secret_scans": true,
  "selected_aws_workload_commands": [
    {
      "scope": "123456789012/us-east-1",
      "service": "ecs",
      "definition_arn": "arn:aws:ecs:us-east-1:123456789012:task-definition/MyTask:3"
    },
    {
      "scope": "123456789012/us-east-1",
      "service": "batch",
      "definition_arn": "arn:aws:batch:us-east-1:123456789012:job-definition/MyJob:3"
    }
  ]
}
```

The definition ARN must include its exact revision and match the selected account
and Region. Internal grants are supplied by the engine, not connector JSON.
Default metadata, category and framework scans do not authorize this content read.

Grant `ecs:DescribeTaskDefinition` and `batch:DescribeJobDefinitions`. Both actions
require `Resource: "*"` because AWS does not support resource-level permissions for
them; use an `aws:RequestedRegion` condition if appropriate. The current customer-role
template already includes these read actions. The collector still restricts every
request to an explicitly selected ARN and binds the session using STS caller identity.
No task submission, execution, secret-store, image-pull or write permission is needed.

Coverage is limited to returned ECS `entryPoint`/`command` arrays and classic Batch
`containerProperties.command`. Both detectors and every selected supported field
must complete for a clean result. Missing arrays, unresolved Batch `Ref::` parameters,
unsupported definitions and denied reads remain undetermined; a detected secret
remains a failure when other inspection is incomplete. Image defaults, environment
files, runtime overrides, EKS/multi-node Batch definitions and executed bytes are excluded.

The reader accepts at most eight definitions in four explicit scopes, with bounded
responses, literal bytes and a cooperative scan deadline. See the
[native contract and original proof](aws-workload-command-source-setup-20261020.md)
for exact bounds and the supervising-process limitation.
