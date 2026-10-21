# Selected ECS environment file review

This source-only handoff covers the ECS `environmentFiles` part of fixed group AWS-2. Batch variants and image association remain separate parts of AWS-2. The default is off. The scan must name `aws.review.ecs.selected_environment_file_secret_indicators`, set `content_secret_scans: true`, and provide both exact selections before a credential or content read. When only the ECS check is named, the selected S3 source list must exactly match the ECS file targets; an unrelated S3 target is rejected. An independently named S3 source check may authorize its own additional S3 selections.

```json
{
  "checks": ["aws.review.ecs.selected_environment_file_secret_indicators"],
  "connector": {
    "provider": "aws",
    "scopes": ["123456789012/us-east-1"],
    "options": {
      "content_secret_scans": true,
      "selected_aws_ecs_environment_files": [{
        "scope": "123456789012/us-east-1",
        "task_definition_arn": "arn:aws:ecs:us-east-1:123456789012:task-definition/app:7",
        "container": "api",
        "environment_file_arn": "arn:aws:s3:::selected-env-bucket/prod/app.env"
      }],
      "selected_aws_s3_sources": [{
        "scope": "123456789012/us-east-1",
        "bucket": "selected-env-bucket",
        "key": "prod/app.env",
        "format": "text"
      }]
    }
  }
}
```

At most four exact files are selected. ECS `DescribeTaskDefinition` is read before and after the file scan. Both responses must identify the same ACTIVE family, revision, unique container, and complete ordered `environmentFiles` list; drift leaves the ECS result UNKNOWN even when a file detector found a likely secret. The transient S3 grant is issued after the first association and revoked after that file read. A container may declare up to ten files; unselected files keep clean evidence UNKNOWN, while a trusted positive may still be FAIL. The reused S3 profile verifies native caller account and bucket location, requires `ExpectedBucketOwner`, then performs bounded `HeadObject` → ETag conditioned `GetObject` → conditioned `HeadObject` with matching version/length/ETag. It does not read Secrets Manager or SSM values, run tasks, write AWS resources, or execute file text. It scans returned `.env` text as source bytes; it does not claim the task consumed the file or that a credential works.

The scanner principal needs `ecs:DescribeTaskDefinition` on the exact task-definition revision ARN; `sts:GetCallerIdentity`; `s3:GetBucketLocation` on the exact bucket ARN; and `s3:GetObject` on the exact object ARN. `HeadObject` is authorized through `s3:GetObject`, not a separate IAM action. This ECS profile selects the current object and does not accept a version ID. Constrain the S3 grant to the trusted account with `aws:ResourceAccount` and retain the API `ExpectedBucketOwner` check. SSE-KMS objects may require `kms:Decrypt` on the specific key for the scanner principal. There is no `s3:ListBucket` requirement for this exact object read.

The ECS task execution role has its own runtime permissions. AWS documents `s3:GetObject` on the file and `s3:GetBucketLocation` on the bucket for that role; those permissions do not grant the scanner access. The scanner must receive its separate read permissions above.

Sources: [ECS environment files](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/taskdef-envfiles.html), [ECS task execution role S3 permissions](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_execution_IAM_role.html), [S3 HeadObject](https://docs.aws.amazon.com/AmazonS3/latest/API/API_HeadObject.html).
