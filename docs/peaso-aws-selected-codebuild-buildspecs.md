# Selected inline CodeBuild buildspec secret inspection

This local addition scans the build instructions stored inline on an explicitly selected CodeBuild project. Kingfisher and TruffleHog run offline; matched values are hidden and matching detections become one leak. It does not inspect referenced files, S3 buildspecs, repositories, artifacts or executed build bytes.

Select `aws.review.codebuild.selected_inline_buildspec_secret_indicators` and supply exact account/Region scopes with these collector options:

```json
{
  "content_secret_scans": true,
  "selected_aws_codebuild_inline_buildspecs": [{
    "scope": "123456789012/us-east-1",
    "project_arn": "arn:aws:codebuild:us-east-1:123456789012:project/MyProject"
  }]
}
```

The selected project ARN must match its account and Region. Default scans, categories and framework selection do not authorize this source read. Internal grants are issued by the engine; do not add them to connector JSON.

Grant only `codebuild:BatchGetProjects` on the selected project ARNs. No build, execution, write, credential-validation or secret-store permission is needed. Normal AWS caller identity reads bind the configured session to the selected account.

The reader supports recognizable inline YAML starting with a `version: 0.1` or `version: 0.2` header, allowing a BOM, comments and document start. Other layouts, missing/default buildspecs and references remain undetermined. A clean result requires both detectors and complete selected coverage; a trustworthy detected hit remains visible when inspection is incomplete.

Bounds: eight projects in four explicit account/Region scopes, twelve calls, 256 KiB inspected source per project, 2 MiB per allocated SDK response and 4 MiB aggregate responses, with a cooperative 90-second collection budget. SDK/auth work can precede those cooperative checks; this is not a hard process or transport-memory limit.

Runtime integration and targeted acceptance are tracked separately from production publication. [Original native source proof and limits](aws-codebuild-buildspec-source-setup-20261020.md).
