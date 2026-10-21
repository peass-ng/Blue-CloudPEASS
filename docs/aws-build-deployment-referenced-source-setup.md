# Selected AWS build and deployment source review

`aws.review.build_deployment.referenced_source_secret_indicators` is off by default. Name this check, set `content_secret_scans: true`, and select at most four exact references in `selected_aws_build_deployment_sources`. S3 profiles also require matching `selected_aws_s3_sources`; the CodeCommit profile does not. Native identity is read before and after the selected content. An extra S3 target is rejected unless the independent S3 check is also named. The S3 reader validates the caller account, bucket Region, `ExpectedBucketOwner`, and HEAD → ETag conditioned GET → conditioned HEAD, with version ID compared throughout when present.

```json
{
  "checks": ["aws.review.build_deployment.referenced_source_secret_indicators"],
  "connector": {"provider": "aws", "scopes": ["123456789012/eu-west-1"], "options": {
    "content_secret_scans": true,
    "selected_aws_build_deployment_sources": [{
      "profile": "codebuild_s3_source", "scope": "123456789012/eu-west-1",
      "project_arn": "arn:aws:codebuild:eu-west-1:123456789012:project/AuditProject",
      "source_s3_uri": "s3://selected-source-bucket/jobs/source.zip"
    }],
    "selected_aws_s3_sources": [{"scope": "123456789012/eu-west-1", "bucket": "selected-source-bucket", "key": "jobs/source.zip", "format": "zip"}]
  }}
}
```

| Profile | Native read and exact field | Bound revision | Accepted object |
| --- | --- | --- | --- |
| `codebuild_s3_source` | `BatchGetProjects.projects[0].source` with `type=S3`, `location=bucket/key` | selected project ARN, `lastModified`, and `sourceVersion` if selected `version_id` is supplied | `.zip` |
| `codebuild_s3_buildspec` | `BatchGetProjects.projects[0].source.buildspec` as exact `arn:aws:s3:::bucket/key` | selected project ARN and `lastModified`; current source configuration only | `.yml`, `.yaml` |
| `codebuild_build_output` | `BatchGetBuilds.builds[0].artifacts.location` as exact `arn:aws:s3:::bucket/key` | selected build ARN/ID, project, successful completed status, `endTime`, and returned artifact location before and after the S3 read | selected ZIP object with an opaque key |
| `codebuild_codecommit_source` | `BatchGetBuilds.builds[0].source.type=CODECOMMIT`, canonical regional `source.location`, and exact `resolvedSourceVersion` commit | selected completed build ARN/ID, same-account CodeCommit repository ARN and repository ID, selected 40-hex commit, exact file path, and file blob ID before and after | one explicitly named UTF-8 file, at most 1 MiB inspected |
| `codepipeline_action_output` | `ListActionExecutions.actionExecutionDetails[*].output.outputArtifacts[*].s3location.bucket/key` | selected pipeline ARN/name, execution ID, action execution ID, artifact name, successful action status, pipeline version, stage/action name, and returned location before and after the S3 read | selected ZIP object with an opaque key |
| `elasticbeanstalk_source_bundle` | `DescribeApplicationVersions.ApplicationVersions[0].SourceBundle.S3Bucket/S3Key` | selected application version ARN, label, `DateUpdated` | `.zip`, `.war` |
| `amplify_s3_zip_deployment` | `GetJob.job.summary.sourceUrl` with `sourceUrlType=ZIP` (or omitted default) | selected app, branch, job ARN/ID, `commitId`, `commitTime` | `s3://.../*.zip` |

The scanner principal needs the selected native permission: `codebuild:BatchGetProjects` on the project ARN; `codebuild:BatchGetBuilds` on the selected build's project ARN; `codepipeline:ListActionExecutions` on the selected pipeline ARN; `elasticbeanstalk:DescribeApplicationVersions` on the selected application version ARN; or `amplify:GetJob` on the job ARN. The CodeCommit profile additionally needs `codecommit:GetRepository` and `codecommit:GetFile` on the selected repository ARN. S3 profiles also need `s3:GetBucketLocation` on the selected bucket and `s3:GetObject` on the selected object for an unversioned read. S3 `HeadObject` uses the corresponding object read permission. If a CodeBuild `sourceVersion` names an S3 object version, set the same `version_id` in both selectors and grant `s3:GetObjectVersion` on that object for versioned HEAD and GET. An SSE-KMS object may additionally require `kms:Decrypt` on its key. `sts:GetCallerIdentity` needs no IAM permission.

For a build artifact, select `profile: codebuild_build_output`, the exact `build_arn`, and `source_s3_uri` matching the native primary artifact location. For a pipeline artifact, select `profile: codepipeline_action_output`, the exact `pipeline_arn`, `pipeline_name`, `pipeline_execution_id`, `action_execution_id`, `artifact_name`, and `source_s3_uri` matching the native output artifact location. Add the matching `selected_aws_s3_sources` object with `format: zip`; the independent S3 check is not required for the one bound object. Both new profiles reject other accounts, Regions, extra S3 objects, missing or changed native references, and native pagination.

For a CodeCommit build source, select exact `profile: codebuild_codecommit_source`, `scope`, `build_arn`, `repository_arn`, `commit_id`, and absolute `file_path`. The selected commit must equal the build's native `resolvedSourceVersion`; the build's primary source location must equal `https://git-codecommit.REGION.amazonaws.com/v1/repos/REPOSITORY`. This profile does not use Git/HTTPS transport, branches, tags, inferred latest commits, repository crawling, or secondary sources. A detected indicator remains a failure if a later identity read changes, while the private build alias is withheld. A clean result requires complete detector output and unchanged build, repository ID, commit, file path, mode, and blob ID. CodeCommit GetFile can transfer up to 6 MiB, but inspection is capped at 1 MiB; larger or non-UTF-8 files yield an incomplete negative.

A CodeCommit-only selection needs no `selected_aws_s3_sources` entry and does not authorize S3 reads. If CodeCommit and S3-backed profiles are selected together, every S3-backed target still needs its exact S3 selector, and extra S3 selectors remain rejected.

```json
{
  "checks": ["aws.review.build_deployment.referenced_source_secret_indicators"],
  "connector": {"provider": "aws", "scopes": ["123456789012/eu-west-1"], "options": {
    "content_secret_scans": true,
    "selected_aws_build_deployment_sources": [{
      "profile": "codebuild_codecommit_source",
      "scope": "123456789012/eu-west-1",
      "build_arn": "arn:aws:codebuild:eu-west-1:123456789012:build/AuditProject:11111111-2222-3333-4444-555555555555",
      "repository_arn": "arn:aws:codecommit:eu-west-1:123456789012:AuditRepo",
      "commit_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "file_path": "/source/config.txt"
    }]
  }}
}
```

The S3 profiles support only objects in the selected account and Region. They do not fetch other Git repositories, HTTP URLs, Amplify `BUCKET_PREFIX` trees, signed artifact URLs, default or relative CodeBuild buildspec paths, CodePipeline source handoff, secondary CodeBuild artifacts, or a build artifact lacking a direct selected object. `ListActionExecutions` pagination is incomplete and therefore UNKNOWN. The two new APIs do not return an S3 object version ID; the selected object is checked with `ExpectedBucketOwner`, ETag conditioned GET, and matching before/after HEAD metadata. A selected native reference and inspected bytes do not prove execution consumed those bytes or that a detected credential works. ZIP inspection is bounded by the existing reader: unsupported members make a negative result UNKNOWN, while a detected indicator remains FAIL.

Official references: [CodeBuild BatchGetBuilds](https://docs.aws.amazon.com/codebuild/latest/APIReference/API_BatchGetBuilds.html), [CodePipeline ListActionExecutions](https://docs.aws.amazon.com/codepipeline/latest/APIReference/API_ListActionExecutions.html), [CodeBuild authorization](https://docs.aws.amazon.com/service-authorization/latest/reference/list_codebuild.html), [CodePipeline authorization](https://docs.aws.amazon.com/service-authorization/latest/reference/list_codepipeline.html), [CodeBuild ProjectSource](https://docs.aws.amazon.com/codebuild/latest/APIReference/API_ProjectSource.html), [CodeBuild Project](https://docs.aws.amazon.com/codebuild/latest/APIReference/API_Project.html), [CodeBuild buildspec storage](https://docs.aws.amazon.com/codebuild/latest/userguide/build-spec-ref.html), [Elastic Beanstalk DescribeApplicationVersions](https://docs.aws.amazon.com/elasticbeanstalk/latest/api/API_DescribeApplicationVersions.html), [Elastic Beanstalk ApplicationVersionDescription](https://docs.aws.amazon.com/elasticbeanstalk/latest/api/API_ApplicationVersionDescription.html), [Amplify GetJob](https://docs.aws.amazon.com/amplify/latest/APIReference/API_GetJob.html), [Amplify JobSummary](https://docs.aws.amazon.com/amplify/latest/APIReference/API_JobSummary.html), [Amplify authorization](https://docs.aws.amazon.com/service-authorization/latest/reference/list_amplify.html), [S3 HeadObject](https://docs.aws.amazon.com/AmazonS3/latest/API/API_HeadObject.html).

Additional CodeCommit references: [Build resolvedSourceVersion](https://docs.aws.amazon.com/codebuild/latest/APIReference/API_Build.html), [CodeCommit GetRepository](https://docs.aws.amazon.com/codecommit/latest/APIReference/API_GetRepository.html), [CodeCommit GetFile](https://docs.aws.amazon.com/codecommit/latest/APIReference/API_GetFile.html), and [CodeCommit repository IAM permissions](https://docs.aws.amazon.com/codecommit/latest/userguide/auth-and-access-control-permissions-reference.html).

This is a source-only additive handoff against the coordinator overlay. The authoritative guarded root remains read-only and requires the release owner's integration. AWS-4 remains partial for other unsupported references; the fixed denominator remains 29.
