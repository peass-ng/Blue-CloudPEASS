# Selected AWS workload referenced source review

The new `aws.review.workload.referenced_source_secret_indicators` check is off by default. A scan must name it, set `content_secret_scans: true`, select at most four exact workload references in `selected_aws_workload_sources`, and list the matching exact S3 objects in `selected_aws_s3_sources`. The native workload describe call runs before and after the S3 read; both must bind the same selected reference. The shared S3 profile then checks caller account, bucket Region, `ExpectedBucketOwner`, and HEAD → ETag conditioned GET → conditioned HEAD with matching version, length, and ETag. The S3 grant is transient, scoped to the selected session and the native bound object. An extra S3 object is rejected when only this named check authorizes S3 access. Naming the existing independent S3 check separately permits its own selections.

Example selection for a Glue script:

```json
{
  "checks": ["aws.review.workload.referenced_source_secret_indicators"],
  "connector": {
    "provider": "aws",
    "scopes": ["123456789012/us-east-1"],
    "options": {
      "content_secret_scans": true,
      "selected_aws_workload_sources": [{
        "profile": "glue_script",
        "scope": "123456789012/us-east-1",
        "job_name": "AuditJob",
        "source_s3_uri": "s3://selected-source-bucket/jobs/audit.py"
      }],
      "selected_aws_s3_sources": [{
        "scope": "123456789012/us-east-1",
        "bucket": "selected-source-bucket",
        "key": "jobs/audit.py",
        "format": "text"
      }]
    }
  }
}
```

Supported native references:

| Profile | Exact native read and field | Selected identity | S3 format |
| --- | --- | --- | --- |
| `glue_script` | Glue `GetJob.Job.Command.ScriptLocation` | job name and returned `LastModifiedOn` | text |
| `emr_serverless_spark` | EMR Serverless `GetJobRun.jobRun.jobDriver.sparkSubmit.entryPoint` | job run ARN and explicit attempt | text |
| `emr_serverless_spark_jar` | Same Spark entry point, when it names a JAR | job run ARN and explicit attempt | zip |
| `emr_serverless_hive` | `GetJobRun.jobRun.jobDriver.hive.query` | job run ARN and explicit attempt | text |
| `emr_serverless_hive_init` | `GetJobRun.jobRun.jobDriver.hive.initQueryFile` | job run ARN and explicit attempt | text |
| `emr_step_jar` | EMR `DescribeStep.Step.Config.Jar` | cluster ID and returned step ID | zip |
| `sagemaker_hyperpod_lifecycle` | SageMaker `DescribeCluster.InstanceGroups[*].LifeCycleConfig.SourceS3Uri` plus `OnCreate` or `OnInitComplete` filename | cluster ARN and unique instance group | text |
| `sagemaker_training_script` | SageMaker `DescribeTrainingJob.HyperParameters.sagemaker_submit_directory` plus `sagemaker_program` | exact selected training-job ARN/name, creation time, job status, source archive, and entry program before and after the S3 read | tar.gz with selected `.py` member |

For `sagemaker_training_script`, select `training_job_arn`, `source_s3_uri` ending in `.tar.gz`, and `program` naming a relative `.py` member such as `entry_point/train.py`. The `selected_aws_s3_sources` object must name the same bucket and key with `format: tar.gz`. The hyperparameter values may be direct strings or JSON-encoded strings, as emitted by supported script-mode callers; both must decode to the exact selection. The entry program must appear as a completely inspected archive member for a clean PASS. A likely secret in any supported archive member remains FAIL even when later metadata changes.

The scanner principal needs the selected native read action: `glue:GetJob` on the job ARN; `emr-serverless:GetJobRun` on the job run ARN; `elasticmapreduce:DescribeStep` on the cluster ARN; `sagemaker:DescribeCluster` on the cluster ARN; or `sagemaker:DescribeTrainingJob` on the selected training-job ARN. It also needs `s3:GetBucketLocation` on the selected bucket ARN and `s3:GetObject` on the selected object ARN. S3 `HeadObject` uses `s3:GetObject`, with no separate IAM action. `sts:GetCallerIdentity` is called for identity binding and requires no IAM permission. SSE-KMS objects may require `kms:Decrypt` on the selected key. This adapter selects the current S3 object; the existing S3 reader compares any returned version ID across HEAD/GET/HEAD but this adapter does not select a historical version. No list, job execution, secret-store, cloud write, or generic S3 read permission is introduced by code.

The source association is a declaration: it does not establish that a job loaded these bytes or that a detected credential works. A JAR or TAR with unsupported binary members can produce a positive FAIL when a supported text member contains a likely secret; a clean result with uninspected members stays UNKNOWN. HyperPod lifecycle sources require the documented `sagemaker-` bucket prefix. SageMaker training `InputDataConfig` and processing `ProcessingInput.S3Uri` describe data inputs; `TrainingImage` names a container image. These fields do not establish a script-mode source archive. Local paths, HTTP URLs, absent hyperparameters, missing entry members, and other archive formats remain UNKNOWN.

Official references: [SageMaker DescribeTrainingJob](https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_DescribeTrainingJob.html), [AWS script-mode Boto3 example](https://docs.aws.amazon.com/sagemaker/latest/dg/debugger-built-in-rules-api.Boto3.html), [AWS script-mode CLI example](https://docs.aws.amazon.com/sagemaker/latest/dg/debugger-built-in-rules-api.CLI.html), [SageMaker SDK script constants](https://sagemaker.readthedocs.io/en/v3.8.0/api/generated/sagemaker.core.constants.html), [Glue JobCommand](https://docs.aws.amazon.com/glue/latest/webapi/API_JobCommand.html), [EMR Serverless SparkSubmit](https://docs.aws.amazon.com/emr-serverless/latest/APIReference/API_SparkSubmit.html), [EMR Serverless Hive](https://docs.aws.amazon.com/emr/latest/EMR-Serverless-UserGuide/jobs-hive.html), [EMR StepConfig](https://docs.aws.amazon.com/emr/latest/APIReference/API_StepConfig.html), [EMR Step output](https://docs.aws.amazon.com/emr/latest/APIReference/API_Step.html), [SageMaker HyperPod lifecycle](https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_ClusterLifeCycleConfig.html), [SageMaker DescribeCluster](https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_DescribeCluster.html), [SageMaker ProcessingS3Input](https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_ProcessingS3Input.html), [S3 HeadObject](https://docs.aws.amazon.com/AmazonS3/latest/API/API_HeadObject.html), and [STS GetCallerIdentity](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html). AWS service authorization tables document resource types for [Glue](https://docs.aws.amazon.com/es_es/service-authorization/latest/reference/list_awsglue.html), [EMR Serverless](https://docs.aws.amazon.com/es_es/service-authorization/latest/reference/list_amazonemrserverless.html), [EMR](https://docs.aws.amazon.com/fr_fr/service-authorization/latest/reference/list_amazonelasticmapreduce.html), and [SageMaker](https://docs.aws.amazon.com/service-authorization/latest/reference/list_sagemaker.html).

This source-only handoff is based on the coordinator overlay and needs guarded root integration. AWS-5 remains partial for other workload reference families and unsupported SageMaker Processing job source inference. The fixed technical group denominator remains 29.
