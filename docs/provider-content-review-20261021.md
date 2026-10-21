# Selected content review — 21 October 2026

This batch extends explicitly selected content inspection. It does not certify all runtime behavior, repository history, binary contents, or live cloud access. Optional content and image scans require their named selections and additional read permissions documented with each reader.

## Reviewed native response contracts

- Databricks workspace FILE: `object_id`, `modified_at`, `size` and optional `resource_id` are documented ObjectInfo fields. The reader requires stable status before/after RAW export; missing optional metadata leaves incomplete evidence. [Workspace get-status](https://docs.databricks.com/api/workspace-files/v1/get-status).
- EMR Serverless: a selected job attempt is read with `GetJobRun(applicationId, jobRunId, attempt)`. The collector binds the returned ARN, attempt and exact Spark/Hive source URI. [GetJobRun](https://docs.aws.amazon.com/emr-serverless/latest/APIReference/API_GetJobRun.html).
- SageMaker HyperPod: the selected instance group lifecycle source binds `SourceS3Uri` and `OnCreate` or `OnInitComplete`. These are source declarations; they do not prove execution. [DescribeCluster](https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_DescribeCluster.html).

## Evidence rules

A finding describes verified selected bytes in one or two direct sentences. Secret values are hidden in ordinary findings; detector results merge by the same secret fingerprint. Known supported positives remain findings when unrelated coverage is incomplete. A clean result requires complete supported content, detector and association evidence. Missing, denied, changed or unsupported evidence is UNKNOWN.

Image findings refer to immutable declared image digests. A declared image is not proof of running process bytes. Trivy clean results require a complete package scan and a fresh database; HIGH/CRITICAL positives can remain useful with incomplete unrelated coverage.

## Validation boundaries

Offline native-response, SDK Stubber, parser and real-detector synthetic tests are recorded separately. They are not live cloud certification. The final composed registry/compiler, API packaging and hosted acceptance remain release gates; this draft does not assert that they passed.
