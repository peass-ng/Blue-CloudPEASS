# Integrated selected inline CodeBuild buildspec control

`aws.review.codebuild.selected_inline_buildspec_secret_indicators` is registered for AWS under the existing Secrets group, with kind `codebuild_selected_inline_buildspec`, exposure category and high severity. It depends on `aws_account` and that selected-content kind. Both offline detectors inspect only the returned inline buildspec; a supported hit is FAIL even with incomplete detector coverage, a clean complete scan is PASS, and references or incomplete/unbound source are UNKNOWN.

The public request needs the exact named check, `content_secret_scans: true`, and one to eight exact project selectors in one to four explicit account/region scopes:

```json
{
  "checks": ["aws.review.codebuild.selected_inline_buildspec_secret_indicators"],
  "connector": {
    "provider": "aws",
    "scopes": ["123456789012/us-east-1"],
    "auth": {"method": "access_keys"},
    "options": {
      "content_secret_scans": true,
      "selected_aws_codebuild_inline_buildspecs": [{
        "scope": "123456789012/us-east-1",
        "project_arn": "arn:aws:codebuild:us-east-1:123456789012:project/AuditProject"
      }]
    }
  }
}
```

Use the connector's separately configured authentication. The public API does not accept the private runtime grant or the standalone proposal's `check_id`/`content_secret_scan_grants` fields. Engine selection issues an opaque process-local pre-auth capability bound to exact selectors and scopes; the collector consumes it. Default, category, framework, inventory-kind and serialized fake-grant selection cannot grant this optional read. A content-only unauthorized plan returns unavailable coverage without resolving credentials.

Only `codebuild:BatchGetProjects` is needed for source content, scoped to the selected project ARN; no default customer role is expanded by this integration. The existing caller bootstrap and the bounded producer read regional STS `GetCallerIdentity` to verify account, partition and principal consistency. The engine retains normal AWS scope/resource envelopes, while capture and request locators are opaque. The consumer uses only JSON-portable snapshot facts and can replay in another process without a local seal.

The original 40-case proposal producer, consumer and tests are unchanged. The adapter executes the original producer code with an explicit package-only readiness binding, union-aware scanner callback and budget/cancellation wrapper. It reads only `projects[0].source.buildspec`, checks returned project identity, and uses the original conservative inline-version recognizer. Paths, default/empty buildspecs, S3 references, alternate YAML/JSON layouts and build overrides are not resolved or executed. The producer remains bounded to eight projects, four scopes, twelve native producer calls, 256 KiB inline bytes, 2 MiB per allocated SDK response, 4 MiB aggregate accepted response bytes, and a cooperative 90-second deadline, with existing scan call/resource/deadline/cancellation limits also enforced. SDK response allocation and SDK-managed authentication are outside a hard transport-memory/process-lifetime guarantee.

Real detector values become the existing union of HMAC/length descriptors, including the common textual encodings. Before any older reader clears its match set, the adapter retains the shared descriptors, then scrubs all returned inventory, metadata, mutable options, cache aliases and cache keys before global cleanup. It never manufactures detector parts or substitutes evidence. Public correlation remains the existing value fingerprint deduplicator. Kingfisher 1.4.0 performs detection only; TruffleHog 3.92.5 runs with credential verification and updates disabled.

Source guard succession is explicit. Exact original main/guard/helper/receipt bytes are packaged in `aws_codebuild_buildspec_runtime_predecessors_20261020.json.gz`; the current successor reconstructs the old three engine/validation function bodies and AWS collector body by removing only the exact new CodeBuild additions. The old Workbench/Dataflow/K8s and S3 helper/receipt files remain unchanged. The existing Dataflow admission still verifies its original 119 executing functions and eighteen imported identity pairs, through the explicitly admitted shared entrypoint. Registration of the shared wave and this new control is transactional and idempotent. Runtime admission reads package data only; copied-package replay succeeds without repository docs or test source, with the four existing Azure namespace data files that are already part of the distribution.

Finite acceptance evidence is in `aws-codebuild-buildspec-runtime-integration-20261020.json`. The owned runtime/current-guard nodes passed 36 tests, plus one added signed native SDK HTTP/parser, real dual-detector and private-DEBUG node; focused affected producer/GCP/K8s/S3 nodes passed 105 tests. One preserved historical proposal assertion that the check is unregistered is explicitly superseded by this integration and was deselected; its file bytes remain unchanged. The current-source baseline/tamper/restored tests replace no historical tests and do not infer negative coverage from an already failing old guard.

Actual engine-derived PASS, FAIL, UNKNOWN, malformed and partial-positive facts are packaged in `peaso/checks/aws_codebuild_buildspec_runtime_cases_20261020.json`; the actual public DTOs are in `aws-codebuild-buildspec-runtime-public-native-20261020.json`. No cloud call, live authentication, build, commit, push or deployment was performed. Root owns canonical/materialized metadata, product prose, frontend and final distribution checks; this worker owns only the four explicitly listed shared source files and the new integration artifacts.
