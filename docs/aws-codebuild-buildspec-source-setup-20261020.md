# Selected inline CodeBuild buildspec proposal

This local proposal adds `aws.review.codebuild.selected_inline_buildspec_secret_indicators` in the existing **Secrets** group. Both offline detectors inspect only returned inline buildspec bytes for an exact selected CodeBuild project. A supported secret produces FAIL even if the other detector is unavailable; PASS requires complete selected coverage, and references or incomplete evidence produce UNKNOWN.

Nothing imports this proposal into the engine, registers its declaration, changes connector validation, or changes customer roles. The existing selected configuration collector continues to cover CodeBuild environment literals and excludes buildspec content. Production integration and any public UI or engine acceptance remain separate work.

## Explicit authorization before authentication

An adapter must call `prepare(options, scopes)` before constructing credentials or SDK sessions. It requires the exact check ID, `content_secret_scans: true`, and the named grant `aws-codebuild-selected-inline-buildspec-v1`; a selected ARN alone grants nothing. A process-local sealed plan rejects changed selectors, scopes, bounds, helpers and reviewed source before `session_factory(scope)` is called.

```python
from peaso.collectors import aws_codebuild_buildspec_source_20261020 as source
from peaso.checks import aws_codebuild_buildspec_source_20261020 as check

scope = "123456789012/us-east-1"
options = {
    "check_id": source.CHECK,
    "content_secret_scans": True,
    "content_secret_scan_grants": [source.GRANT],
    source.OPTION: [{
        "scope": scope,
        "project_arn": "arn:aws:codebuild:us-east-1:123456789012:project/AuditProject",
    }],
}
plan = source.prepare(options, [scope])  # no auth or cloud calls
# A future authorized adapter supplies its pinned SDK session factory here.
# collection = source.collect(plan, authorized_session_factory)
# results = [check.evaluate(row, collection) for row in collection["items"]]
```

For a future authorized run, grant only the read action on the exact selected project ARN; this document does not apply the grant:

```json
{
  "Effect": "Allow",
  "Action": "codebuild:BatchGetProjects",
  "Resource": "arn:aws:codebuild:us-east-1:123456789012:project/AuditProject"
}
```

The producer also calls regional STS `GetCallerIdentity` to bind the session to the selected account and partition. This identity bootstrap does not require an IAM allow grant. The factory must return the authorized session for that scope; default auth discovery is not implemented by this proposal.

## Coverage and bounds

The producer issues one `BatchGetProjects(names=[exact_project_arn])` per selection. It verifies returned project ARN and name, empty `projectsNotFound`, source type and the actual `projects[0].source.buildspec` field. Only inline content beginning with a recognizable YAML `version: 0.1` or `version: 0.2` line, allowing a BOM, comments and a document start, is scanned as original UTF-8 bytes. This deliberately conservative recognizer returns UNKNOWN for JSON/flow syntax, other valid YAML layouts, unsupported versions, empty/default buildspecs, relative paths, S3 URIs and S3 ARNs; references are never followed or scanned as source. No YAML expansion or build execution occurs, and runtime build overrides, repositories, secondary sources, environment configuration, secret references and executed build behavior are outside this control.

Limits are eight projects, four scopes, twelve calls including identity reads, 256 KiB inline bytes per project, 2 MiB per allocated SDK response, 4 MiB aggregate response bytes, 128 leaks and 512 locations per project, and a 90-second cooperative collection deadline. SDK retry count is one total attempt and fixed official regional HTTPS endpoints are checked; connect/read timeouts are each at most three seconds and each detector receives at most fifteen seconds. SDK response allocation, factory/auth internals, SDK parsing and Kingfisher lock contention precede or can outlive cooperative checks, so the deadline and byte limits do not constitute a hard transport-memory or process-lifetime guarantee. A supervising adapter must impose a process deadline for that stronger guarantee.

Public results retain only opaque HMAC locators, safe counts, engine identities, field provenance and redacted findings. Provider metadata, error text, project names/ARNs, source text, request paths, caller names and credentials are not copied into results. Kingfisher 1.4.0 uses detection only; TruffleHog 3.92.5 uses `--no-verification`, `--no-update` and no verification cache. Neither validates or revokes credentials. Existing `merge_leaks` and `deduplicate_secret_findings` correlate the same secret across detectors and selected projects within the process.

The consumer is pure and validates supplied provenance/shape; it does not authenticate arbitrary externally supplied snapshots. Source hashes and loaded-function proofs detect accidental code/helper drift before authentication and again before publishing; they are local review evidence, not a signature or a defense against a hostile Python process or edited receipt.

## Local proof and references

Run only the directed proof:

```sh
.venv/bin/python -m pytest -q tests/test_aws_codebuild_buildspec_source_20261020.py
```

Tests use botocore Stubber with explicit dummy credentials and network denial, through the actual SDK operation and request serializer, plus installed real Kingfisher and TruffleHog. No cloud read, credential discovery, build, write, commit or deployment is part of this proof. Stubber does not exercise a live signed HTTP request; transport reachability, deployed IAM and production integration remain unverified.

Primary AWS references browsed on 2026-10-20:

- [BatchGetProjects API](https://docs.aws.amazon.com/codebuild/latest/APIReference/API_BatchGetProjects.html): selected names or ARNs, returned projects and missing projects.
- [ProjectSource API](https://docs.aws.amazon.com/codebuild/latest/APIReference/API_ProjectSource.html): inline definition versus relative path or S3 ARN and empty/default semantics.
- [Buildspec reference](https://docs.aws.amazon.com/codebuild/latest/userguide/build-spec-ref.html): YAML syntax and project source file location.
- [CodeBuild permissions reference](https://docs.aws.amazon.com/codebuild/latest/userguide/auth-and-access-control-permissions-reference.html): `codebuild:BatchGetProjects` scoped to a project ARN.
- [STS GetCallerIdentity API](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html): caller identity and no permission requirement.

The source-bound receipt is `docs/check-review/aws-codebuild-buildspec-source-20261020.json`. It records all newly authored source/guide hashes, relevant unchanged helper hashes, executing callable proofs and primary references; regenerate review evidence after any change rather than weakening source checks.
