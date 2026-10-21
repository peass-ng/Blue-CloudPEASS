# Selected AWS image vulnerabilities

The optional AWS image stage inspects HIGH and CRITICAL package vulnerabilities
in exact immutable private ECR images. A selected Lambda function is resolved to
its current `$LATEST` container image digest, with the function ARN, revision and
resolved digest checked again before and after scanning. This is image evidence,
not proof of execution, reachability or exploitability.

Enable `image_vulnerability_scans`, explicitly select the native check
`aws.review.ecr.selected_image_vulnerabilities`, and supply
`selected_aws_image_vulnerabilities` in connector options. Broad category or
framework selection alone never authorizes an image download. The setting is
independent of `content_secret_scans`: image CVE inspection does not run secret
detectors, and enabling it does not enable content secret scans.

The connector's metadata allowlist can include all of its exact account/region
scopes. Select one to eight targets across at most eight of those scopes; every
metadata scope is still validated for shape and duplicates. Each target has
exactly one of these forms:

```json
{"scope":"123456789012/us-east-1","repository_name":"example/image","image_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
```

```json
{"scope":"123456789012/us-east-1","function_arn":"arn:aws:lambda:us-east-1:123456789012:function:example"}
```

Targets require the same account and region as their scope. Tags, wildcards,
function aliases/qualified versions, image indexes, public registries, external
registries and cross-account image references are unsupported. Supplied selectors
are validated even when scanning is disabled. Organization/account/region
discovery options cannot expand this selected read.

The existing authenticated AWS session is reused. The native reader checks
`sts:GetCallerIdentity`, uses `ecr:BatchGetImage` by exact digest, and obtains
signed regional S3 blob locations with `ecr:GetDownloadUrlForLayer`. Lambda
selection additionally needs `lambda:GetFunction`. No image or function is
executed, no registry authorization token is requested, and no cloud configuration
or credentials are changed. Downloads use the existing regional S3 HTTPS
allowlist, disabled proxies/redirects, byte limits and cancellation checks.

The pinned Trivy runner receives only digest-validated manifest/config/layer
bytes and a native revalidation callback. The existing database lease provisions
or refreshes the public vulnerability database under its bounded worker policy;
the image scan runs offline with database updates disabled and without workload
credentials. Native SDK clients use fixed service endpoints, one attempt, a
three-second connect timeout and a five-second read timeout. A scope has a
1,200-second native reader deadline and at most 128 SDK reads, within the enclosing
scan's shared deadline and request budget. Each layer download is streamed into
an owned regular file in a private directory, with an exact digest/size check,
at most 1 MiB in each read, a 300-second download deadline and reserved free disk.
Partial files are removed on failure; the caller removes the directory afterward.

Practical archive limits apply: a single Linux amd64/arm64 manifest; at most 64
layers; at most 512 MiB per compressed layer and 1 GiB compressed image/config
content; at most 4 GiB expanded content and 200,000 supported tar members. Layer
validation and archive construction use bounded disk streams, including safe
virtual Linux links, without extracting an image onto the host filesystem.
The runner bounds its archive, scratch usage and time separately. Unsupported archives,
missing CLI/database, stale/incomplete scans, failed reads, cleanup failure,
changed native bindings and missing selected targets remain UNKNOWN. They never
become an empty successful image result. Independently proven HIGH/CRITICAL
findings survive incomplete coverage.

When multiple selected assets resolve to the same immutable image in one scope
and database lease, the image is downloaded/scanned once. Only the typed result,
manifest and image proof are retained for reuse. Each Lambda function still gets
independent caller, function revision and resolved-digest revalidation and its own
observation; a changed association remains UNKNOWN. No layer-byte cache accumulates.

Snapshot metadata stages only typed immutable image observations in
`image_vulnerability_scan` for the existing tenant-authorized Images backend.
Native image bytes, function environments, signed URLs, credentials and provider
exception text are excluded from observations, native finding evidence and logs.
The existing runner owns and removes its private temporary archive. A fresh
completed scan is required; historical reports cannot manufacture uncollected CVEs.

The additive native modules require the coordinated finite source admission and
the single grouped check-registration transaction before this route is enabled
in a release. The pure selector validator is safe to import in the lean API.
