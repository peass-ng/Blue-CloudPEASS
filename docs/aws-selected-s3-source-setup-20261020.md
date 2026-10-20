# Selected S3 source secret inspection

The check `aws.review.s3.selected_source_secret_indicators` is registered once in the Secrets group at high severity. It is optional: select that exact check, set `content_secret_scans=true`, and supply `selected_aws_s3_sources`. Category, framework, inventory or collect-all selection alone cannot enable content reads.

Supply one to four exact `{scope, bucket, key, format, version_id?}` entries. `scope` is a selected `ACCOUNT/REGION`; `format` is `text`, `zip`, `tar` or `tar.gz`. Current objects need no versioning. An optional `version_id` selects an already existing version. Selectors cannot contain endpoints, URLs, directory buckets or reference-following instructions.

Provide only the approved read permissions for each selected bucket and exact object: `s3:GetBucketLocation`, plus `s3:GetObject` for current-object HEAD/GET or `s3:GetObjectVersion` for an explicit version. Existing applicable encryption permissions/key policies must already allow the read. No content grant was added to the generated default metadata role, and this feature makes no KMS, restore, session, list, write or credential-verification call. See the [bounded permission contract](aws-selected-s3-source-secret-permissions-20261020.md) for API links and precise limits; that document records the original reviewed proposal.

The production hook verifies native STS account, selected regional bucket, `ExpectedBucketOwner`, and coherent conditional HEAD/GET/HEAD responses. Content and archive members remain in memory, without extraction, execution, nested archive traversal or following scripts/service references. ETag is an opaque condition token, not MD5 or an immutable-object guarantee.

Both pinned offline detectors must finish for PASS. A bound completed detector hit stays FAIL with incomplete coverage if a later step fails; otherwise incomplete or unbound content is UNKNOWN. Native SDK logs are private during explicit content reads and STS calls, with filters restored afterward and other-thread logging preserved. Raw bodies never enter the S3 request cache; detected values and source locators remain hidden in returned evidence.
