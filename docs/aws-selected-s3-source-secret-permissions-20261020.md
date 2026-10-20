# Optional selected S3 source secret inspection

This unregistered proposal reads only one to four explicitly selected objects when `content_secret_scans=true` and the named check `aws.review.s3.selected_source_secret_indicators` is selected. Root must integrate the reviewed Requests profile and selector validation before enabling it. Ordinary inventory must exclude `s3_selected_source_content`.

Use `selected_aws_s3_sources` entries containing `scope` (`ACCOUNT/REGION`), `bucket`, `key`, `format` (`text`, `zip`, `tar`, or `tar.gz`) and optionally `version_id`. The account must match the authenticated STS caller and the bucket's native Region must match the selected Region. Current objects require no versioning. A version selector refers to an already existing version; it does not enable versioning or create a snapshot.

Grant only the approved reader access to the selected bucket and exact object ARN(s):

- `s3:GetBucketLocation` on the selected bucket ARN.
- `s3:GetObject` on each exact object ARN for current-object HEAD and GET.
- `s3:GetObjectVersion` instead for explicit-version HEAD and GET; optionally constrain `s3:VersionId` to the selected existing version.
- Existing encryption permissions and key policies must already permit the read. AWS documents `kms:Decrypt` and `kms:GenerateDataKey` for SSE-KMS GetObject. This reader grants nothing and calls no KMS decrypt or key-content operation. It does not request checksum mode.

STS `GetCallerIdentity` supplies the native account/principal proof and requires no IAM allow. ARM/Azure permissions are irrelevant. No ListBucket, ListObjects, ListObjectVersions, write, restore, session, ACL, policy, key retrieval or credential-verification permission is requested. Without ListBucket, a missing object may return 403; it remains UNKNOWN rather than being classified as absent or clean.

Each target uses at most five native operations: STS GetCallerIdentity, S3 GetBucketLocation, HeadObject, GetObject with `IfMatch`, and a second conditional HeadObject. Every S3 read includes `ExpectedBucketOwner`. GET and both HEAD responses must agree on opaque ETag, length and optional version. ETag is not treated as MD5 or proof of immutability; an unversioned object can change after inspection or undergo undetectable same-ETag changes. A later mismatch makes coverage incomplete and cannot erase an already bound completed detector hit.

Only standard commercial AWS regional endpoints are admitted; configured/custom endpoints, GovCloud/China/isolated partitions, directory buckets, access points, Object Lambda, Outposts, requester-pays and SSE-C are unsupported. The reader never follows download URLs, scripts or service references and makes no deployment association claim.

Content stays in memory. Limits are four targets, 20 native calls, 2 MiB per response/object, 8 MiB total wire data, 256 KiB per text member, 64 archive entries per object, 128 entries total, 4 MiB expanded per archive, 8 MiB total expanded data, expansion ratio 100, and 120 seconds within any shorter caller deadline. Reads use bounded chunks and remaining-time socket timeouts. Both streams and temporary SDK HTTP wrappers close in `finally` blocks.

ZIP supports regular stored/deflate members without comments, extra fields, encryption or appended data. TAR supports regular files and directories; gzip must contain exactly one complete stream. Links, sparse members, unsafe paths, duplicate names, nested archives, binary/unreadable members and exhausted limits prevent a clean result. Nothing is extracted or executed.

Pinned offline Kingfisher 1.4.0 and TruffleHog 3.92.5 run without verification. Both must complete for PASS. A completed detector's bound hit remains FAIL with `complete=false` when later coverage fails; otherwise incomplete coverage is UNKNOWN. Output uses HMAC fingerprints and opaque locations, merges the same value across engines and members, and scrubs discovered values from metadata and retained cache aliases. Raw content, values, object keys and authentication headers are not evidence. The standalone `peaso.collectors.aws_content_sdk_logging.private_sdk_logs` context suppresses native SDK auth/content DEBUG records only on the selected-read thread, then restores its filters; other threads retain their logging.

Official contracts reviewed on 2026-10-20: [GetObject](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObject.html), [HeadObject](https://docs.aws.amazon.com/AmazonS3/latest/API/API_HeadObject.html), [GetBucketLocation](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketLocation.html), and [GetCallerIdentity](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html).
