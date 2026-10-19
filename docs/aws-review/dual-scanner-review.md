# Independent dual secret scanner review

Reviewed 2026-10-19. Ownership: this worker added only `tests/test_dual_secret_scanning_review.py` and this report; the coordinator implemented scanner, consumer, reporting, grouping and Docker corrections.

Real detection acceptance uses the workspace `.venv` Kingfisher SDK **1.4.0** and installed TruffleHog **3.92.5**. Two deliberately synthetic, high entropy GitHub PAT shapes are used without validation, revocation, cloud calls or real credentials. Assertions check both engine labels, value-level fingerprints, repeated multiline occurrences, distinct values, cross-source/check/asset/Region deduplication, full `evaluate_snapshot` reporting/grouping, compact `finding_summary` grouping, and `publish_report` with in-memory artifacts. Two distinct leak rows survive persisted finding indexes as well as full report/Markdown downloads.

The adapter command is checked for `--no-verification`, `--no-update`, `--no-verification-cache`, `--force-skip-archives` and `--fail-on-scan-errors`. SDK scanning uses `Scanner.scan_input`, with no validation API. Python subprocess probes check deadline/output limits kill and reap children, discard stderr, and omit inherited AWS/GitHub credential variables. Engine absence, errors, timeouts and malformed output cannot establish complete negative evidence; proven positives from the other engine survive. Failed results are retried and successful cache entries retain only redacted metadata.

Defects reported with executable regressions:

- Valid package positives were lost in real reports because an exact `list` type check rejected sealed `FrozenList` data. The coordinator corrected container subclass handling while keeping exact scalar checks; the full report test proves two distinct leak findings across Lambda function/layer inputs and combines the repeated leak's three locations.
- Invalid leak fingerprints passed the package consumer and raised during report deduplication, aborting unrelated results. The coordinator added strict leak validation and conservative malformed-row containment; direct and full report regressions exercise this boundary.
- Detected raw token values survived in caller-provided filenames and cache keys. The coordinator changed cache-key representation and filename redaction; a real scanner regression checks output/cache privacy.
- A follow-up split-detector regression found that per-engine filename redaction can retain the other engine's detected value when the path contains both values. The coordinator changed the cache to retain only the complete outcome after redacting the union of both engines' values; the split-detector output/cache regression now passes.

**Final result: 29 passed, zero failures/errors/skips, in 6.70 seconds.** The coordinator corrected all reproduced scanner/report defects; no worker runtime edits were made. The focused command was:

```sh
.venv/bin/python -m pytest -q tests/test_dual_secret_scanning_review.py --tb=short --junitxml=/tmp/peasso-aws-review-20261019/dual-secret-scanning-review.xml
```

Limits: real engine coverage is limited to two plaintext synthetic GitHub token shapes; it does not establish exhaustive rule recall, credential validity, decoded/composite detector equivalence, nested archive completeness or live cloud collector behavior. Subprocess isolation assertions cover command flags, child lifecycle, stderr and environment; they are not an OS-level network sandbox attestation. No broad suite or Docker build was run by this worker.

Receipt: `/tmp/peasso-aws-review-20261019/dual-secret-scanning-review.xml`; SHA-256 `ca5ffefb6a47807f20db0a3f170588e1dbefac930ea1540f4aba7a61b44e69a2`.

Reviewed source hashes after the final passing run:

- `peaso/secret_scanning.py`: `9d4b5dcbc8feb799bc601ad3f60833192ff9cc59d9a9be4e5c746cf114514338`
- `peaso/secret_findings.py`: `7de03e95c2ddf07ecffc4634e9f5a07fe1d8563439dab844651c92bc382c7784`
- `peaso/finding_groups.py`: `6d6dd6052aa24ca87cc2bfca89bf19893e23739405375bfc4e393b41a81da528`
- `peaso/storage/reports.py`: `2e8432c3c0004dbdb364732e36a0debcdc3e5140d4dc3bb16a018b5abb530d87`
- `peaso/checks/aws_package_content_review_20261019.py`: `9e96307a4a905534018680534bbc151c147ff4f0d1a2c1a959219be69beeb824`
- `peaso/collectors/aws_package_content_indicators.py`: `ce459d4b5ed0ae991591f09f61b462f7841f0977d5935579e561409c0117e7e6`
- `tests/test_dual_secret_scanning_review.py`: `51dbe0cc65abea3721e3403f4e57c8b01b138a967495054dec94c5216b4c16c3`

## EC2 user-data addendum

The existing `aws_cis_ec2_userdata_embedded_secrets` check now accepts optional
Kingfisher/TruffleHog results collected before caching/redaction. This requires
explicitly naming the check and `content_secret_scans=true`; broad selection does
not invoke the engines. The unchanged default uses the existing bounded indicators.
The new SDK-to-snapshot regression uses both real offline engines on a synthetic
GitHub token repeated across two instances and verifies exactly one secret finding,
both detector labels, both locations, and no raw token in cache/snapshot/report.
Incomplete negative and malformed detector coverage remain UNKNOWN.

Focused selection/projection/engine acceptance: **119 passed, zero skips**,
receipt `/tmp/peasso-aws-review-20261019/userdata-dual.xml`. No live EC2 instance
was created or modified. This does not establish exhaustive detector recall;
compressed/binary user-data remains unsupported/UNKNOWN.
