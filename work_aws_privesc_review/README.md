# AWS privilege escalation review status

`technique-status.tsv` is the working record for the current AWS catalog. It has exactly one row for every active AWS technique. `checked` records an individual review of its AWS operation, permissions, target relationship, and evaluator behavior. Exact passing positive, negative, and unknown cases are recorded separately in `route-case-coverage.tsv`; a catalog review does not imply those cases all pass. `checked_previous` means the technique appeared in an earlier individual review but later changes need revalidation. `pending` means no individual review is documented for that active ID.

`verification-status.tsv` tracks validation separately from that catalog review. It has one row per active technique with review evidence, external proof dependencies, test references, the full-suite gate, and exact remaining case gaps from `route-case-coverage.tsv`. Generate it with `python3 work_aws_privesc_review/build_verification_status.py`. All 220 active techniques have a located test file, but a file reference alone does not establish an exact positive or negative case. `external_proof_route=yes` means at least one route reads externally supplied `aws_privesc_challenge_evidence`; it does not establish that every route for that technique requires it. `static-parity-source-drift.tsv` must remain empty.

After all 19 final pytest shards finish, run `python3 work_aws_privesc_review/build_final_suite_result.py /path/to/junit-directory`, then regenerate `verification-status.tsv` and `WORKLOG.md`. The suite result file records each JUnit report's hash and counts. Its global pass or failure state is not per-technique proof; the case ledger retains each technique's specific test evidence and gaps.

After reviewing a technique in the current catalog, update its row with `checked` and concise evidence. When the catalog changes, add or remove rows to match its active AWS IDs. Run `python work_aws_privesc_review/status.py` before reporting counts or remaining work; it rejects missing, duplicate, and stale IDs. Its reviewed total includes `checked` and `checked_previous`, while current sign-off is reported separately.

Cross-cutting fixes do not count as individual sign-off. The active AWS catalog resource requirements use `{source.partition}` so a grant in GovCloud or China is not tested against a commercial-partition ARN. The EKS admin-policy request context resolves the same partition. The catalog-wide invariant and representative IAM and EKS regressions are in `tests/test_peaso_privesc_schema_ext.py`.

## Recovery review

`retired-technique-status.tsv` fixes the cohort of 362 IDs that were active in HackTricks Cloud at revision `47c375ae49` and were removed from the executable YAML at `3a88bec50b`. Each row records its old source, target kind and current exclusion entry. `page-status.tsv` lists every Markdown page under the AWS privilege escalation section. A `triaged` row has only an initial classification; it is not signed off. `excluded_verified` requires a documented reason why the path is not represented as a definite automatic principal edge, including any missing resource, trust, or execution witness. It does not assert the attack can never exist. `implemented` requires a catalog route with recorded review and tests.

`candidate` is unresolved. It records a plausible route or credential chain that still needs an exact principal, resource, permission, and execution join. A candidate is neither implemented nor safely excluded.

Run `python work_aws_privesc_review/retired_status.py --book-root /path/to/hacktricks-cloud` to validate the cohorts and print progress. Keep the full 362-row cohort even when an ID is restored, so its review remains auditable.
