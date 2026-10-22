# AWS privilege escalation review status

`technique-status.tsv` is the working record for the current AWS catalog. It has exactly one row for every active AWS technique. `checked` means its AWS operation, required permissions, target relationship, evaluator behavior, and a positive and negative case have been reviewed in the current catalog. `checked_previous` means the technique appeared in the documented earlier individual catalog review, but later changes still need revalidation. `pending` means no individual review is documented for that active ID. General catalog tests alone do not change a row's status.

After reviewing a technique in the current catalog, update its row with `checked` and concise evidence. When the catalog changes, add or remove rows to match its active AWS IDs. Run `python work_aws_privesc_review/status.py` before reporting counts or remaining work; it rejects missing, duplicate, and stale IDs. Its reviewed total includes `checked` and `checked_previous`, while current sign-off is reported separately.

Cross-cutting fixes do not count as individual sign-off. The active AWS catalog resource requirements use `{source.partition}` so a grant in GovCloud or China is not tested against a commercial-partition ARN. The EKS admin-policy request context resolves the same partition. The catalog-wide invariant and representative IAM and EKS regressions are in `tests/test_peaso_privesc_schema_ext.py`.

## Recovery review

`retired-technique-status.tsv` fixes the cohort of 362 IDs that were active in HackTricks Cloud at revision `47c375ae49` and were removed from the executable YAML at `3a88bec50b`. Each row records its old source, target kind and current exclusion entry. `page-status.tsv` lists every Markdown page under the AWS privilege escalation section. A `triaged` row has only an initial classification; it is not signed off. `excluded_verified` requires a documented reason that the path cannot produce another AWS principal's permissions, while `implemented` requires an exact working catalog route and positive and negative tests.

`candidate` is unresolved. It records a plausible route or credential chain that still needs an exact principal, resource, permission, and execution join. A candidate is neither implemented nor safely excluded.

Run `python work_aws_privesc_review/retired_status.py --book-root /path/to/hacktricks-cloud` to validate the cohorts and print progress. Keep the full 362-row cohort even when an ID is restored, so its review remains auditable.
