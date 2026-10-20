# AWS Prowler parity review — 2026-10-19

All **662 current AWS source IDs** reconcile: **651 active native lineages** and **11 individually justified exclusions** after the 35 admissions. No absent, duplicate or removed ID remains, and all **16,866** check/framework/control references from **44** compliance files match the manifest. Source lineage is not semantic or runtime certification.

The official [HEAD API](https://api.github.com/repos/prowler-cloud/prowler/commits/HEAD) resolves to **7f9eb2cb11ea931f54acccb6e49152358ccf949d**, committed **2026-10-19T14:00:26Z**. Comparison of complete recursive Git trees found **zero AWS service/compliance blob changes** from the earlier reviewed HEAD `1783527c1147f584f30b60f2d7ccc8a53b4a63b7`. The AWS-only manifest pin has been updated to `7f9eb2cb11ea931f54acccb6e49152358ccf949d`; other providers retain their original pins.

All **662 check evaluators**, 662 metadata files and 44 compliance files were downloaded and Git-blob verified: **1,368 source files, 10,926,502 bytes**, plus the API tree. No clone or upstream execution was needed. The current cache is `/tmp/peasso-aws-review-20261019/prowler/head-20261019-140026`; the previous snapshot is preserved in its parent. One raw evaluator SHA differs from the manifest representation: `ec2_securitygroup_allow_ingress_from_internet_to_any_port_from_ip`. The pinned original and current upstream bytes are identical CRLF text; the manifest parser hashes LF-normalized text. Raw and normalized fingerprints are both retained, and **zero normalized evaluator changes** remain. This is a fingerprint representation difference, not an upstream code change.

| Current disposition | IDs |
|---|---:|
| mapped_predicate_equivalence_unverified | 651 |
| excluded_manual_verified | 3 |
| excluded_customer_configuration | 4 |
| excluded_external_probe | 1 |
| excluded_external_service | 1 |
| excluded_unsound_upstream_predicate | 2 |

The remaining exclusions are three unconditional manual account checks; four customer-approved organization/delegate/golden-PCR comparisons; one anonymous external repository probe; one Shodan integration; and two unsound takeover predicates. Every excluded evaluator was read individually. A legitimate other-account IP/S3 website disproves the Route53 account-nonownership inference; successful HEAD alone does not prove foreign ownership or a service dependency for shadow buckets. None is rejected merely because its input could contain secrets.

The earlier eight configuration/policy gaps, debug-attestation events, sampled object ACLs and content detectors now have active bounded evidence. Optional package/code/log scanning uses real **Kingfisher SDK 1.4.0 + TruffleHog 3.92.5** without credential validation; configuration regex indicators remain narrower. Disabled, denied, truncated or unsupported negative collection remains UNKNOWN. Sampled object ACL evidence cannot establish whole-bucket safety. [AWS GetObjectAcl](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObjectAcl.html) returns ACL metadata, while [Nitro Enclave conditions](https://docs.aws.amazon.com/kms/latest/developerguide/conditions-nitro-enclave.html) support the configuration/attestation distinction.

**574** mapped source IDs have **10,020** exact upstream requirement edges absent from the union of their active native `requirement_controls`. This is a lineage-to-native coverage divergence for individual mapping review, not proof that those requirements should be fully automated. The sibling mapping audit owns that analysis; no broad compliance claims were imported here.

The JSON records every current ID, precise disposition, active predicate/function/line/digests, dependencies, archived references, exact compliance edges and local catalog/collector hashes. `remaining-source-exclusions.json` records the 88 exclusions across all three repositories, resolved admissions, real scanner limits and the archived exact-listening contract. All active source mappings still require the stated semantic and collection-completeness limits; no whole-runtime equivalence claim follows from registration.

Reproduce with:

```sh
.venv/bin/python scripts/audit_aws_prowler_parity.py --cache /tmp/peasso-aws-review-20261019/prowler/head-20261019-140026
```

Add `--fetch` to recheck API HEAD and fill missing bounded files. A changed HEAD requires a new empty cache. Focused parity validation uses `tests/test_aws_prowler_parity_review.py`, `tests/test_aws_steampipe_parity_review.py` and `tests/test_aws_current_source_parity_review.py`; no live cloud call, build, deployment or full suite was run.

Directed parity validation: **21 tests passed**, zero failures, errors or skips; receipt `/tmp/peasso-aws-review-20261019/current-parity-tests.xml`.

Final source-association acceptance: zero unresolved edges after 13 bounded PARTIAL signal additions and nine explicit decisions to retain existing membership. See `requirement-associations.json`.

Final source-association acceptance: zero unresolved edges after 13 bounded PARTIAL signal additions and nine explicit decisions to retain existing membership. See `requirement-associations.json`.

Final source-association acceptance: zero unresolved edges after 13 bounded PARTIAL signal additions and nine explicit decisions to retain existing membership. See `requirement-associations.json`.
