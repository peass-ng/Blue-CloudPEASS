# AWS native contract review — 2026-10-19

The authoritative [per-ID ledger](native-contracts.json) contains 1,556 registered AWS definitions: 1,404 active and 152 archived. Every registered callback executed in a passing mocked test and every active ID has a PASS witness. There are 611 registered definitions with directed runtime cases in this receipt set. This establishes recorded invocation and bounded behavior, not exhaustive semantics or live certification.

The latest AWS-only gate recorded 10,638 passed, 34 failed and one skipped. All 34 failed nodes subsequently passed explicit directed rechecks. The original failures and the 64-case final recheck remain under `/tmp/peasso-aws-review-20261019/final-aws-acceptance/`; 17 cases additionally test the updated IAM parser. A consolidated current SDK-to-registered-evaluator batch passed 1,205 cases. Eight optional Lambda public-pipeline tests separately exercised both real offline secret detectors on synthetic content.

The ledger merges those receipts with explicitly retained older directed supplements: 12,885 passing test nodes, one skipped, zero unresolved failed nodes. This merged total is not one fresh suite against one frozen tree. Its receipts and source hashes remain visible.

The skipped partial-dependency mutation for `aws_nist_config_enabled_all_regions` has no dependency envelopes in its historical positive fixture; directed native Config successor tests cover that contract. Nine active IDs lack an observed FAIL in this selected set; actual UNKNOWN/MANUAL or applicability expectations remain explicit rather than artificial failures.

The ledger records callback hashes, dependencies, invocation nodes, statuses, uncertainty probes and known field gaps. Its blockers list is empty. [Field producers](field-producers.json) credits 56 native-shape and 235 derived-producer rows, with 1,113 remaining witness-only under its stricter accessor proof rules. Those are evidence limits, not a count of missing implementations. See the [review index](README.md) and [latest acceptance](latest-acceptance.json) for source accounting, mapping, live smoke scope and publication limits.
