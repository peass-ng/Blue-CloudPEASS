# Python CI runtime study (2026-10-22)

## Before

Public [Actions run 39678899809](https://github.com/peass-ng/PEASSo-CSPM/actions/runs/39678899809) spent 1 minute 55 seconds on the isolated performance gate, then 3 minutes 31 seconds starting and collecting the Python suite. The suite ran for another 29 minutes 35 seconds and reached 78% before cancellation at 33 minutes 6 seconds into that step. The parallel frontend job completed in 7 minutes 25 seconds. Another [run 39663360220](https://github.com/peass-ng/PEASSo-CSPM/actions/runs/39663360220) was cancelled after its Python suite had run 37 minutes 44 seconds. These are partial runs, so they do not establish a completed baseline time.

## Change and coverage

The workflow now starts eight independent Python suite jobs with `fail-fast: false` and retains a single aggregate `Python test suite` check. Each job performs the existing pinned tool and source setup, runs the same pytest options and skip gate, and receives one file shard. Shard zero also runs the original isolated performance gate and performance skip gate. The frontend job is unchanged.

`scripts/pytest_shard.py` enumerates both pytest default file patterns under `tests/`, sorts files by source size, and assigns each whole file to the currently lightest shard. It invokes pytest with `tests` as the collection root and `--ignore` for every other shard's files, retaining the existing `tests/conftest.py` source-admission and draft-isolation hooks. The performance module and the two 10,000-principal cases remain solely in the isolated gate. Eight `--verify` invocations on rebased `main` assigned all 1,889 matching files exactly once, with 234–237 files and 2,219,975–2,220,498 source bytes per shard. No test body or production evaluator changed.

## After measurements and remaining validation

A collection-only run of shard zero on rebased `main`, using Python 3.12, collected 16,052 real cases in 81.36 seconds wall time (pytest reported 58.55 seconds). This is a local collection measurement, not a comparable hosted end-to-end duration. `actionlint` passed, and the directed workflow assertion passed. The exact-byte source epoch test passed before rebasing, but on rebased `main` it fails on `docs/compliance-ledgers/descriptions/accepted-base-corrections-20261019.json`, a file unchanged by this patch and identical to `origin/main`; that release baseline failure was reported to the coordinator. The coordinator owns the finite-history test correction, so this branch leaves that file unchanged.

For the coordinator's exact finite-history successor, the new `.github/workflows/tests.yml` is 10,915 bytes with SHA-256 `d8efd15e5098580412f2a2697cee43a7ea8e6bbcda1d094912b2481a70e8cddd` (prior epoch `9037ba9dac836655384bbb0d19370609cfd16098f314cf49c8634ab560bec2eb`). The new `tests/test_privesc_sync.py` is 21,340 bytes with SHA-256 `1b2d924d6c5333222add3101288dc0fb58afb3c23317bb450b482be3ccdc0e2d` (prior epoch `d0d5c0fa2f9c76d82eb335d0dc33c9c4672f2ab31aa8d4c72d9ff2399e96e0e3`). The original epoch manifest and prior hashes are unchanged.

The 5–10 minute end-to-end target remains unverified until this branch runs in Actions. Eight shards should reduce Python test execution contention, while the existing frontend job already takes about 7 minutes; queue time, uneven per-file test cost, and the current release baseline failure can still prevent a trustworthy complete result within 10 minutes. No broad suite or new Actions run was launched for profiling.
