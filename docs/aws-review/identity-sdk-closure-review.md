# Identity SDK closure — 2026-10-19

The [per-ID report](identity-sdk-closure-review.json) accounts for the exact **169 previously unproved IDs**. Independent botocore-validated responses now run through **Requests → public `aws.collect` → registered engine evaluators** for **105 IDs**; 64 CloudTrail, KMS, Secrets Manager and Organizations rows remain outside this executed identity cohort. No fixture documents or handmade collection indexes establish these new contracts.

**Validation: 412 distinct tests passed**: 411 public SDK/gate cases in 40.27 seconds and one report-integrity case in 0.36 seconds. Two targeted setup-date rechecks refined the inactive-key case without changing the expected verdict. There were no live AWS calls, resource configuration changes, credential validation or new check IDs; existing UI groups and evidence prose were preserved.

| Evidence | Result |
|---|---:|
| Input IDs accounted for | 169 |
| IDs with new public native contracts | 105 |
| IDs with observed positive and negative outcomes | 103 |
| Field observations reviewed | 2,166 |
| Field observations emitted through public SDK collection | 749 |
| Required-accessor observations with emitted SDK paths | 692 |
| Earlier exact-path uncertainties in the executed cohort | 36 |
| Those uncertainties resolved by emitted native fields | 16 |
| Those uncertainties resolved by the actual alternative branch | 12 |
| Unvisited exact-path branches in the executed cohort | 8 |
| Remaining exact-path uncertainties across all 169 IDs | 143 |

Emission receipts identify the SDK operation/member or explicit transformation, public snapshot path, producer function, observed type, scenario and callback outcomes. A parsed policy child, CSV column, collection status or derived identity alias is distinguished from a direct botocore structure member. **No row claims complete semantic verification.**

## Corrected public producer contracts

Public collection previously accepted a foreign IAM ARN, credential-report ARN or analyzer ARN, stamped the caller's account ID onto it, and allowed a local compliance PASS. SDK-shaped counterexamples reproduced the issue for policy, user, role and group consumers. The coordinator applied the separately proposed guard: partition/account/resource identity is validated before emission, with the documented AWS-managed policy exception and regional analyzer binding. The new public regressions require unavailable outcomes for rejected identities; original false-PASS receipts remain separately hashed.

Four service-usage consumers previously could not obtain `ServicesLastAccessed` because the producer disabled report generation. AWS explicitly classifies `GenerateServiceLastAccessedDetails` and `GenerateCredentialReport` as **Read**. The coordinator applied the reviewed producer helper and selection gates rather than retiring useful checks. Only those two named generation operations are admitted, and raw Requests defaults remain closed. [AWS IAM authorization reference](https://docs.aws.amazon.com/service-authorization/latest/reference/list_iam.html).

The helper binds service report jobs to the cached STS session, principal account/partition and generated job ID. It uses bounded concurrency and one shared session/Region deadline, validates completed job type/timestamps, rejects future authentication dates and contradictory/reused job identity, and requires complete pagination before emitting service rows. Credential fallback runs only for unavailable existing reports, never to recover an access-denied read. Engine selection separates service-usage reports from credential reports, so MFA-only principal checks do not generate unrelated service-access jobs. Directed cases cover positive/negative history, polling, pages, denied/failed/malformed jobs, repeated cursors, changed page dates, limits, timeouts, foreign principals and credential fallback. Report history describes observed attempts, not effective permissions. [AWS service-access reports](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetServiceLastAccessedDetails.html), [AWS credential reports](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_getting-report.html).

## Native field and branch findings

GAAD responses include URL-encoded default and inline documents; production decoding and default-version selection are exercised with a safe default plus an unsafe nondefault version. Missing documents, contradictory default selectors, denied inventory, native policy populations, attachment joins, role trust, role last use, MFA and group membership remain distinct outcomes. A separate paginated `ListPolicies(Scope=Local, OnlyAttached=False)` → `GetPolicyVersion` route proves the customer-policy universe for the six aggregate consumers. [AWS GAAD](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountAuthorizationDetails.html), [AWS GetPolicyVersion](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetPolicyVersion.html).

Nine credential timing observations do not require a fabricated CSV `_provenance` member: the actual callback falls back to the engine's captured snapshot clock. Three legacy policy-attachment fields (`AttachedUsers`, `AttachedGroups`, `AttachedRoles`) are not native GAAD members required by the current branch: emitted GAAD provenance selects the tested join over complete principal `AttachedManagedPolicies` and `GroupList`. These are alternative-contract resolutions, not invented SDK emissions.

The executed cohort still has eight exact-path uncertainties: four unvisited parsed condition-operator branches and four optional coverage-annotation branches. Other semantic limits include effective policy evaluation, all condition/deny combinations, every service observation boundary and exhaustive pagination/time cutoffs. The 64 rows outside the executed cohort retain their original uncertainties individually in the JSON.

Analyzer ACTIVE, CREATING, DISABLED, FAILED, future-status, denied and foreign-identity cases use existing ACCOUNT and ACCOUNT_UNUSED_ACCESS inventories and perform no analyzer creation. The complete-empty public path would enter the temporary-analyzer lifecycle and is explicitly unproved under this review's resource-mutation constraint. Credential rotation cannot establish first-key creation, so the setup check intentionally retains UNKNOWN for that applicable branch. These two IDs do not acquire artificial FAIL witnesses. [AWS ListAnalyzers](https://docs.aws.amazon.com/access-analyzer/latest/APIReference/API_ListAnalyzers.html).

Account contact tests establish present, missing, denied and malformed alternate-contact metadata, plus distinct-contact reductions, while confirming names, addresses, phone numbers and email values do not survive into the snapshot. The earlier organization ID alias remains a separate established contract.

## Reproduction and source identity

```sh
IDENTITY_SDK_RECEIPTS=/tmp/identity-sdk-receipts.json \
  .venv/bin/python -m pytest tests/test_aws_identity_sdk_closure_review.py -q
```

The JSON contains the exact input IDs and input SHA-256, current source hashes, installed botocore version/model digests, per-ID callback results, per-field producer paths, and hashed receipts. Full directed artifacts and minimal proposals are under `/tmp/peasso-aws-review-20261019/identity-sdk-closure/`; only the final passing installed-source receipts establish these contracts. The worker edited only the assigned test and two report files; the coordinator applied all runtime changes and owns central-ledger integration and release.
