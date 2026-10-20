# AWS mapping and source-association review — 2026-10-19

All **1,404 active AWS checks** pass bidirectional requirement/public-mapping integrity across 81 frameworks: 1,182 have numbered requirements and 222 have no numbered requirement. HackTricks security membership applies to 1,061; unrelated operational checks are not automatically labeled security best practices.

The [per-ID report](framework-mappings.json) verifies exact framework/requirement identifiers, canonical assurance, approved source hosts and runtime/public tags. It is not semantic certification. [Source associations](requirement-associations.json) account for 574 divergent upstream IDs / 10,020 edges after acceptance, with **zero unresolved edges**: 10,010 explicit canonical rejections, one manual/out-of-scope decision and nine accepted decisions to preserve existing membership.

Root accepted 16 canonical corrections: seven CIS initial-key and one CIS root-administration requirement retain PARTIAL assurance, while eight approved-port explanations match the actual configuration comparison. Thirteen bounded signal links were admitted as PARTIAL, including KMS enclave, ECS environment and EC2 user-data topics. Nine other source associations were individually rejected as substitutions for a different predicate. [Requirement decisions](requirement-decisions.json) preserve the exact source IDs, reasons and approved actions.

Of six candidate own controls, Cognito app-client refresh-token rotation was implemented, admitted and SDK-tested as the 35th new check. The other five depend on an organizational encryption/network/root-access/retention decision and were not added as universal automatic failures. Their proposals remain in `absent-useful-controls.json`.

Source accounting does not prove all native predicates equivalent to Prowler/SQL or all organizational compliance obligations automated. See the [review index](README.md) for the separate execution and native-field proof layers.
