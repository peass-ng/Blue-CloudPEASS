# Azure Entra user roster projection

`entra_user` is a subscription-scoped view of the existing, fully paged Microsoft Graph v1.0 `/users` `directory_user` read. It adds no Graph operation, API permission, write, application secret read, or content read. The parent remains a tenant-scoped `directory_user` envelope; each projected envelope names `source_inventory` and `parent_inventory` as `directory_user`.

## Admission and provenance

The collector requests the existing `directory_user` and ARM `subscription` inventories when `entra_user` is selected. It emits a complete or empty subscription roster only when the Graph parent read is complete, the authenticated Graph tenant is verified, the parent and every row have matching read-only tenant provenance, and current ARM subscription metadata binds that subscription to the same tenant. It rejects duplicate or missing Graph IDs, conflicting tenant facts, and ambiguous subscription bindings. Denied and partial parent reads stay denied or partial; missing, foreign, or unverified bindings yield an unavailable envelope with no items. A Graph sign-in-activity permission fallback can leave that field uncovered while still completing the `/users` roster.

Rows retain only the selected Graph user metadata: ID, display name, UPN, enabled state, user type, and sign-in activity, plus existing field coverage and provenance. The projection adds `tenant_id` and `subscription_id` for the three exact consumers. The subscription field identifies the evaluation context; it does not assert that every tenant user has a subscription grant. User type and sign-in activity do not establish `human`, IdP subject mapping, effective authorization, MFA enforcement, disable events, removal history, or federation. The projection supplies none of those fields or the `scopeCoverage` proof for a complete subscription principal universe.

## Consumer boundary

The three `compliance_new_sw20` consumers retain their existing semantics. The subscription MFA check still requires a separate effective principal universe, grants, and sign-in policy decisions before PASS; even an empty Graph roster cannot prove its empty authorization universe. The disable deadline check still requires authoritative IdP events and dated cloud access removal. The federation check still requires human classification, correlated sign-in history, and domain federation evidence. A roster alone therefore yields no PASS for any of the three.

## Verification

`tests/test_peaso_azure_entra_user_native.py` drives inert ARM and Graph responses through `collect_snapshot`, including multi-page users, empty, denied, partial, duplicate and missing IDs, foreign tenant facts, unverified tenant, and failed subscription binding. It also evaluates the three checks without external proof. The test transport permits only the existing ARM subscriptions and Graph users GET paths.
