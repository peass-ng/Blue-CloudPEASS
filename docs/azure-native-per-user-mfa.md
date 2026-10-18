# Native evidence for nonprivileged per-user MFA

The automatic branch of `azure.cis.multifactor_auth_status_non_privileged_users`
reads Microsoft Graph metadata. It does not change users, authentication methods,
Conditional Access, role assignments or tenant policies, and does not require an
approved company baseline for its enabled/enforced per-user MFA decision.

For an enabled user whose nonprivileged status is established from complete
directory role, group and PIM evidence, `perUserMfaState=enabled` or `enforced`
passes only when the registration report also says `isMfaCapable=true`. A
successfully measured false capability fails. Registration alone does not prove
MFA enforcement. Disabled users and users proven privileged follow the existing
not-applicable branches. A disabled **per-user MFA state** does not receive a
native pass from this adapter; its existing sign-in/equivalence branch remains
unchanged and can remain UNKNOWN.

The connector needs read access to the relevant directory roles, current and
eligible PIM paths, transitive membership, owners of role-capable groups,
registration reports and each user's authentication requirements. Requirements
are described by the provider's [authentication requirements API](https://learn.microsoft.com/en-us/graph/api/authentication-get?view=graph-rest-beta),
[registration report API](https://learn.microsoft.com/en-us/graph/api/authenticationmethodsroot-list-userregistrationdetails?view=graph-rest-1.0),
[role definition API](https://learn.microsoft.com/en-us/graph/api/resources/unifiedroledefinition?view=graph-rest-beta)
and [PIM group instance API](https://learn.microsoft.com/en-us/graph/api/privilegedaccessgroup-list-eligibilityscheduleinstances?view=graph-rest-1.0).
The scanner does not grant these permissions. Denied reads, incomplete pages,
ambiguous identities, unresolved ownership and uncorroborated PIM timing remain
UNKNOWN. Ownership is not converted into an invented active role or an
automatic not-applicable result.

This branch uses Graph **beta** for per-user requirements and the provider's
`isPrivileged` role classification. Microsoft states that beta APIs can change
and are not supported for production applications. Treat this as best-effort
beta integration: an unsupported or changed response does not establish
compliance. `isMfaRegistered` and `isAdmin` are not substitutes for the evidence
above.

Portable transport-to-engine regression cases are in
`tests/test_peaso_azure_nonprivileged_mfa_native.py`. They cover enabled/enforced
states, usable methods, privilege and ownership, opaque Graph object IDs,
permanent assignments with corroborating evidence, incomplete and foreign
sources, and valid HTTP request targets. Mocked cases demonstrate those bounded
branches; they do not certify a live tenant or every possible policy context.
