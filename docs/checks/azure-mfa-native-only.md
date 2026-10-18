# Native Azure MFA configuration proofs

The three CIS MFA controls for users, administrative groups and risky sign-ins can establish a native configuration verdict without company-policy metadata. The default scope is the complete enabled-user universe, all applications and all client types. A complete universal MFA policy covers the administrative subset without inventing administrative group membership.

Evidence must come from matching read-only Graph tenant captures: Conditional Access policies, directory users, Security Defaults, and any required authentication-strength/group or risk-entitlement facts. Unconditional enabled All-users/All-applications/all-client MFA or a complete supported native union can establish coverage. Mixed grant alternatives, exclusions, unsupported conditions, foreign identities, incomplete reads or conflicting captures cannot supply a positive proof. Risk-based coverage additionally requires the supported current per-user entitlement evidence.

A complete native user inventory, disabled Security Defaults and no enabled Conditional Access policy can prove a user-control FAIL. Report-only rules do not count as enforcement. Other incomplete/unsupported configurations remain UNKNOWN; the scanner does not ask for company approvals to complete this native path. Explicit historical owner-policy fixtures remain compatibility inputs and cannot replace missing native capture proof.

These are configuration proofs, not runtime authentication attempts or guarantees about every possible sign-in context. No Graph write or login test is executed.
