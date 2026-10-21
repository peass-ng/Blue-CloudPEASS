# AWS IAM role recorded activity

The existing `aws.claude_a.iam.role_used_within_60_days` control remains in
Hardening with its ID and formal compliance mappings. Its current title and
criteria distinguish recent role creation from recorded AWS use.

The evaluator validates the current role name, immutable role ID, ARN/account,
creation date, capture clock and native field coverage. A role created within
60 days passes for its age even if it has no recorded use. An older role with a
valid recorded last-use date more than 60 days old fails with that actual date
and elapsed days. Recent recorded use passes. Future dates, use before creation,
foreign-account observations, missing creation data and denied fields remain
UNKNOWN or Access denied. The exact 60-day boundary does not count as older.

An older role without a recorded last-use date remains UNKNOWN. AWS documents
bounded tracking for RoleLastUsed, with a period that can vary by Region; a null
date does not supply an explicit complete inactivity interval. ACTIVE unused-access
analyzer findings remain separate native Hardening evidence for provider-classified
unused roles, credentials and permissions. No date or unused-day count is invented.

The original signed evaluator source and description remain intact. A hash-bound
current review updates the registered evaluator, fixture cases, title and current
public criteria without changing the historical source bytes or control ID.
The collector already reads CreateDate and RoleLastUsed; no new AWS permission,
API write, analyzer creation or credential-value read is introduced.

Sources: [AWS RoleLastUsed API](https://docs.aws.amazon.com/IAM/latest/APIReference/API_RoleLastUsed.html)
and [AWS role creation-age review example](https://aws.amazon.com/blogs/security/continuously-monitor-unused-iam-roles-aws-config/).
