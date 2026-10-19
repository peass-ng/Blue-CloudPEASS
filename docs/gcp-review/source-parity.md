# GCP current upstream source accounting

Reproduce offline: `python scripts/audit_gcp_source_parity.py`. Refresh pinned HEADs: add `--fetch`.

All source blobs are Git SHA-1 and SHA-256 verified; selected cached metadata/evaluators/JSON/PP/SQL stay within 32 MiB. No upstream execution, clone, cloud call, runtime or canonical mapping change occurred.

## Counts

```json
{
  "current_upstream_ids": 766,
  "baseline_upstream_ids": 766,
  "independent_query_definitions": 202,
  "active_native_gcp_checks": 422,
  "status_counts": {
    "mapped-active": 692,
    "mapped-only-archived": 24,
    "rejected": 50
  },
  "changed_existing_ids": 0,
  "retired_upstream_ids": 0,
  "review_classifications": {
    "owner_policy_required": 24,
    "automatable_related_native": 14,
    "useful_automatable_gap": 13,
    "manual_or_partial": 17,
    "unsound_security_predicate": 2,
    "non_security_preference": 1,
    "governance_without_security_predicate": 2,
    "external_observation": 1
  },
  "bounded_native_successor_reconciliations": 13,
  "unreconciled_initial_useful_gap_source_ids": 0,
  "proposal_source_ids": 15,
  "distinct_proposal_contracts": 4,
  "source_cache_bytes": 5792170,
  "by_repository": {
    "turbot/steampipe-mod-gcp-compliance": 621,
    "turbot/steampipe-mod-gcp-perimeter": 33,
    "prowler-cloud/prowler": 112
  }
}
```

## Exact revisions

- [prowler-cloud/prowler](https://github.com/prowler-cloud/prowler/tree/4d922da2a6a29fdf49287176bae11401aaf02b75): `4d922da2a6a29fdf49287176bae11401aaf02b75`, tree `e1a162bee9309ccb56d35a61840b25ce1a9805b7`, corpus SHA-256 `3ecc55e26d6da5205b7eac6ffb68f03db9c406b4699515b7a2e2fe64c7f1dded`; 240 verified blobs.
- [turbot/steampipe-mod-gcp-compliance](https://github.com/turbot/steampipe-mod-gcp-compliance/tree/3ac653021a284b68c69b14c75afa2ebc1feff665): `3ac653021a284b68c69b14c75afa2ebc1feff665`, tree `3b2d73e7bfb05b6d8104577f498695852468b1f8`, corpus SHA-256 `014a0da0da777883d4a46bbdd9674ba287da7cb9c4b64d86367d8dd1816787a7`; 136 verified blobs.
- [turbot/steampipe-mod-gcp-perimeter](https://github.com/turbot/steampipe-mod-gcp-perimeter/tree/e2c5a299d1927a41fe8bbd748bdffd295237937c): `e2c5a299d1927a41fe8bbd748bdffd295237937c`, tree `fb51810d3874beed35388c19b2d8d458d272767d`, corpus SHA-256 `0ccc68b0095067fc0b622317d241186c513d63cbcfafa914ba572506273f7c63`; 5 verified blobs.

## Interpretation

- Mapped-active is an explicit historical association to an active native ID, not a semantic equivalence result.
- Prowler metadata blobs are compared with the pinned baseline Git subtree; title/path/query/evaluator/framework mappings are compared against manifest projections. Current source bytes are Git-blob verified.
- Legacy perimeter evaluator hashes cover wrappers. resolved_sha256 additionally binds referenced local SQL; unchanged pinned Steampipe revision binds the old shared SQL bytes.
- Manual INFO wrappers are reviewed by requirement independently; positive content scanning remains a useful automatable extension.
- No upstream code was executed and no cloud service was queried.

Proposal contracts and 1–2 natural evidence sentences are in `/tmp/peasso-gcp-review-20261019/source-proposals/checks.json`. They use existing network/hardening groups; coordinator owns runtime and mapping admission.

## Workbench root admission

- `prowler.gcp.vertexai_workbench_instance_public_ip_disabled` → `gcp.review.workbench.public_ip_disabled`: **mapped-active**; requirement assurance: reviewed_partial, without full requirement certification.
- `prowler.gcp.vertexai_workbench_instance_root_access_disabled` → `gcp.review.workbench.root_access_disabled`: **mapped-active**; requirement assurance: reviewed_partial, without full requirement certification.

## Individually inspected omissions and archived mappings

### gcp-compliance.control.cis_v120_1_1

**mapped-only-archived / owner_policy_required** — 1.1 Ensure that corporate login credentials are used

The SQL compares user email domains against organization owner directoryCustomerId; the native requires an explicit trusted_domains list. Organization association does not identify every legitimate external user. An org-derived comparator is a useful advisory, not an equivalent corporate-identity verdict.

[Exact upstream source](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v120/section_1.pp#L33). [Official documentation 1](https://cloud.google.com/iam/docs/policies).

### gcp-compliance.control.cis_v120_1_12

**rejected / automatable_related_native** — 1.12 Ensure API keys are not created for a project

API key inventory can establish key absence with complete pagination. The wrapper remains INFO; active key-absence natives are separate implementations, so this report proposes reviewed requirement association rather than claiming SQL semantic equivalence.

[Exact upstream source](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v120/section_1.pp#L187). [Official documentation 1](https://cloud.google.com/api-keys/docs/reference/rest/v2/projects.locations.keys/list).

Related native states: `gcp.claude.project.no_api_keys` (active), `gcp.ports.project_no_api_key` (active).

### gcp-compliance.control.cis_v120_1_2

**rejected / useful_automatable_gap** — 1.2 Ensure that multi-factor authentication is enabled for all non-service accounts

Directory users exposes enrollment and enforcement independently. At initial review the native implementation read isEnrolledIn2Sv only, so enrollment does not establish enforced MFA; external identities and incomplete group expansion also remain unresolved.

[Exact upstream source](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v120/section_1.pp#L47). [Official documentation 1](https://developers.google.com/workspace/admin/directory/reference/rest/v1/users).

Related native states: `gcp.identity.non_service_account_mfa` (active).

Proposed evidence: User {primaryEmail} is enrolled in two-step verification but enforcement is disabled. Directory returned both settings for this active identity.

### gcp-compliance.control.cis_v120_1_3

**rejected / manual_or_partial** — 1.3 Ensure that Security Key Enforcement is enabled for all admin accounts

Security-key-only enforcement is stronger than enrollment or enforced 2SV. Directory boolean fields do not identify the required authentication factor. Retain the attestation unless an authoritative per-admin security-key policy source is collected; existing MFA and super-admin separation checks do not establish this requirement.

[Exact upstream source](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v120/section_1.pp#L61). [Official documentation 1](https://developers.google.com/workspace/admin/directory/reference/rest/v1/users).

Related native states: `gcp.identity.non_service_account_mfa` (active), `gcp.identity.super_admin_separation` (active).

### gcp-compliance.control.cis_v120_4_10

**rejected / automatable_related_native** — 4.10 Ensure that App Engine applications enforce HTTPS connections

Serving-version handler securityLevel is readable; active App Engine HTTPS check is a related declarative implementation. SECURE_ALWAYS declaration does not prove all custom-domain routing or runtime TLS behavior.

[Exact upstream source](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v120/section_4.pp#L155). [Official documentation 1](https://cloud.google.com/appengine/docs/admin-api/reference/rest/v1/apps.services.versions).

Related native states: `gcp.appengine.version_https_only` (active).

### gcp-compliance.control.cis_v120_6_1_1

**rejected / manual_or_partial** — 6.1.1 Ensure that a MySQL database instance does not allow anyone to connect with administrative privileges

Cloud SQL users.list exposes account names and hosts, but not passwords or an authenticated database administrative-privilege test. The active mysql_admin_account_posture check covers readable account posture only; never claim that it proves no privileged authentication is possible.

[Exact upstream source](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v120/section_6.pp#L59). [Official documentation 1](https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1/users).

Related native states: `gcp.sql.mysql_admin_account_posture` (active).

### gcp-compliance.control.cis_v120_6_2_13

**rejected / automatable_related_native** — 6.2.13 Ensure that the 'log_min_messages' database flag for Cloud SQL PostgreSQL instance is set appropriately

Cloud SQL settings.databaseFlags exposes log_min_messages. Related active PostgreSQL flag checks exist, but their exact accepted values and provider defaults must be compared with this versioned requirement; INFO is not a flag evaluator and logging configuration is not delivered-log evidence.

[Exact upstream source](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v120/section_6.pp#L297). [Official documentation 1](https://cloud.google.com/sql/docs/postgres/flags).

Related native states: `gcp.ports.sql_instance_postgresql_log_min_messages_database_flag_error` (active).

### gcp-compliance.control.cis_v120_6_2_2

**rejected / automatable_related_native** — 6.2.2 Ensure 'log_error_verbosity' database flag for Cloud SQL PostgreSQL instance is set to 'DEFAULT' or stricter

Cloud SQL settings.databaseFlags exposes log_error_verbosity. Related active PostgreSQL flag checks exist, but their exact accepted values and provider defaults must be compared with this versioned requirement; INFO is not a flag evaluator and logging configuration is not delivered-log evidence.

[Exact upstream source](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v120/section_6.pp#L143). [Official documentation 1](https://cloud.google.com/sql/docs/postgres/flags).

Related native states: `gcp.ports.sql_instance_postgresql_log_error_verbosity_database_flag_default_or_stricter` (active).

### gcp-compliance.control.cis_v120_6_2_7

**rejected / automatable_related_native** — 6.2.7 Ensure 'log_statement' database flag for Cloud SQL PostgreSQL instance is set appropriately

Cloud SQL settings.databaseFlags exposes log_statement. Related active PostgreSQL flag checks exist, but their exact accepted values and provider defaults must be compared with this versioned requirement; INFO is not a flag evaluator and logging configuration is not delivered-log evidence.

[Exact upstream source](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v120/section_6.pp#L213). [Official documentation 1](https://cloud.google.com/sql/docs/postgres/flags).

Related native states: `gcp.reviewed.sql.postgres_log_statement` (active).

### gcp-compliance.control.cis_v130_1_1

**mapped-only-archived / owner_policy_required** — 1.1 Ensure that corporate login credentials are used

The SQL compares user email domains against organization owner directoryCustomerId; the native requires an explicit trusted_domains list. Organization association does not identify every legitimate external user. An org-derived comparator is a useful advisory, not an equivalent corporate-identity verdict.

[Exact upstream source](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v130/section_1.pp#L36). [Official documentation 1](https://cloud.google.com/iam/docs/policies).

### gcp-compliance.control.cis_v130_1_12

**rejected / automatable_related_native** — 1.12 Ensure API keys are not created for a project

API key inventory can establish key absence with complete pagination. The wrapper remains INFO; active key-absence natives are separate implementations, so this report proposes reviewed requirement association rather than claiming SQL semantic equivalence.

[Exact upstream source](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v130/section_1.pp#L190). [Official documentation 1](https://cloud.google.com/api-keys/docs/reference/rest/v2/projects.locations.keys/list).

Related native states: `gcp.claude.project.no_api_keys` (active), `gcp.ports.project_no_api_key` (active).

### gcp-compliance.control.cis_v130_1_18

**rejected / useful_automatable_gap** — 1.18 Ensure Secrets are Not Stored in Cloud Functions Environment Variables by Using Secret Manager

The wrapper supplies no predicate, but Functions v2 exposes runtime and build environment maps. At initial review the native scanned credential-like variable names only; benign names can hold secret values. Add bounded local value scanning with redacted evidence and explicit coverage; do not fetch Secret Manager payloads or infer a clean workload from truncated content.

[Exact upstream source](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v130/section_1.pp#L274). [Official documentation 1](https://cloud.google.com/functions/docs/reference/rest/v2/projects.locations.functions#ServiceConfig).

Related native states: `gcp.htbp.function.secret_env_from_secret_manager` (active).

Proposed evidence: Function {name} contains a likely credential in a literal environment variable. The value is redacted; move it to Secret Manager and rotate the exposed credential.

### gcp-compliance.control.cis_v130_1_2

**rejected / useful_automatable_gap** — 1.2 Ensure that multi-factor authentication is enabled for all non-service accounts

Directory users exposes enrollment and enforcement independently. At initial review the native implementation read isEnrolledIn2Sv only, so enrollment does not establish enforced MFA; external identities and incomplete group expansion also remain unresolved.

[Exact upstream source](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v130/section_1.pp#L50). [Official documentation 1](https://developers.google.com/workspace/admin/directory/reference/rest/v1/users).

Related native states: `gcp.identity.non_service_account_mfa` (active).

Proposed evidence: User {primaryEmail} is enrolled in two-step verification but enforcement is disabled. Directory returned both settings for this active identity.

### gcp-compliance.control.cis_v130_1_3

**rejected / manual_or_partial** — 1.3 Ensure that Security Key Enforcement is enabled for all admin accounts

Security-key-only enforcement is stronger than enrollment or enforced 2SV. Directory boolean fields do not identify the required authentication factor. Retain the attestation unless an authoritative per-admin security-key policy source is collected; existing MFA and super-admin separation checks do not establish this requirement.

[Exact upstream source](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v130/section_1.pp#L64). [Official documentation 1](https://developers.google.com/workspace/admin/directory/reference/rest/v1/users).

Related native states: `gcp.identity.non_service_account_mfa` (active), `gcp.identity.super_admin_separation` (active).

### gcp-compliance.control.cis_v130_2_14

**rejected / manual_or_partial** — 2.14 Ensure 'Access Transparency' is 'Enabled'

Recent Access Transparency entries can prove an observed signal. The active signal check correctly returns UNKNOWN when no events exist; provider personnel may not have accessed the project, so an empty log cannot prove that Access Transparency is disabled or enabled.

[Exact upstream source](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v130/section_2.pp#L215). [Official documentation 1](https://cloud.google.com/logging/docs/audit/access-transparency-overview).

Related native states: `gcp.logging.access_transparency_entries` (active).

### gcp-compliance.control.cis_v130_4_10

**rejected / automatable_related_native** — 4.10 Ensure that App Engine applications enforce HTTPS connections

Serving-version handler securityLevel is readable; active App Engine HTTPS check is a related declarative implementation. SECURE_ALWAYS declaration does not prove all custom-domain routing or runtime TLS behavior.

[Exact upstream source](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v130/section_4.pp#L156). [Official documentation 1](https://cloud.google.com/appengine/docs/admin-api/reference/rest/v1/apps.services.versions).

Related native states: `gcp.appengine.version_https_only` (active).

### gcp-compliance.control.cis_v130_4_12

**rejected / useful_automatable_gap** — 4.12 Ensure the Latest Operating System Updates Are Installed On Your Virtual Machines in All Projects

OS Config vulnerabilityReports exposes package vulnerabilities and updateTime. Native patch checks are archived because they require an owner grace period; a separate native check can flag positive outstanding security updates with explicit observed-time evidence, while unreadable or stale assessments stay UNKNOWN.

[Exact upstream source](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v130/section_4.pp#L184). [Official documentation 1](https://cloud.google.com/compute/docs/osconfig/rest/v1/projects.locations.instances.vulnerabilityReports).

Related native states: `gcp.compute.os_patch_compliance` (archived).

Proposed evidence: VM {name} has outstanding security updates in its latest OS Config assessment. The assessment was recorded at {updateTime}.

### gcp-compliance.control.cis_v130_6_1_1

**rejected / manual_or_partial** — 6.1.1 Ensure that a MySQL database instance does not allow anyone to connect with administrative privileges

Cloud SQL users.list exposes account names and hosts, but not passwords or an authenticated database administrative-privilege test. The active mysql_admin_account_posture check covers readable account posture only; never claim that it proves no privileged authentication is possible.

[Exact upstream source](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v130/section_6.pp#L59). [Official documentation 1](https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1/users).

Related native states: `gcp.sql.mysql_admin_account_posture` (active).

### gcp-compliance.control.cis_v130_6_2_1

**rejected / automatable_related_native** — 6.2.1 Ensure 'log_error_verbosity' database flag for Cloud SQL PostgreSQL instance is set to 'DEFAULT' or stricter

Cloud SQL settings.databaseFlags exposes log_error_verbosity. Related active PostgreSQL flag checks exist, but their exact accepted values and provider defaults must be compared with this versioned requirement; INFO is not a flag evaluator and logging configuration is not delivered-log evidence.

[Exact upstream source](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v130/section_6.pp#L122). [Official documentation 1](https://cloud.google.com/sql/docs/postgres/flags).

Related native states: `gcp.ports.sql_instance_postgresql_log_error_verbosity_database_flag_default_or_stricter` (active).

### gcp-compliance.control.cis_v130_6_2_4

**rejected / automatable_related_native** — 6.2.4 Ensure 'log_statement' database flag for Cloud SQL PostgreSQL instance is set appropriately

Cloud SQL settings.databaseFlags exposes log_statement. Related active PostgreSQL flag checks exist, but their exact accepted values and provider defaults must be compared with this versioned requirement; INFO is not a flag evaluator and logging configuration is not delivered-log evidence.

[Exact upstream source](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v130/section_6.pp#L164). [Official documentation 1](https://cloud.google.com/sql/docs/postgres/flags).

Related native states: `gcp.reviewed.sql.postgres_log_statement` (active).

### gcp-compliance.control.cis_v130_6_2_6

**rejected / automatable_related_native** — 6.2.6 Ensure that the 'log_min_messages' database flag for Cloud SQL PostgreSQL instance is set appropriately

Cloud SQL settings.databaseFlags exposes log_min_messages. Related active PostgreSQL flag checks exist, but their exact accepted values and provider defaults must be compared with this versioned requirement; INFO is not a flag evaluator and logging configuration is not delivered-log evidence.

[Exact upstream source](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v130/section_6.pp#L192). [Official documentation 1](https://cloud.google.com/sql/docs/postgres/flags).

Related native states: `gcp.ports.sql_instance_postgresql_log_min_messages_database_flag_error` (active).

### gcp-compliance.control.cis_v200_1_1

**mapped-only-archived / owner_policy_required** — 1.1 Ensure that corporate login credentials are used

The SQL compares user email domains against organization owner directoryCustomerId; the native requires an explicit trusted_domains list. Organization association does not identify every legitimate external user. An org-derived comparator is a useful advisory, not an equivalent corporate-identity verdict.

[Exact upstream source](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v200/section_1.pp#L36). [Official documentation 1](https://cloud.google.com/iam/docs/policies).

### gcp-compliance.control.cis_v200_1_12

**rejected / automatable_related_native** — 1.12 Ensure API Keys Only Exist for Active Services

API key restrictions can be joined to enabled service inventory. Active natives already inspect this declaration; the INFO wrapper is not an executable equivalent. Wildcard service names and unreadable enabled-service inventory need explicit treatment.

[Exact upstream source](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v200/section_1.pp#L190). [Official documentation 1](https://cloud.google.com/api-keys/docs/reference/rest/v2/projects.locations.keys).

Related native states: `gcp.apikeys.active_service_restrictions` (active), `gcp_api_keys_active_services_only` (active).

### gcp-compliance.control.cis_v200_1_18

**rejected / useful_automatable_gap** — 1.18 Ensure Secrets are Not Stored in Cloud Functions Environment Variables by Using Secret Manager

The wrapper supplies no predicate, but Functions v2 exposes runtime and build environment maps. At initial review the native scanned credential-like variable names only; benign names can hold secret values. Add bounded local value scanning with redacted evidence and explicit coverage; do not fetch Secret Manager payloads or infer a clean workload from truncated content.

[Exact upstream source](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v200/section_1.pp#L274). [Official documentation 1](https://cloud.google.com/functions/docs/reference/rest/v2/projects.locations.functions#ServiceConfig).

Related native states: `gcp.htbp.function.secret_env_from_secret_manager` (active).

Proposed evidence: Function {name} contains a likely credential in a literal environment variable. The value is redacted; move it to Secret Manager and rotate the exposed credential.

### gcp-compliance.control.cis_v200_1_2

**rejected / useful_automatable_gap** — 1.2 Ensure that multi-factor authentication is enabled for all non-service accounts

Directory users exposes enrollment and enforcement independently. At initial review the native implementation read isEnrolledIn2Sv only, so enrollment does not establish enforced MFA; external identities and incomplete group expansion also remain unresolved.

[Exact upstream source](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v200/section_1.pp#L50). [Official documentation 1](https://developers.google.com/workspace/admin/directory/reference/rest/v1/users).

Related native states: `gcp.identity.non_service_account_mfa` (active).

Proposed evidence: User {primaryEmail} is enrolled in two-step verification but enforcement is disabled. Directory returned both settings for this active identity.

### gcp-compliance.control.cis_v200_1_3

**rejected / manual_or_partial** — 1.3 Ensure that Security Key Enforcement is enabled for all admin accounts

Security-key-only enforcement is stronger than enrollment or enforced 2SV. Directory boolean fields do not identify the required authentication factor. Retain the attestation unless an authoritative per-admin security-key policy source is collected; existing MFA and super-admin separation checks do not establish this requirement.

[Exact upstream source](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v200/section_1.pp#L64). [Official documentation 1](https://developers.google.com/workspace/admin/directory/reference/rest/v1/users).

Related native states: `gcp.identity.non_service_account_mfa` (active), `gcp.identity.super_admin_separation` (active).

### gcp-compliance.control.cis_v200_2_14

**rejected / manual_or_partial** — 2.14 Ensure 'Access Transparency' is 'Enabled'

Recent Access Transparency entries can prove an observed signal. The active signal check correctly returns UNKNOWN when no events exist; provider personnel may not have accessed the project, so an empty log cannot prove that Access Transparency is disabled or enabled.

[Exact upstream source](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v200/section_2.pp#L216). [Official documentation 1](https://cloud.google.com/logging/docs/audit/access-transparency-overview).

Related native states: `gcp.logging.access_transparency_entries` (active).

### gcp-compliance.control.cis_v200_4_10

**rejected / automatable_related_native** — 4.10 Ensure that App Engine applications enforce HTTPS connections

Serving-version handler securityLevel is readable; active App Engine HTTPS check is a related declarative implementation. SECURE_ALWAYS declaration does not prove all custom-domain routing or runtime TLS behavior.

[Exact upstream source](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v200/section_4.pp#L156). [Official documentation 1](https://cloud.google.com/appengine/docs/admin-api/reference/rest/v1/apps.services.versions).

Related native states: `gcp.appengine.version_https_only` (active).

### gcp-compliance.control.cis_v200_4_12

**rejected / useful_automatable_gap** — 4.12 Ensure the Latest Operating System Updates Are Installed On Your Virtual Machines in All Projects

OS Config vulnerabilityReports exposes package vulnerabilities and updateTime. Native patch checks are archived because they require an owner grace period; a separate native check can flag positive outstanding security updates with explicit observed-time evidence, while unreadable or stale assessments stay UNKNOWN.

[Exact upstream source](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v200/section_4.pp#L184). [Official documentation 1](https://cloud.google.com/compute/docs/osconfig/rest/v1/projects.locations.instances.vulnerabilityReports).

Related native states: `gcp.compute.os_patch_compliance` (archived).

Proposed evidence: VM {name} has outstanding security updates in its latest OS Config assessment. The assessment was recorded at {updateTime}.

### gcp-compliance.control.cis_v200_6_1_1

**rejected / manual_or_partial** — 6.1.1 Ensure that a MySQL database instance does not allow anyone to connect with administrative privileges

Cloud SQL users.list exposes account names and hosts, but not passwords or an authenticated database administrative-privilege test. The active mysql_admin_account_posture check covers readable account posture only; never claim that it proves no privileged authentication is possible.

[Exact upstream source](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v200/section_6.pp#L59). [Official documentation 1](https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1/users).

Related native states: `gcp.sql.mysql_admin_account_posture` (active).

### gcp-compliance.control.cis_v300_1_1

**mapped-only-archived / owner_policy_required** — 1.1 Ensure that Corporate Login Credentials are Used

The SQL compares user email domains against organization owner directoryCustomerId; the native requires an explicit trusted_domains list. Organization association does not identify every legitimate external user. An org-derived comparator is a useful advisory, not an equivalent corporate-identity verdict.

[Exact upstream source](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v300/section_1.pp#L35). [Official documentation 1](https://cloud.google.com/iam/docs/policies).

### gcp-compliance.control.cis_v300_1_17

**rejected / useful_automatable_gap** — 1.17 Ensure Secrets are Not Stored in Cloud Functions Environment Variables by Using Secret Manager

The wrapper supplies no predicate, but Functions v2 exposes runtime and build environment maps. At initial review the native scanned credential-like variable names only; benign names can hold secret values. Add bounded local value scanning with redacted evidence and explicit coverage; do not fetch Secret Manager payloads or infer a clean workload from truncated content.

[Exact upstream source](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v300/section_1.pp#L259). [Official documentation 1](https://cloud.google.com/functions/docs/reference/rest/v2/projects.locations.functions#ServiceConfig).

Related native states: `gcp.htbp.function.secret_env_from_secret_manager` (active).

Proposed evidence: Function {name} contains a likely credential in a literal environment variable. The value is redacted; move it to Secret Manager and rotate the exposed credential.

### gcp-compliance.control.cis_v300_1_2

**rejected / useful_automatable_gap** — 1.2 Ensure that Multi-Factor Authentication is 'Enabled' for All Non-Service Accounts

Directory users exposes enrollment and enforcement independently. At initial review the native implementation read isEnrolledIn2Sv only, so enrollment does not establish enforced MFA; external identities and incomplete group expansion also remain unresolved.

[Exact upstream source](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v300/section_1.pp#L49). [Official documentation 1](https://developers.google.com/workspace/admin/directory/reference/rest/v1/users).

Related native states: `gcp.identity.non_service_account_mfa` (active).

Proposed evidence: User {primaryEmail} is enrolled in two-step verification but enforcement is disabled. Directory returned both settings for this active identity.

### gcp-compliance.control.cis_v300_1_3

**rejected / manual_or_partial** — 1.3 Ensure that Security Key Enforcement is Enabled for All Admin Accounts

Security-key-only enforcement is stronger than enrollment or enforced 2SV. Directory boolean fields do not identify the required authentication factor. Retain the attestation unless an authoritative per-admin security-key policy source is collected; existing MFA and super-admin separation checks do not establish this requirement.

[Exact upstream source](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v300/section_1.pp#L63). [Official documentation 1](https://developers.google.com/workspace/admin/directory/reference/rest/v1/users).

Related native states: `gcp.identity.non_service_account_mfa` (active), `gcp.identity.super_admin_separation` (active).

### gcp-compliance.control.cis_v300_2_14

**rejected / manual_or_partial** — 2.14 Ensure 'Access Transparency' is 'Enabled'

Recent Access Transparency entries can prove an observed signal. The active signal check correctly returns UNKNOWN when no events exist; provider personnel may not have accessed the project, so an empty log cannot prove that Access Transparency is disabled or enabled.

[Exact upstream source](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v300/section_2.pp#L216). [Official documentation 1](https://cloud.google.com/logging/docs/audit/access-transparency-overview).

Related native states: `gcp.logging.access_transparency_entries` (active).

### gcp-compliance.control.cis_v300_4_10

**rejected / automatable_related_native** — 4.10 Ensure That App Engine Applications Enforce HTTPS Connections

Serving-version handler securityLevel is readable; active App Engine HTTPS check is a related declarative implementation. SECURE_ALWAYS declaration does not prove all custom-domain routing or runtime TLS behavior.

[Exact upstream source](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v300/section_4.pp#L156). [Official documentation 1](https://cloud.google.com/appengine/docs/admin-api/reference/rest/v1/apps.services.versions).

Related native states: `gcp.appengine.version_https_only` (active).

### gcp-compliance.control.cis_v300_4_12

**rejected / useful_automatable_gap** — 4.12 Ensure the Latest Operating System Updates Are Installed On Your Virtual Machines in All Project

OS Config vulnerabilityReports exposes package vulnerabilities and updateTime. Native patch checks are archived because they require an owner grace period; a separate native check can flag positive outstanding security updates with explicit observed-time evidence, while unreadable or stale assessments stay UNKNOWN.

[Exact upstream source](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v300/section_4.pp#L184). [Official documentation 1](https://cloud.google.com/compute/docs/osconfig/rest/v1/projects.locations.instances.vulnerabilityReports).

Related native states: `gcp.compute.os_patch_compliance` (archived).

Proposed evidence: VM {name} has outstanding security updates in its latest OS Config assessment. The assessment was recorded at {updateTime}.

### gcp-compliance.control.cis_v300_6_1_1

**rejected / manual_or_partial** — 6.1.1 Ensure That a MySQL Database Instance Does Not Allow Anyone To Connect With Administrative Privileges

Cloud SQL users.list exposes account names and hosts, but not passwords or an authenticated database administrative-privilege test. The active mysql_admin_account_posture check covers readable account posture only; never claim that it proves no privileged authentication is possible.

[Exact upstream source](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v300/section_6.pp#L59). [Official documentation 1](https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1/users).

Related native states: `gcp.sql.mysql_admin_account_posture` (active).

### gcp-compliance.control.cis_v300_7_4

**rejected / manual_or_partial** — 7.4 Ensure all data in BigQuery has been classified

BigQuery table schemas expose column policy tags and governance annotations, so metadata coverage and bounded content discovery are automatable. Whether all data is correctly classified needs taxonomy and content semantics; do not treat arbitrary labels as proof. A separate advisory can enumerate unannotated columns without claiming full classification compliance.

[Exact upstream source](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v300/section_7.pp#L65). [Official documentation 1](https://docs.cloud.google.com/bigquery/docs/column-level-security). [Official documentation 2](https://docs.cloud.google.com/bigquery/docs/reference/rest/v2/tables).

Proposed evidence: BigQuery table {name} has columns without a classification annotation. This inventories metadata gaps and does not determine the sensitivity of the stored values.

### gcp-compliance.control.cis_v400_1_1

**mapped-only-archived / owner_policy_required** — 1.1 Ensure that Corporate Login Credentials are Used

The SQL compares user email domains against organization owner directoryCustomerId; the native requires an explicit trusted_domains list. Organization association does not identify every legitimate external user. An org-derived comparator is a useful advisory, not an equivalent corporate-identity verdict.

[Exact upstream source](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v400/section_1.pp#L35). [Official documentation 1](https://cloud.google.com/iam/docs/policies).

### gcp-compliance.control.cis_v400_1_17

**rejected / useful_automatable_gap** — 1.17 Ensure Secrets are Not Stored in Cloud Functions Environment Variables by Using Secret Manager

The wrapper supplies no predicate, but Functions v2 exposes runtime and build environment maps. At initial review the native scanned credential-like variable names only; benign names can hold secret values. Add bounded local value scanning with redacted evidence and explicit coverage; do not fetch Secret Manager payloads or infer a clean workload from truncated content.

[Exact upstream source](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v400/section_1.pp#L259). [Official documentation 1](https://cloud.google.com/functions/docs/reference/rest/v2/projects.locations.functions#ServiceConfig).

Related native states: `gcp.htbp.function.secret_env_from_secret_manager` (active).

Proposed evidence: Function {name} contains a likely credential in a literal environment variable. The value is redacted; move it to Secret Manager and rotate the exposed credential.

### gcp-compliance.control.cis_v400_1_2

**rejected / useful_automatable_gap** — 1.2 Ensure that Multi-Factor Authentication is 'Enabled' for All Non-Service Accounts

Directory users exposes enrollment and enforcement independently. At initial review the native implementation read isEnrolledIn2Sv only, so enrollment does not establish enforced MFA; external identities and incomplete group expansion also remain unresolved.

[Exact upstream source](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v400/section_1.pp#L49). [Official documentation 1](https://developers.google.com/workspace/admin/directory/reference/rest/v1/users).

Related native states: `gcp.identity.non_service_account_mfa` (active).

Proposed evidence: User {primaryEmail} is enrolled in two-step verification but enforcement is disabled. Directory returned both settings for this active identity.

### gcp-compliance.control.cis_v400_1_3

**rejected / manual_or_partial** — 1.3 Ensure that Security Key Enforcement is Enabled for All Admin Accounts

Security-key-only enforcement is stronger than enrollment or enforced 2SV. Directory boolean fields do not identify the required authentication factor. Retain the attestation unless an authoritative per-admin security-key policy source is collected; existing MFA and super-admin separation checks do not establish this requirement.

[Exact upstream source](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v400/section_1.pp#L63). [Official documentation 1](https://developers.google.com/workspace/admin/directory/reference/rest/v1/users).

Related native states: `gcp.identity.non_service_account_mfa` (active), `gcp.identity.super_admin_separation` (active).

### gcp-compliance.control.cis_v400_2_14

**rejected / manual_or_partial** — 2.14 Ensure 'Access Transparency' is 'Enabled'

Recent Access Transparency entries can prove an observed signal. The active signal check correctly returns UNKNOWN when no events exist; provider personnel may not have accessed the project, so an empty log cannot prove that Access Transparency is disabled or enabled.

[Exact upstream source](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v400/section_2.pp#L216). [Official documentation 1](https://cloud.google.com/logging/docs/audit/access-transparency-overview).

Related native states: `gcp.logging.access_transparency_entries` (active).

### gcp-compliance.control.cis_v400_4_10

**rejected / automatable_related_native** — 4.10 Ensure That App Engine Applications Enforce HTTPS Connections

Serving-version handler securityLevel is readable; active App Engine HTTPS check is a related declarative implementation. SECURE_ALWAYS declaration does not prove all custom-domain routing or runtime TLS behavior.

[Exact upstream source](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v400/section_4.pp#L156). [Official documentation 1](https://cloud.google.com/appengine/docs/admin-api/reference/rest/v1/apps.services.versions).

Related native states: `gcp.appengine.version_https_only` (active).

### gcp-compliance.control.cis_v400_4_12

**rejected / useful_automatable_gap** — 4.12 Ensure the Latest Operating System Updates Are Installed On Your Virtual Machines in All Projects

OS Config vulnerabilityReports exposes package vulnerabilities and updateTime. Native patch checks are archived because they require an owner grace period; a separate native check can flag positive outstanding security updates with explicit observed-time evidence, while unreadable or stale assessments stay UNKNOWN.

[Exact upstream source](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v400/section_4.pp#L184). [Official documentation 1](https://cloud.google.com/compute/docs/osconfig/rest/v1/projects.locations.instances.vulnerabilityReports).

Related native states: `gcp.compute.os_patch_compliance` (archived).

Proposed evidence: VM {name} has outstanding security updates in its latest OS Config assessment. The assessment was recorded at {updateTime}.

### gcp-compliance.control.cis_v400_6_1_1

**rejected / manual_or_partial** — 6.1.1 Ensure That a MySQL Database Instance Does Not Allow Anyone To Connect With Administrative Privileges

Cloud SQL users.list exposes account names and hosts, but not passwords or an authenticated database administrative-privilege test. The active mysql_admin_account_posture check covers readable account posture only; never claim that it proves no privileged authentication is possible.

[Exact upstream source](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v400/section_6.pp#L59). [Official documentation 1](https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1/users).

Related native states: `gcp.sql.mysql_admin_account_posture` (active).

### gcp-compliance.control.cis_v400_7_4

**rejected / manual_or_partial** — 7.4 Ensure all data in BigQuery has been classified

BigQuery table schemas expose column policy tags and governance annotations, so metadata coverage and bounded content discovery are automatable. Whether all data is correctly classified needs taxonomy and content semantics; do not treat arbitrary labels as proof. A separate advisory can enumerate unannotated columns without claiming full classification compliance.

[Exact upstream source](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v400/section_7.pp#L65). [Official documentation 1](https://docs.cloud.google.com/bigquery/docs/column-level-security). [Official documentation 2](https://docs.cloud.google.com/bigquery/docs/reference/rest/v2/tables).

Proposed evidence: BigQuery table {name} has columns without a classification annotation. This inventories metadata gaps and does not determine the sensitivity of the stored values.

### gcp-compliance.control.compute_instance_with_custom_metadata

**rejected / unsound_security_predicate** — Compute Instances should have custom metadata

The query tests metadata object non-null, not metadata.items, and skips gke-* names in the status branch. Object presence does not establish a security setting or secret absence; retain the rejection of this predicate, but startup-script/metadata secret content scanning remains independently useful.

[Exact upstream source](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/compute.pp#L440). [Official documentation 1](https://cloud.google.com/compute/docs/reference/rest/v1/instances).

### gcp-compliance.control.compute_target_https_proxy_quic_protocol_enabled

**rejected / non_security_preference** — Compute Target HTTPS proxy QUIC protocol should be enabled

The query alarms unless quic_override is ENABLE. The API exposes NONE, ENABLE and DISABLE as supported transport choices; this predicate supplies no TLS-policy or authentication weakness. A minimum TLS policy check is a separate security predicate.

[Exact upstream source](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/compute.pp#L456). [Official documentation 1](https://cloud.google.com/compute/docs/reference/rest/v1/targetHttpsProxies).

### gcp-compliance.control.kubernetes_cluster_with_less_than_three_node_auto_upgrade_enabled

**rejected / unsound_security_predicate** — GKE clusters with less than three nodes should have auto upgrade enabled

The SQL alarms when autoUpgrade=true and cluster current_node_count<3, contradicting its title, and uses cluster-wide size per node pool. Do not reproduce this inverted availability heuristic; node auto-upgrade configuration is independently automatable.

[Exact upstream source](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/kubernetes.pp#L269). [Official documentation 1](https://cloud.google.com/kubernetes-engine/docs/concepts/node-auto-upgrades).

### gcp-compliance.control.kubernetes_cluster_with_resource_labels

**rejected / governance_without_security_predicate** — GKE clusters should have resource labels

The query checks only whether the labels object is null, so an empty object or arbitrary label passes. No security classification key or enforced authorization rule is identified; labels presence cannot prove secure configuration.

[Exact upstream source](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/kubernetes.pp#L166). [Official documentation 1](https://cloud.google.com/resource-manager/docs/creating-managing-labels).

### gcp-compliance.control.only_my_domain

**mapped-only-archived / owner_policy_required** — Only allow members from my domain to be added to IAM roles

The SQL compares user email domains against organization owner directoryCustomerId; the native requires an explicit trusted_domains list. Organization association does not identify every legitimate external user. An org-derived comparator is a useful advisory, not an equivalent corporate-identity verdict.

[Exact upstream source](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/iam.pp#L19). [Official documentation 1](https://cloud.google.com/iam/docs/policies).

### gcp-compliance.control.service_versions

**rejected / manual_or_partial** — Limit the number of App Engine application versions simultaneously running or installed

App Engine versions and traffic allocations are readable and can identify inactive or old versions. The upstream title provides no safe numerical version limit; report version inventory or owner-selected lifecycle policy rather than inventing a security PASS threshold.

[Exact upstream source](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/appengine.pp#L7). [Official documentation 1](https://cloud.google.com/appengine/docs/admin-api/reference/rest/v1/apps.services.versions).

### gcp-compliance.control.sql_instance_with_labels

**rejected / governance_without_security_predicate** — SQL Instances should have labels configured

The query checks only whether the labels object is null, so an empty object or arbitrary label passes. No security classification key or enforced authorization rule is identified; labels presence cannot prove secure configuration.

[Exact upstream source](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/sql.pp#L359). [Official documentation 1](https://cloud.google.com/resource-manager/docs/creating-managing-labels).

### gcp-perimeter.control.bigtable_instance_policy_shared_access

**mapped-only-archived / owner_policy_required** — Bigtable instance IAM policies should only grant access to trusted principals

The resolved shared SQL compares each non-project user/group/domain/service-account member against $1-$4 trusted-principal lists; only-project members produce INFO. IAM APIs expose bindings but do not establish organizational trust of every identity. Public principal detection is automatable separately; it does not replace the trust-list predicate.

[Exact upstream source](https://github.com/turbot/steampipe-mod-gcp-perimeter/blob/e2c5a299d1927a41fe8bbd748bdffd295237937c/perimeter/iam_policy_shared_access.pp#L649). [Official documentation 1](https://cloud.google.com/iam/docs/policies).

### gcp-perimeter.control.billing_account_policy_shared_access

**mapped-only-archived / owner_policy_required** — Billing account IAM policies should only grant access to trusted principals

The resolved shared SQL compares each non-project user/group/domain/service-account member against $1-$4 trusted-principal lists; only-project members produce INFO. IAM APIs expose bindings but do not establish organizational trust of every identity. Public principal detection is automatable separately; it does not replace the trust-list predicate.

[Exact upstream source](https://github.com/turbot/steampipe-mod-gcp-perimeter/blob/e2c5a299d1927a41fe8bbd748bdffd295237937c/perimeter/iam_policy_shared_access.pp#L618). [Official documentation 1](https://cloud.google.com/iam/docs/policies).

### gcp-perimeter.control.cloud_function_policy_shared_access

**mapped-only-archived / owner_policy_required** — Cloud Function IAM policies should only grant access to trusted principals

The resolved shared SQL compares each non-project user/group/domain/service-account member against $1-$4 trusted-principal lists; only-project members produce INFO. IAM APIs expose bindings but do not establish organizational trust of every identity. Public principal detection is automatable separately; it does not replace the trust-list predicate.

[Exact upstream source](https://github.com/turbot/steampipe-mod-gcp-perimeter/blob/e2c5a299d1927a41fe8bbd748bdffd295237937c/perimeter/iam_policy_shared_access.pp#L587). [Official documentation 1](https://cloud.google.com/iam/docs/policies).

### gcp-perimeter.control.cloud_run_job_policy_shared_access

**mapped-only-archived / owner_policy_required** — Cloud Run job IAM policies should only grant access to trusted principals

The resolved shared SQL compares each non-project user/group/domain/service-account member against $1-$4 trusted-principal lists; only-project members produce INFO. IAM APIs expose bindings but do not establish organizational trust of every identity. Public principal detection is automatable separately; it does not replace the trust-list predicate.

[Exact upstream source](https://github.com/turbot/steampipe-mod-gcp-perimeter/blob/e2c5a299d1927a41fe8bbd748bdffd295237937c/perimeter/iam_policy_shared_access.pp#L526). [Official documentation 1](https://cloud.google.com/iam/docs/policies).

### gcp-perimeter.control.cloud_run_service_policy_shared_access

**mapped-only-archived / owner_policy_required** — Cloud Run service IAM policies should only grant access to trusted principals

The resolved shared SQL compares each non-project user/group/domain/service-account member against $1-$4 trusted-principal lists; only-project members produce INFO. IAM APIs expose bindings but do not establish organizational trust of every identity. Public principal detection is automatable separately; it does not replace the trust-list predicate.

[Exact upstream source](https://github.com/turbot/steampipe-mod-gcp-perimeter/blob/e2c5a299d1927a41fe8bbd748bdffd295237937c/perimeter/iam_policy_shared_access.pp#L556). [Official documentation 1](https://cloud.google.com/iam/docs/policies).

### gcp-perimeter.control.compute_disk_policy_shared_access

**mapped-only-archived / owner_policy_required** — Compute disk IAM policies should only grant access to trusted principals

The resolved shared SQL compares each non-project user/group/domain/service-account member against $1-$4 trusted-principal lists; only-project members produce INFO. IAM APIs expose bindings but do not establish organizational trust of every identity. Public principal detection is automatable separately; it does not replace the trust-list predicate.

[Exact upstream source](https://github.com/turbot/steampipe-mod-gcp-perimeter/blob/e2c5a299d1927a41fe8bbd748bdffd295237937c/perimeter/iam_policy_shared_access.pp#L315). [Official documentation 1](https://cloud.google.com/iam/docs/policies).

### gcp-perimeter.control.compute_image_policy_shared_access

**mapped-only-archived / owner_policy_required** — Compute image IAM policies should only grant access to trusted principals

The resolved shared SQL compares each non-project user/group/domain/service-account member against $1-$4 trusted-principal lists; only-project members produce INFO. IAM APIs expose bindings but do not establish organizational trust of every identity. Public principal detection is automatable separately; it does not replace the trust-list predicate.

[Exact upstream source](https://github.com/turbot/steampipe-mod-gcp-perimeter/blob/e2c5a299d1927a41fe8bbd748bdffd295237937c/perimeter/iam_policy_shared_access.pp#L345). [Official documentation 1](https://cloud.google.com/iam/docs/policies).

### gcp-perimeter.control.compute_instance_policy_shared_access

**mapped-only-archived / owner_policy_required** — Compute instance IAM policies should only grant access to trusted principals

The resolved shared SQL compares each non-project user/group/domain/service-account member against $1-$4 trusted-principal lists; only-project members produce INFO. IAM APIs expose bindings but do not establish organizational trust of every identity. Public principal detection is automatable separately; it does not replace the trust-list predicate.

[Exact upstream source](https://github.com/turbot/steampipe-mod-gcp-perimeter/blob/e2c5a299d1927a41fe8bbd748bdffd295237937c/perimeter/iam_policy_shared_access.pp#L375). [Official documentation 1](https://cloud.google.com/iam/docs/policies).

### gcp-perimeter.control.compute_node_group_policy_shared_access

**mapped-only-archived / owner_policy_required** — Compute node group IAM policies should only grant access to trusted principals

The resolved shared SQL compares each non-project user/group/domain/service-account member against $1-$4 trusted-principal lists; only-project members produce INFO. IAM APIs expose bindings but do not establish organizational trust of every identity. Public principal detection is automatable separately; it does not replace the trust-list predicate.

[Exact upstream source](https://github.com/turbot/steampipe-mod-gcp-perimeter/blob/e2c5a299d1927a41fe8bbd748bdffd295237937c/perimeter/iam_policy_shared_access.pp#L405). [Official documentation 1](https://cloud.google.com/iam/docs/policies).

### gcp-perimeter.control.compute_node_template_policy_shared_access

**mapped-only-archived / owner_policy_required** — Compute node template IAM policies should only grant access to trusted principals

The resolved shared SQL compares each non-project user/group/domain/service-account member against $1-$4 trusted-principal lists; only-project members produce INFO. IAM APIs expose bindings but do not establish organizational trust of every identity. Public principal detection is automatable separately; it does not replace the trust-list predicate.

[Exact upstream source](https://github.com/turbot/steampipe-mod-gcp-perimeter/blob/e2c5a299d1927a41fe8bbd748bdffd295237937c/perimeter/iam_policy_shared_access.pp#L435). [Official documentation 1](https://cloud.google.com/iam/docs/policies).

### gcp-perimeter.control.compute_resource_policy_shared_access

**mapped-only-archived / owner_policy_required** — Compute resource policy IAM policies should only grant access to trusted principals

The resolved shared SQL compares each non-project user/group/domain/service-account member against $1-$4 trusted-principal lists; only-project members produce INFO. IAM APIs expose bindings but do not establish organizational trust of every identity. Public principal detection is automatable separately; it does not replace the trust-list predicate.

[Exact upstream source](https://github.com/turbot/steampipe-mod-gcp-perimeter/blob/e2c5a299d1927a41fe8bbd748bdffd295237937c/perimeter/iam_policy_shared_access.pp#L465). [Official documentation 1](https://cloud.google.com/iam/docs/policies).

### gcp-perimeter.control.compute_subnetwork_policy_shared_access

**mapped-only-archived / owner_policy_required** — Compute subnetwork IAM policies should only grant access to trusted principals

The resolved shared SQL compares each non-project user/group/domain/service-account member against $1-$4 trusted-principal lists; only-project members produce INFO. IAM APIs expose bindings but do not establish organizational trust of every identity. Public principal detection is automatable separately; it does not replace the trust-list predicate.

[Exact upstream source](https://github.com/turbot/steampipe-mod-gcp-perimeter/blob/e2c5a299d1927a41fe8bbd748bdffd295237937c/perimeter/iam_policy_shared_access.pp#L495). [Official documentation 1](https://cloud.google.com/iam/docs/policies).

### gcp-perimeter.control.iam_service_account_policy_shared_access

**mapped-only-archived / owner_policy_required** — IAM service account IAM policies should only grant access to trusted principals

The resolved shared SQL compares each non-project user/group/domain/service-account member against $1-$4 trusted-principal lists; only-project members produce INFO. IAM APIs expose bindings but do not establish organizational trust of every identity. Public principal detection is automatable separately; it does not replace the trust-list predicate.

[Exact upstream source](https://github.com/turbot/steampipe-mod-gcp-perimeter/blob/e2c5a299d1927a41fe8bbd748bdffd295237937c/perimeter/iam_policy_shared_access.pp#L253). [Official documentation 1](https://cloud.google.com/iam/docs/policies).

### gcp-perimeter.control.kms_key_policy_shared_access

**mapped-only-archived / owner_policy_required** — KMS key IAM policies should only grant access to trusted principals

The resolved shared SQL compares each non-project user/group/domain/service-account member against $1-$4 trusted-principal lists; only-project members produce INFO. IAM APIs expose bindings but do not establish organizational trust of every identity. Public principal detection is automatable separately; it does not replace the trust-list predicate.

[Exact upstream source](https://github.com/turbot/steampipe-mod-gcp-perimeter/blob/e2c5a299d1927a41fe8bbd748bdffd295237937c/perimeter/iam_policy_shared_access.pp#L680). [Official documentation 1](https://cloud.google.com/iam/docs/policies).

### gcp-perimeter.control.kms_key_ring_policy_shared_access

**mapped-only-archived / owner_policy_required** — KMS key ring IAM policies should only grant access to trusted principals

The resolved shared SQL compares each non-project user/group/domain/service-account member against $1-$4 trusted-principal lists; only-project members produce INFO. IAM APIs expose bindings but do not establish organizational trust of every identity. Public principal detection is automatable separately; it does not replace the trust-list predicate.

[Exact upstream source](https://github.com/turbot/steampipe-mod-gcp-perimeter/blob/e2c5a299d1927a41fe8bbd748bdffd295237937c/perimeter/iam_policy_shared_access.pp#L710). [Official documentation 1](https://cloud.google.com/iam/docs/policies).

### gcp-perimeter.control.pubsub_subscription_policy_shared_access

**mapped-only-archived / owner_policy_required** — Pub/Sub subscription IAM policies should only grant access to trusted principals

The resolved shared SQL compares each non-project user/group/domain/service-account member against $1-$4 trusted-principal lists; only-project members produce INFO. IAM APIs expose bindings but do not establish organizational trust of every identity. Public principal detection is automatable separately; it does not replace the trust-list predicate.

[Exact upstream source](https://github.com/turbot/steampipe-mod-gcp-perimeter/blob/e2c5a299d1927a41fe8bbd748bdffd295237937c/perimeter/iam_policy_shared_access.pp#L771). [Official documentation 1](https://cloud.google.com/iam/docs/policies).

### gcp-perimeter.control.pubsub_topic_policy_shared_access

**mapped-only-archived / owner_policy_required** — Pub/Sub topic IAM policies should only grant access to trusted principals

The resolved shared SQL compares each non-project user/group/domain/service-account member against $1-$4 trusted-principal lists; only-project members produce INFO. IAM APIs expose bindings but do not establish organizational trust of every identity. Public principal detection is automatable separately; it does not replace the trust-list predicate.

[Exact upstream source](https://github.com/turbot/steampipe-mod-gcp-perimeter/blob/e2c5a299d1927a41fe8bbd748bdffd295237937c/perimeter/iam_policy_shared_access.pp#L741). [Official documentation 1](https://cloud.google.com/iam/docs/policies).

### gcp-perimeter.control.storage_bucket_policy_shared_access

**mapped-only-archived / owner_policy_required** — Storage bucket IAM policies should only grant access to trusted principals

The resolved shared SQL compares each non-project user/group/domain/service-account member against $1-$4 trusted-principal lists; only-project members produce INFO. IAM APIs expose bindings but do not establish organizational trust of every identity. Public principal detection is automatable separately; it does not replace the trust-list predicate.

[Exact upstream source](https://github.com/turbot/steampipe-mod-gcp-perimeter/blob/e2c5a299d1927a41fe8bbd748bdffd295237937c/perimeter/iam_policy_shared_access.pp#L284). [Official documentation 1](https://cloud.google.com/iam/docs/policies).

### prowler.gcp.compute_public_address_shodan

**rejected / external_observation** — Public IP address is not listed in Shodan

The evaluator constructs shodan.Shodan(shodan_api_key) and calls api.host(address.ip) for EXTERNAL addresses. This useful third-party observation needs external credentials and internet-service data; native external-IP/firewall facts cannot prove Shodan indexing parity. Keep a separately enabled enrichment integration outside provider-read-only coverage rather than mark it semantically covered.

[Exact upstream source](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/compute/compute_public_address_shodan/compute_public_address_shodan.metadata.json). [Official documentation 1](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/compute/compute_public_address_shodan/compute_public_address_shodan.py).

## Complete per-ID index

| Upstream ID | Status | Active native IDs | Changes |
| --- | --- | --- | --- |
| [gcp-compliance.control.allow_only_private_cluster](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/kubernetes.pp#L7) | mapped-active | gcp.gke.private_endpoint |  |
| [gcp-compliance.control.alloydb_cluster_encrypted_with_cmk](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/alloydb.pp#L43) | mapped-active | gcp.ports.alloydb_cluster_encrypted_with_cmk |  |
| [gcp-compliance.control.alloydb_instance_log_error_verbosity_database_flag_default_or_stricter](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/alloydb.pp#L7) | mapped-active | gcp.ports.alloydb_instance_log_error_verbosity_database_flag_default_or_stricter |  |
| [gcp-compliance.control.alloydb_instance_log_min_error_statement_database_flag_configured](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/alloydb.pp#L19) | mapped-active | gcp.ports.alloydb_instance_log_min_error_statement_database_flag_configured |  |
| [gcp-compliance.control.alloydb_instance_log_min_messages_database_flag_error](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/alloydb.pp#L31) | mapped-active | gcp.ports.alloydb_instance_log_min_messages_database_flag_error |  |
| [gcp-compliance.control.app_engine_application_iap_enabled](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/appengine.pp#L17) | mapped-active | gcp.ports.app_engine_application_iap_enabled |  |
| [gcp-compliance.control.audit_logging_configured_for_all_service](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/resourcemanager.pp#L7) | mapped-active | gcp.ports.audit_logging_configured_for_all_service |  |
| [gcp-compliance.control.bigquery_dataset_encrypted_with_cmk](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/bigquery.pp#L47) | mapped-active | gcp.reviewed.bigquery.cmek |  |
| [gcp-compliance.control.bigquery_table_encrypted_with_cmk](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/bigquery.pp#L60) | mapped-active | gcp.ports.bigquery_table_encrypted_with_cmk |  |
| [gcp-compliance.control.cis_v120_1_1](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v120/section_1.pp#L33) | mapped-only-archived |  |  |
| [gcp-compliance.control.cis_v120_1_10](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v120/section_1.pp#L159) | mapped-active | gcp.ports.kms_key_rotated_within_90_day |  |
| [gcp-compliance.control.cis_v120_1_11](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v120/section_1.pp#L173) | mapped-active | gcp.ports.kms_key_separation_of_duties_enforced |  |
| [gcp-compliance.control.cis_v120_1_12](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v120/section_1.pp#L187) | rejected |  |  |
| [gcp-compliance.control.cis_v120_1_13](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v120/section_1.pp#L201) | mapped-active | gcp.ports.iam_api_key_restricts_websites_hosts_apps |  |
| [gcp-compliance.control.cis_v120_1_14](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v120/section_1.pp#L215) | mapped-active | gcp.ports.iam_api_key_restricts_apis |  |
| [gcp-compliance.control.cis_v120_1_15](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v120/section_1.pp#L229) | mapped-active | gcp.ports.iam_api_key_age_90 |  |
| [gcp-compliance.control.cis_v120_1_2](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v120/section_1.pp#L47) | rejected |  |  |
| [gcp-compliance.control.cis_v120_1_3](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v120/section_1.pp#L61) | rejected |  |  |
| [gcp-compliance.control.cis_v120_1_4](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v120/section_1.pp#L75) | mapped-active | gcp.ports.iam_service_account_gcp_managed_key |  |
| [gcp-compliance.control.cis_v120_1_5](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v120/section_1.pp#L89) | mapped-active | gcp.gap.iam_user_managed_sa_no_admin_roles |  |
| [gcp-compliance.control.cis_v120_1_6](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v120/section_1.pp#L103) | mapped-active | gcp.ports.iam_user_not_assigned_service_account_user_role_project_level |  |
| [gcp-compliance.control.cis_v120_1_7](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v120/section_1.pp#L117) | mapped-active | gcp.ports.iam_service_account_key_age_90 |  |
| [gcp-compliance.control.cis_v120_1_8](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v120/section_1.pp#L131) | mapped-active | gcp.ports.iam_user_separation_of_duty_scoped |  |
| [gcp-compliance.control.cis_v120_1_9](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v120/section_1.pp#L145) | mapped-active | gcp.reviewed.kms.no_public_iam |  |
| [gcp-compliance.control.cis_v120_2_1](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v120/section_2.pp#L30) | mapped-active | gcp.ports.audit_logging_configured_for_all_service |  |
| [gcp-compliance.control.cis_v120_2_10](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v120/section_2.pp#L156) | mapped-active | gcp.claude2.logging.metric_alert_bucket_iam_changes |  |
| [gcp-compliance.control.cis_v120_2_11](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v120/section_2.pp#L170) | mapped-active | gcp.claude2.logging.metric_alert_sql_instance_configuration_changes |  |
| [gcp-compliance.control.cis_v120_2_12](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v120/section_2.pp#L184) | mapped-active | gcp.claude.network.dns_logging |  |
| [gcp-compliance.control.cis_v120_2_2](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v120/section_2.pp#L44) | mapped-active | gcp.claude2.logging.sink_all_log_entries |  |
| [gcp-compliance.control.cis_v120_2_3](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v120/section_2.pp#L58) | mapped-active | gcp.claude.bucket.log_sink_retention_locked |  |
| [gcp-compliance.control.cis_v120_2_4](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v120/section_2.pp#L72) | mapped-active | gcp.claude2.logging.metric_alert_project_ownership_changes |  |
| [gcp-compliance.control.cis_v120_2_5](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v120/section_2.pp#L86) | mapped-active | gcp.claude2.logging.metric_alert_audit_configuration_changes |  |
| [gcp-compliance.control.cis_v120_2_6](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v120/section_2.pp#L100) | mapped-active | gcp.claude2.logging.metric_alert_custom_role_changes |  |
| [gcp-compliance.control.cis_v120_2_7](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v120/section_2.pp#L114) | mapped-active | gcp.claude2.logging.metric_alert_firewall_rule_changes |  |
| [gcp-compliance.control.cis_v120_2_8](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v120/section_2.pp#L128) | mapped-active | gcp.claude2.logging.metric_alert_route_changes |  |
| [gcp-compliance.control.cis_v120_2_9](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v120/section_2.pp#L142) | mapped-active | gcp.claude2.logging.metric_alert_network_changes |  |
| [gcp-compliance.control.cis_v120_3_1](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v120/section_3.pp#L28) | mapped-active | gcp.reviewed.network.no_default_vpc |  |
| [gcp-compliance.control.cis_v120_3_10](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v120/section_3.pp#L154) | mapped-active | gcp.ports.firewall_http_lb_proxy_source_restriction |  |
| [gcp-compliance.control.cis_v120_3_2](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v120/section_3.pp#L42) | mapped-active | gcp.ports.compute_network_contains_no_legacy_network |  |
| [gcp-compliance.control.cis_v120_3_3](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v120/section_3.pp#L56) | mapped-active | gcp.claude.dns_zone.dnssec_enabled |  |
| [gcp-compliance.control.cis_v120_3_4](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v120/section_3.pp#L70) | mapped-active | gcp.claude.dns_zone.ksk_not_rsasha1 |  |
| [gcp-compliance.control.cis_v120_3_5](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v120/section_3.pp#L84) | mapped-active | gcp.claude.dns_zone.zsk_not_rsasha1 |  |
| [gcp-compliance.control.cis_v120_3_6](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v120/section_3.pp#L98) | mapped-active | gcp.ports.compute_firewall_rule_ssh_access_restricted |  |
| [gcp-compliance.control.cis_v120_3_7](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v120/section_3.pp#L112) | mapped-active | gcp.ports.compute_firewall_rule_rdp_access_restricted |  |
| [gcp-compliance.control.cis_v120_3_8](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v120/section_3.pp#L126) | mapped-active | gcp.reviewed.network.flow_logs |  |
| [gcp-compliance.control.cis_v120_3_9](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v120/section_3.pp#L140) | mapped-active | gcp.ports.compute_ssl_policy_strict_declaration |  |
| [gcp-compliance.control.cis_v120_4_1](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v120/section_4.pp#L29) | mapped-active | gcp.ports.compute_instance_with_no_default_service_account |  |
| [gcp-compliance.control.cis_v120_4_10](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v120/section_4.pp#L155) | rejected |  |  |
| [gcp-compliance.control.cis_v120_4_11](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v120/section_4.pp#L169) | mapped-active | gcp.reviewed.compute.confidential_computing |  |
| [gcp-compliance.control.cis_v120_4_2](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v120/section_4.pp#L43) | mapped-active | gcp.ports.compute_instance_with_no_default_service_account_with_full_access |  |
| [gcp-compliance.control.cis_v120_4_3](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v120/section_4.pp#L57) | mapped-active | gcp.ports.compute_instance_block_project_wide_ssh_enabled |  |
| [gcp-compliance.control.cis_v120_4_4](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v120/section_4.pp#L71) | mapped-active | gcp.ports.compute_oslogin_metadata_precedence |  |
| [gcp-compliance.control.cis_v120_4_5](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v120/section_4.pp#L85) | mapped-active | gcp.reviewed.compute.no_serial_console |  |
| [gcp-compliance.control.cis_v120_4_6](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v120/section_4.pp#L99) | mapped-active | gcp.ports.compute_instance_ip_forwarding_disabled |  |
| [gcp-compliance.control.cis_v120_4_7](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v120/section_4.pp#L113) | mapped-active | gcp.ports.compute_disk_encrypted_with_csk |  |
| [gcp-compliance.control.cis_v120_4_8](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v120/section_4.pp#L127) | mapped-active | gcp.ports.compute_instance_shielded_vm_enabled |  |
| [gcp-compliance.control.cis_v120_4_9](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v120/section_4.pp#L141) | mapped-active | gcp.ports.compute_instance_with_no_public_ip_addresses |  |
| [gcp-compliance.control.cis_v120_5_1](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v120/section_5.pp#L21) | mapped-active | gcp.storage.no_public_iam |  |
| [gcp-compliance.control.cis_v120_5_2](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v120/section_5.pp#L35) | mapped-active | gcp.storage.uniform_access |  |
| [gcp-compliance.control.cis_v120_6_1_1](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v120/section_6.pp#L59) | rejected |  |  |
| [gcp-compliance.control.cis_v120_6_1_2](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v120/section_6.pp#L73) | mapped-active | gcp.reviewed.sql.mysql_skip_show_database |  |
| [gcp-compliance.control.cis_v120_6_1_3](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v120/section_6.pp#L87) | mapped-active | gcp.reviewed.sql.mysql_local_infile |  |
| [gcp-compliance.control.cis_v120_6_2_1](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v120/section_6.pp#L129) | mapped-active | gcp.ports.sql_instance_postgresql_log_checkpoints_database_flag_on |  |
| [gcp-compliance.control.cis_v120_6_2_10](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v120/section_6.pp#L255) | mapped-active | gcp.ports.sql_instance_postgresql_log_planner_stats_database_flag_off |  |
| [gcp-compliance.control.cis_v120_6_2_11](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v120/section_6.pp#L269) | mapped-active | gcp.ports.sql_instance_postgresql_log_executor_stats_database_flag_off |  |
| [gcp-compliance.control.cis_v120_6_2_12](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v120/section_6.pp#L283) | mapped-active | gcp.ports.sql_instance_postgresql_log_statement_stats_database_flag_off |  |
| [gcp-compliance.control.cis_v120_6_2_13](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v120/section_6.pp#L297) | rejected |  |  |
| [gcp-compliance.control.cis_v120_6_2_14](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v120/section_6.pp#L310) | mapped-active | gcp.ports.sql_instance_postgresql_log_min_error_statement_database_flag_configured |  |
| [gcp-compliance.control.cis_v120_6_2_15](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v120/section_6.pp#L323) | mapped-active | gcp.ports.sql_instance_postgresql_log_temp_files_database_flag_0 |  |
| [gcp-compliance.control.cis_v120_6_2_16](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v120/section_6.pp#L337) | mapped-active | gcp.ports.sql_instance_postgresql_log_min_duration_statement_database_flag_disabled |  |
| [gcp-compliance.control.cis_v120_6_2_2](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v120/section_6.pp#L143) | rejected |  |  |
| [gcp-compliance.control.cis_v120_6_2_3](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v120/section_6.pp#L157) | mapped-active | gcp.reviewed.sql.postgres_log_connections |  |
| [gcp-compliance.control.cis_v120_6_2_4](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v120/section_6.pp#L171) | mapped-active | gcp.reviewed.sql.postgres_log_disconnections |  |
| [gcp-compliance.control.cis_v120_6_2_5](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v120/section_6.pp#L185) | mapped-active | gcp.ports.sql_instance_postgresql_log_duration_database_flag_on |  |
| [gcp-compliance.control.cis_v120_6_2_6](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v120/section_6.pp#L199) | mapped-active | gcp.ports.sql_instance_postgresql_log_lock_waits_database_flag_on |  |
| [gcp-compliance.control.cis_v120_6_2_7](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v120/section_6.pp#L213) | rejected |  |  |
| [gcp-compliance.control.cis_v120_6_2_8](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v120/section_6.pp#L227) | mapped-active | gcp.ports.sql_instance_postgresql_log_hostname_database_flag_configured |  |
| [gcp-compliance.control.cis_v120_6_2_9](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v120/section_6.pp#L241) | mapped-active | gcp.ports.sql_instance_postgresql_log_parser_stats_database_flag_off |  |
| [gcp-compliance.control.cis_v120_6_3_1](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v120/section_6.pp#L370) | mapped-active | gcp.ports.sql_instance_sql_external_scripts_enabled_database_flag_off |  |
| [gcp-compliance.control.cis_v120_6_3_2](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v120/section_6.pp#L383) | mapped-active | gcp.ports.sql_instance_sql_cross_db_ownership_chaining_database_flag_off |  |
| [gcp-compliance.control.cis_v120_6_3_3](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v120/section_6.pp#L396) | mapped-active | gcp.ports.sql_instance_sql_user_connections_database_flag_configured |  |
| [gcp-compliance.control.cis_v120_6_3_4](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v120/section_6.pp#L409) | mapped-active | gcp.ports.sql_instance_sql_user_options_database_flag_not_configured |  |
| [gcp-compliance.control.cis_v120_6_3_5](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v120/section_6.pp#L422) | mapped-active | gcp.ports.sql_instance_sql_remote_access_database_flag_off |  |
| [gcp-compliance.control.cis_v120_6_3_6](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v120/section_6.pp#L435) | mapped-active | gcp.gap.sql_3625_trace_flag_off_cis_v1 |  |
| [gcp-compliance.control.cis_v120_6_3_7](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v120/section_6.pp#L448) | mapped-active | gcp.ports.sql_instance_sql_contained_database_authentication_database_flag_off |  |
| [gcp-compliance.control.cis_v120_6_4](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v120/section_6.pp#L461) | mapped-active | gcp.ports.sql_instance_require_ssl_enabled |  |
| [gcp-compliance.control.cis_v120_6_5](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v120/section_6.pp#L474) | mapped-active | gcp.ports.sql_instance_not_open_to_internet |  |
| [gcp-compliance.control.cis_v120_6_6](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v120/section_6.pp#L487) | mapped-active | gcp.claude.sql_instance.second_gen_no_public_ip |  |
| [gcp-compliance.control.cis_v120_6_7](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v120/section_6.pp#L500) | mapped-active | gcp.sql.backups |  |
| [gcp-compliance.control.cis_v120_7_1](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v120/section_7.pp#L22) | mapped-active | gcp.reviewed.bigquery.no_public_acl |  |
| [gcp-compliance.control.cis_v120_7_2](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v120/section_7.pp#L36) | mapped-active | gcp.ports.bigquery_table_encrypted_with_cmk |  |
| [gcp-compliance.control.cis_v120_7_3](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v120/section_7.pp#L50) | mapped-active | gcp.reviewed.bigquery.cmek |  |
| [gcp-compliance.control.cis_v130_1_1](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v130/section_1.pp#L36) | mapped-only-archived |  |  |
| [gcp-compliance.control.cis_v130_1_10](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v130/section_1.pp#L162) | mapped-active | gcp.ports.kms_key_rotated_within_90_day |  |
| [gcp-compliance.control.cis_v130_1_11](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v130/section_1.pp#L176) | mapped-active | gcp.ports.kms_key_separation_of_duties_enforced |  |
| [gcp-compliance.control.cis_v130_1_12](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v130/section_1.pp#L190) | rejected |  |  |
| [gcp-compliance.control.cis_v130_1_13](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v130/section_1.pp#L204) | mapped-active | gcp.ports.iam_api_key_restricts_websites_hosts_apps |  |
| [gcp-compliance.control.cis_v130_1_14](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v130/section_1.pp#L218) | mapped-active | gcp.ports.iam_api_key_restricts_apis |  |
| [gcp-compliance.control.cis_v130_1_15](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v130/section_1.pp#L232) | mapped-active | gcp.ports.iam_api_key_age_90 |  |
| [gcp-compliance.control.cis_v130_1_16](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v130/section_1.pp#L246) | mapped-active | gcp.ports.organization_essential_contacts_complete |  |
| [gcp-compliance.control.cis_v130_1_17](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v130/section_1.pp#L260) | mapped-active | gcp.ports.dataproc_cluster_encryption_with_cmek |  |
| [gcp-compliance.control.cis_v130_1_18](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v130/section_1.pp#L274) | rejected |  |  |
| [gcp-compliance.control.cis_v130_1_2](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v130/section_1.pp#L50) | rejected |  |  |
| [gcp-compliance.control.cis_v130_1_3](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v130/section_1.pp#L64) | rejected |  |  |
| [gcp-compliance.control.cis_v130_1_4](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v130/section_1.pp#L78) | mapped-active | gcp.ports.iam_service_account_gcp_managed_key |  |
| [gcp-compliance.control.cis_v130_1_5](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v130/section_1.pp#L92) | mapped-active | gcp.gap.iam_user_managed_sa_no_admin_roles |  |
| [gcp-compliance.control.cis_v130_1_6](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v130/section_1.pp#L106) | mapped-active | gcp.ports.iam_user_not_assigned_service_account_user_role_project_level |  |
| [gcp-compliance.control.cis_v130_1_7](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v130/section_1.pp#L120) | mapped-active | gcp.ports.iam_service_account_key_age_90 |  |
| [gcp-compliance.control.cis_v130_1_8](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v130/section_1.pp#L134) | mapped-active | gcp.ports.iam_user_separation_of_duty_scoped |  |
| [gcp-compliance.control.cis_v130_1_9](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v130/section_1.pp#L148) | mapped-active | gcp.reviewed.kms.no_public_iam |  |
| [gcp-compliance.control.cis_v130_2_1](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v130/section_2.pp#L33) | mapped-active | gcp.ports.audit_logging_configured_for_all_service |  |
| [gcp-compliance.control.cis_v130_2_10](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v130/section_2.pp#L159) | mapped-active | gcp.claude2.logging.metric_alert_bucket_iam_changes |  |
| [gcp-compliance.control.cis_v130_2_11](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v130/section_2.pp#L173) | mapped-active | gcp.claude2.logging.metric_alert_sql_instance_configuration_changes |  |
| [gcp-compliance.control.cis_v130_2_12](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v130/section_2.pp#L187) | mapped-active | gcp.claude.network.dns_logging |  |
| [gcp-compliance.control.cis_v130_2_13](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v130/section_2.pp#L201) | mapped-active | gcp.ports.project_service_cloudasset_api_enabled |  |
| [gcp-compliance.control.cis_v130_2_14](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v130/section_2.pp#L215) | rejected |  |  |
| [gcp-compliance.control.cis_v130_2_15](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v130/section_2.pp#L229) | mapped-active | gcp.ports.access_approval_explicit_enrollment |  |
| [gcp-compliance.control.cis_v130_2_2](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v130/section_2.pp#L47) | mapped-active | gcp.claude2.logging.sink_all_log_entries |  |
| [gcp-compliance.control.cis_v130_2_3](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v130/section_2.pp#L61) | mapped-active | gcp.claude.bucket.log_sink_retention_locked |  |
| [gcp-compliance.control.cis_v130_2_4](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v130/section_2.pp#L75) | mapped-active | gcp.claude2.logging.metric_alert_project_ownership_changes |  |
| [gcp-compliance.control.cis_v130_2_5](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v130/section_2.pp#L89) | mapped-active | gcp.claude2.logging.metric_alert_audit_configuration_changes |  |
| [gcp-compliance.control.cis_v130_2_6](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v130/section_2.pp#L103) | mapped-active | gcp.claude2.logging.metric_alert_custom_role_changes |  |
| [gcp-compliance.control.cis_v130_2_7](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v130/section_2.pp#L117) | mapped-active | gcp.claude2.logging.metric_alert_firewall_rule_changes |  |
| [gcp-compliance.control.cis_v130_2_8](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v130/section_2.pp#L131) | mapped-active | gcp.claude2.logging.metric_alert_route_changes |  |
| [gcp-compliance.control.cis_v130_2_9](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v130/section_2.pp#L145) | mapped-active | gcp.claude2.logging.metric_alert_network_changes |  |
| [gcp-compliance.control.cis_v130_3_1](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v130/section_3.pp#L28) | mapped-active | gcp.reviewed.network.no_default_vpc |  |
| [gcp-compliance.control.cis_v130_3_10](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v130/section_3.pp#L154) | mapped-active | gcp.gap.firewall_tcp_ingress_iap_health_check_sources_only |  |
| [gcp-compliance.control.cis_v130_3_2](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v130/section_3.pp#L42) | mapped-active | gcp.ports.compute_network_contains_no_legacy_network |  |
| [gcp-compliance.control.cis_v130_3_3](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v130/section_3.pp#L56) | mapped-active | gcp.claude.dns_zone.dnssec_enabled |  |
| [gcp-compliance.control.cis_v130_3_4](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v130/section_3.pp#L70) | mapped-active | gcp.claude.dns_zone.ksk_not_rsasha1 |  |
| [gcp-compliance.control.cis_v130_3_5](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v130/section_3.pp#L84) | mapped-active | gcp.claude.dns_zone.zsk_not_rsasha1 |  |
| [gcp-compliance.control.cis_v130_3_6](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v130/section_3.pp#L98) | mapped-active | gcp.ports.compute_firewall_rule_ssh_access_restricted |  |
| [gcp-compliance.control.cis_v130_3_7](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v130/section_3.pp#L112) | mapped-active | gcp.ports.compute_firewall_rule_rdp_access_restricted |  |
| [gcp-compliance.control.cis_v130_3_8](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v130/section_3.pp#L126) | mapped-active | gcp.reviewed.network.flow_logs |  |
| [gcp-compliance.control.cis_v130_3_9](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v130/section_3.pp#L140) | mapped-active | gcp.ports.compute_ssl_policy_strict_declaration |  |
| [gcp-compliance.control.cis_v130_4_1](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v130/section_4.pp#L30) | mapped-active | gcp.ports.compute_instance_with_no_default_service_account |  |
| [gcp-compliance.control.cis_v130_4_10](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v130/section_4.pp#L156) | rejected |  |  |
| [gcp-compliance.control.cis_v130_4_11](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v130/section_4.pp#L170) | mapped-active | gcp.reviewed.compute.confidential_computing |  |
| [gcp-compliance.control.cis_v130_4_12](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v130/section_4.pp#L184) | rejected |  |  |
| [gcp-compliance.control.cis_v130_4_2](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v130/section_4.pp#L44) | mapped-active | gcp.ports.compute_instance_with_no_default_service_account_with_full_access |  |
| [gcp-compliance.control.cis_v130_4_3](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v130/section_4.pp#L58) | mapped-active | gcp.ports.compute_instance_block_project_wide_ssh_enabled |  |
| [gcp-compliance.control.cis_v130_4_4](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v130/section_4.pp#L72) | mapped-active | gcp.ports.compute_oslogin_metadata_precedence |  |
| [gcp-compliance.control.cis_v130_4_5](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v130/section_4.pp#L86) | mapped-active | gcp.reviewed.compute.no_serial_console |  |
| [gcp-compliance.control.cis_v130_4_6](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v130/section_4.pp#L100) | mapped-active | gcp.ports.compute_instance_ip_forwarding_disabled |  |
| [gcp-compliance.control.cis_v130_4_7](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v130/section_4.pp#L114) | mapped-active | gcp.ports.compute_disk_encrypted_with_csk |  |
| [gcp-compliance.control.cis_v130_4_8](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v130/section_4.pp#L128) | mapped-active | gcp.ports.compute_instance_shielded_vm_enabled |  |
| [gcp-compliance.control.cis_v130_4_9](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v130/section_4.pp#L142) | mapped-active | gcp.ports.compute_instance_with_no_public_ip_addresses |  |
| [gcp-compliance.control.cis_v130_5_1](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v130/section_5.pp#L21) | mapped-active | gcp.storage.no_public_iam |  |
| [gcp-compliance.control.cis_v130_5_2](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v130/section_5.pp#L35) | mapped-active | gcp.storage.uniform_access |  |
| [gcp-compliance.control.cis_v130_6_1_1](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v130/section_6.pp#L59) | rejected |  |  |
| [gcp-compliance.control.cis_v130_6_1_2](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v130/section_6.pp#L73) | mapped-active | gcp.reviewed.sql.mysql_skip_show_database |  |
| [gcp-compliance.control.cis_v130_6_1_3](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v130/section_6.pp#L87) | mapped-active | gcp.reviewed.sql.mysql_local_infile |  |
| [gcp-compliance.control.cis_v130_6_2_1](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v130/section_6.pp#L122) | rejected |  |  |
| [gcp-compliance.control.cis_v130_6_2_2](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v130/section_6.pp#L136) | mapped-active | gcp.reviewed.sql.postgres_log_connections |  |
| [gcp-compliance.control.cis_v130_6_2_3](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v130/section_6.pp#L150) | mapped-active | gcp.reviewed.sql.postgres_log_disconnections |  |
| [gcp-compliance.control.cis_v130_6_2_4](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v130/section_6.pp#L164) | rejected |  |  |
| [gcp-compliance.control.cis_v130_6_2_5](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v130/section_6.pp#L178) | mapped-active | gcp.ports.sql_instance_postgresql_log_hostname_database_flag_configured |  |
| [gcp-compliance.control.cis_v130_6_2_6](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v130/section_6.pp#L192) | rejected |  |  |
| [gcp-compliance.control.cis_v130_6_2_7](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v130/section_6.pp#L205) | mapped-active | gcp.ports.sql_instance_postgresql_log_min_error_statement_database_flag_configured |  |
| [gcp-compliance.control.cis_v130_6_2_8](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v130/section_6.pp#L218) | mapped-active | gcp.ports.sql_instance_postgresql_log_min_duration_statement_database_flag_disabled |  |
| [gcp-compliance.control.cis_v130_6_2_9](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v130/section_6.pp#L231) | mapped-active | gcp.reviewed.sql.postgres_pgaudit |  |
| [gcp-compliance.control.cis_v130_6_3_1](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v130/section_6.pp#L265) | mapped-active | gcp.ports.sql_instance_sql_external_scripts_enabled_database_flag_off |  |
| [gcp-compliance.control.cis_v130_6_3_2](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v130/section_6.pp#L278) | mapped-active | gcp.ports.sql_instance_sql_cross_db_ownership_chaining_database_flag_off |  |
| [gcp-compliance.control.cis_v130_6_3_3](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v130/section_6.pp#L291) | mapped-active | gcp.ports.sql_instance_sql_user_connections_database_flag_configured |  |
| [gcp-compliance.control.cis_v130_6_3_4](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v130/section_6.pp#L304) | mapped-active | gcp.ports.sql_instance_sql_user_options_database_flag_not_configured |  |
| [gcp-compliance.control.cis_v130_6_3_5](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v130/section_6.pp#L317) | mapped-active | gcp.ports.sql_instance_sql_remote_access_database_flag_off |  |
| [gcp-compliance.control.cis_v130_6_3_6](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v130/section_6.pp#L330) | mapped-active | gcp.gap.sql_3625_trace_flag_off_cis_v1 |  |
| [gcp-compliance.control.cis_v130_6_3_7](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v130/section_6.pp#L343) | mapped-active | gcp.ports.sql_instance_sql_contained_database_authentication_database_flag_off |  |
| [gcp-compliance.control.cis_v130_6_4](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v130/section_6.pp#L356) | mapped-active | gcp.ports.sql_instance_require_ssl_enabled |  |
| [gcp-compliance.control.cis_v130_6_5](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v130/section_6.pp#L369) | mapped-active | gcp.ports.sql_instance_not_open_to_internet |  |
| [gcp-compliance.control.cis_v130_6_6](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v130/section_6.pp#L382) | mapped-active | gcp.claude.sql_instance.second_gen_no_public_ip |  |
| [gcp-compliance.control.cis_v130_6_7](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v130/section_6.pp#L395) | mapped-active | gcp.sql.backups |  |
| [gcp-compliance.control.cis_v130_7_1](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v130/section_7.pp#L22) | mapped-active | gcp.reviewed.bigquery.no_public_acl |  |
| [gcp-compliance.control.cis_v130_7_2](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v130/section_7.pp#L36) | mapped-active | gcp.ports.bigquery_table_encrypted_with_cmk |  |
| [gcp-compliance.control.cis_v130_7_3](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v130/section_7.pp#L50) | mapped-active | gcp.reviewed.bigquery.cmek |  |
| [gcp-compliance.control.cis_v200_1_1](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v200/section_1.pp#L36) | mapped-only-archived |  |  |
| [gcp-compliance.control.cis_v200_1_10](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v200/section_1.pp#L162) | mapped-active | gcp.ports.kms_key_rotated_within_90_day |  |
| [gcp-compliance.control.cis_v200_1_11](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v200/section_1.pp#L176) | mapped-active | gcp.ports.kms_key_separation_of_duties_enforced |  |
| [gcp-compliance.control.cis_v200_1_12](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v200/section_1.pp#L190) | rejected |  |  |
| [gcp-compliance.control.cis_v200_1_13](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v200/section_1.pp#L204) | mapped-active | gcp.ports.iam_api_key_restricts_websites_hosts_apps |  |
| [gcp-compliance.control.cis_v200_1_14](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v200/section_1.pp#L218) | mapped-active | gcp.ports.iam_api_key_restricts_apis |  |
| [gcp-compliance.control.cis_v200_1_15](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v200/section_1.pp#L232) | mapped-active | gcp.ports.iam_api_key_age_90 |  |
| [gcp-compliance.control.cis_v200_1_16](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v200/section_1.pp#L246) | mapped-active | gcp.ports.organization_essential_contacts_complete |  |
| [gcp-compliance.control.cis_v200_1_17](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v200/section_1.pp#L260) | mapped-active | gcp.ports.dataproc_cluster_encryption_with_cmek |  |
| [gcp-compliance.control.cis_v200_1_18](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v200/section_1.pp#L274) | rejected |  |  |
| [gcp-compliance.control.cis_v200_1_2](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v200/section_1.pp#L50) | rejected |  |  |
| [gcp-compliance.control.cis_v200_1_3](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v200/section_1.pp#L64) | rejected |  |  |
| [gcp-compliance.control.cis_v200_1_4](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v200/section_1.pp#L78) | mapped-active | gcp.ports.iam_service_account_gcp_managed_key |  |
| [gcp-compliance.control.cis_v200_1_5](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v200/section_1.pp#L92) | mapped-active | gcp.gap.iam_user_managed_sa_no_admin_roles |  |
| [gcp-compliance.control.cis_v200_1_6](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v200/section_1.pp#L106) | mapped-active | gcp.ports.iam_user_not_assigned_service_account_user_role_project_level |  |
| [gcp-compliance.control.cis_v200_1_7](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v200/section_1.pp#L120) | mapped-active | gcp.ports.iam_service_account_key_age_90 |  |
| [gcp-compliance.control.cis_v200_1_8](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v200/section_1.pp#L134) | mapped-active | gcp.ports.iam_user_separation_of_duty_scoped |  |
| [gcp-compliance.control.cis_v200_1_9](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v200/section_1.pp#L148) | mapped-active | gcp.reviewed.kms.no_public_iam |  |
| [gcp-compliance.control.cis_v200_2_1](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v200/section_2.pp#L34) | mapped-active | gcp.ports.audit_logging_configured_for_all_service |  |
| [gcp-compliance.control.cis_v200_2_10](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v200/section_2.pp#L160) | mapped-active | gcp.claude2.logging.metric_alert_bucket_iam_changes |  |
| [gcp-compliance.control.cis_v200_2_11](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v200/section_2.pp#L174) | mapped-active | gcp.claude2.logging.metric_alert_sql_instance_configuration_changes |  |
| [gcp-compliance.control.cis_v200_2_12](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v200/section_2.pp#L188) | mapped-active | gcp.claude.network.dns_logging |  |
| [gcp-compliance.control.cis_v200_2_13](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v200/section_2.pp#L202) | mapped-active | gcp.ports.project_service_cloudasset_api_enabled |  |
| [gcp-compliance.control.cis_v200_2_14](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v200/section_2.pp#L216) | rejected |  |  |
| [gcp-compliance.control.cis_v200_2_15](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v200/section_2.pp#L230) | mapped-active | gcp.ports.access_approval_explicit_enrollment |  |
| [gcp-compliance.control.cis_v200_2_16](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v200/section_2.pp#L244) | mapped-active | gcp.ports.compute_url_map_backend_logging |  |
| [gcp-compliance.control.cis_v200_2_2](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v200/section_2.pp#L48) | mapped-active | gcp.claude2.logging.sink_all_log_entries |  |
| [gcp-compliance.control.cis_v200_2_3](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v200/section_2.pp#L62) | mapped-active | gcp.claude.bucket.log_sink_retention_locked |  |
| [gcp-compliance.control.cis_v200_2_4](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v200/section_2.pp#L76) | mapped-active | gcp.claude2.logging.metric_alert_project_ownership_changes |  |
| [gcp-compliance.control.cis_v200_2_5](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v200/section_2.pp#L90) | mapped-active | gcp.claude2.logging.metric_alert_audit_configuration_changes |  |
| [gcp-compliance.control.cis_v200_2_6](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v200/section_2.pp#L104) | mapped-active | gcp.claude2.logging.metric_alert_custom_role_changes |  |
| [gcp-compliance.control.cis_v200_2_7](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v200/section_2.pp#L118) | mapped-active | gcp.claude2.logging.metric_alert_firewall_rule_changes |  |
| [gcp-compliance.control.cis_v200_2_8](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v200/section_2.pp#L132) | mapped-active | gcp.claude2.logging.metric_alert_route_changes |  |
| [gcp-compliance.control.cis_v200_2_9](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v200/section_2.pp#L146) | mapped-active | gcp.claude2.logging.metric_alert_network_changes |  |
| [gcp-compliance.control.cis_v200_3_1](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v200/section_3.pp#L28) | mapped-active | gcp.reviewed.network.no_default_vpc |  |
| [gcp-compliance.control.cis_v200_3_10](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v200/section_3.pp#L154) | mapped-active | gcp.gap.firewall_tcp_ingress_iap_health_check_sources_only |  |
| [gcp-compliance.control.cis_v200_3_2](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v200/section_3.pp#L42) | mapped-active | gcp.ports.compute_network_contains_no_legacy_network |  |
| [gcp-compliance.control.cis_v200_3_3](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v200/section_3.pp#L56) | mapped-active | gcp.claude.dns_zone.dnssec_enabled |  |
| [gcp-compliance.control.cis_v200_3_4](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v200/section_3.pp#L70) | mapped-active | gcp.claude.dns_zone.ksk_not_rsasha1 |  |
| [gcp-compliance.control.cis_v200_3_5](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v200/section_3.pp#L84) | mapped-active | gcp.claude.dns_zone.zsk_not_rsasha1 |  |
| [gcp-compliance.control.cis_v200_3_6](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v200/section_3.pp#L98) | mapped-active | gcp.ports.compute_firewall_rule_ssh_access_restricted |  |
| [gcp-compliance.control.cis_v200_3_7](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v200/section_3.pp#L112) | mapped-active | gcp.ports.compute_firewall_rule_rdp_access_restricted |  |
| [gcp-compliance.control.cis_v200_3_8](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v200/section_3.pp#L126) | mapped-active | gcp.reviewed.network.flow_logs |  |
| [gcp-compliance.control.cis_v200_3_9](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v200/section_3.pp#L140) | mapped-active | gcp.ports.compute_ssl_policy_strict_declaration |  |
| [gcp-compliance.control.cis_v200_4_1](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v200/section_4.pp#L30) | mapped-active | gcp.ports.compute_instance_with_no_default_service_account |  |
| [gcp-compliance.control.cis_v200_4_10](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v200/section_4.pp#L156) | rejected |  |  |
| [gcp-compliance.control.cis_v200_4_11](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v200/section_4.pp#L170) | mapped-active | gcp.reviewed.compute.confidential_computing |  |
| [gcp-compliance.control.cis_v200_4_12](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v200/section_4.pp#L184) | rejected |  |  |
| [gcp-compliance.control.cis_v200_4_2](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v200/section_4.pp#L44) | mapped-active | gcp.ports.compute_instance_with_no_default_service_account_with_full_access |  |
| [gcp-compliance.control.cis_v200_4_3](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v200/section_4.pp#L58) | mapped-active | gcp.ports.compute_instance_block_project_wide_ssh_enabled |  |
| [gcp-compliance.control.cis_v200_4_4](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v200/section_4.pp#L72) | mapped-active | gcp.ports.compute_oslogin_metadata_precedence |  |
| [gcp-compliance.control.cis_v200_4_5](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v200/section_4.pp#L86) | mapped-active | gcp.reviewed.compute.no_serial_console |  |
| [gcp-compliance.control.cis_v200_4_6](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v200/section_4.pp#L100) | mapped-active | gcp.ports.compute_instance_ip_forwarding_disabled |  |
| [gcp-compliance.control.cis_v200_4_7](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v200/section_4.pp#L114) | mapped-active | gcp.ports.compute_disk_encrypted_with_csk |  |
| [gcp-compliance.control.cis_v200_4_8](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v200/section_4.pp#L128) | mapped-active | gcp.ports.compute_instance_shielded_vm_enabled |  |
| [gcp-compliance.control.cis_v200_4_9](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v200/section_4.pp#L142) | mapped-active | gcp.ports.compute_instance_with_no_public_ip_addresses |  |
| [gcp-compliance.control.cis_v200_5_1](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v200/section_5.pp#L21) | mapped-active | gcp.storage.no_public_iam |  |
| [gcp-compliance.control.cis_v200_5_2](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v200/section_5.pp#L35) | mapped-active | gcp.storage.uniform_access |  |
| [gcp-compliance.control.cis_v200_6_1_1](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v200/section_6.pp#L59) | rejected |  |  |
| [gcp-compliance.control.cis_v200_6_1_2](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v200/section_6.pp#L73) | mapped-active | gcp.reviewed.sql.mysql_skip_show_database |  |
| [gcp-compliance.control.cis_v200_6_1_3](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v200/section_6.pp#L87) | mapped-active | gcp.reviewed.sql.mysql_local_infile |  |
| [gcp-compliance.control.cis_v200_6_2_1](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v200/section_6.pp#L122) | mapped-active | gcp.ports.sql_instance_postgresql_log_error_verbosity_database_flag_default_or_stricter |  |
| [gcp-compliance.control.cis_v200_6_2_2](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v200/section_6.pp#L136) | mapped-active | gcp.reviewed.sql.postgres_log_connections |  |
| [gcp-compliance.control.cis_v200_6_2_3](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v200/section_6.pp#L150) | mapped-active | gcp.reviewed.sql.postgres_log_disconnections |  |
| [gcp-compliance.control.cis_v200_6_2_4](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v200/section_6.pp#L164) | mapped-active | gcp.reviewed.sql.postgres_log_statement |  |
| [gcp-compliance.control.cis_v200_6_2_5](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v200/section_6.pp#L177) | mapped-active | gcp.ports.sql_instance_postgresql_log_min_messages_database_flag_error |  |
| [gcp-compliance.control.cis_v200_6_2_6](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v200/section_6.pp#L189) | mapped-active | gcp.ports.sql_instance_postgresql_log_min_error_statement_database_flag_configured |  |
| [gcp-compliance.control.cis_v200_6_2_7](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v200/section_6.pp#L202) | mapped-active | gcp.ports.sql_instance_postgresql_log_min_duration_statement_database_flag_disabled |  |
| [gcp-compliance.control.cis_v200_6_2_8](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v200/section_6.pp#L215) | mapped-active | gcp.reviewed.sql.postgres_pgaudit |  |
| [gcp-compliance.control.cis_v200_6_2_9](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v200/section_6.pp#L229) | mapped-active | gcp.claude.sql_instance.private_ip_only |  |
| [gcp-compliance.control.cis_v200_6_3_1](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v200/section_6.pp#L262) | mapped-active | gcp.ports.sql_instance_sql_external_scripts_enabled_database_flag_off |  |
| [gcp-compliance.control.cis_v200_6_3_2](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v200/section_6.pp#L275) | mapped-active | gcp.ports.sql_instance_sql_cross_db_ownership_chaining_database_flag_off |  |
| [gcp-compliance.control.cis_v200_6_3_3](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v200/section_6.pp#L288) | mapped-active | gcp.ports.sql_instance_sql_user_connections_database_flag_configured |  |
| [gcp-compliance.control.cis_v200_6_3_4](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v200/section_6.pp#L301) | mapped-active | gcp.ports.sql_instance_sql_user_options_database_flag_not_configured |  |
| [gcp-compliance.control.cis_v200_6_3_5](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v200/section_6.pp#L314) | mapped-active | gcp.ports.sql_instance_sql_remote_access_database_flag_off |  |
| [gcp-compliance.control.cis_v200_6_3_6](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v200/section_6.pp#L327) | mapped-active | gcp.ports.sql_instance_sql_3625_trace_database_flag_on |  |
| [gcp-compliance.control.cis_v200_6_3_7](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v200/section_6.pp#L340) | mapped-active | gcp.ports.sql_instance_sql_contained_database_authentication_database_flag_off |  |
| [gcp-compliance.control.cis_v200_6_4](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v200/section_6.pp#L353) | mapped-active | gcp.ports.sql_instance_require_ssl_enabled |  |
| [gcp-compliance.control.cis_v200_6_5](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v200/section_6.pp#L366) | mapped-active | gcp.ports.sql_instance_not_open_to_internet |  |
| [gcp-compliance.control.cis_v200_6_6](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v200/section_6.pp#L379) | mapped-active | gcp.claude.sql_instance.second_gen_no_public_ip |  |
| [gcp-compliance.control.cis_v200_6_7](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v200/section_6.pp#L392) | mapped-active | gcp.sql.backups |  |
| [gcp-compliance.control.cis_v200_7_1](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v200/section_7.pp#L22) | mapped-active | gcp.reviewed.bigquery.no_public_acl |  |
| [gcp-compliance.control.cis_v200_7_2](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v200/section_7.pp#L36) | mapped-active | gcp.ports.bigquery_table_encrypted_with_cmk |  |
| [gcp-compliance.control.cis_v200_7_3](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v200/section_7.pp#L50) | mapped-active | gcp.reviewed.bigquery.cmek |  |
| [gcp-compliance.control.cis_v300_1_1](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v300/section_1.pp#L35) | mapped-only-archived |  |  |
| [gcp-compliance.control.cis_v300_1_10](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v300/section_1.pp#L161) | mapped-active | gcp.ports.kms_key_rotated_within_90_day |  |
| [gcp-compliance.control.cis_v300_1_11](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v300/section_1.pp#L175) | mapped-active | gcp.ports.kms_key_separation_of_duties_enforced |  |
| [gcp-compliance.control.cis_v300_1_12](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v300/section_1.pp#L189) | mapped-active | gcp.claude.project.no_api_keys |  |
| [gcp-compliance.control.cis_v300_1_13](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v300/section_1.pp#L203) | mapped-active | gcp.ports.iam_api_key_restricts_websites_hosts_apps |  |
| [gcp-compliance.control.cis_v300_1_14](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v300/section_1.pp#L217) | mapped-active | gcp.ports.iam_api_key_restricts_apis |  |
| [gcp-compliance.control.cis_v300_1_15](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v300/section_1.pp#L231) | mapped-active | gcp.ports.iam_api_key_age_90 |  |
| [gcp-compliance.control.cis_v300_1_16](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v300/section_1.pp#L245) | mapped-active | gcp.ports.organization_essential_contacts_complete |  |
| [gcp-compliance.control.cis_v300_1_17](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v300/section_1.pp#L259) | rejected |  |  |
| [gcp-compliance.control.cis_v300_1_2](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v300/section_1.pp#L49) | rejected |  |  |
| [gcp-compliance.control.cis_v300_1_3](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v300/section_1.pp#L63) | rejected |  |  |
| [gcp-compliance.control.cis_v300_1_4](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v300/section_1.pp#L77) | mapped-active | gcp.ports.iam_service_account_gcp_managed_key |  |
| [gcp-compliance.control.cis_v300_1_5](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v300/section_1.pp#L91) | mapped-active | gcp.gap.iam_user_managed_sa_no_admin_roles |  |
| [gcp-compliance.control.cis_v300_1_6](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v300/section_1.pp#L105) | mapped-active | gcp.ports.iam_user_not_assigned_service_account_user_role_project_level |  |
| [gcp-compliance.control.cis_v300_1_7](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v300/section_1.pp#L119) | mapped-active | gcp.ports.iam_service_account_key_age_90 |  |
| [gcp-compliance.control.cis_v300_1_8](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v300/section_1.pp#L133) | mapped-active | gcp.ports.iam_user_separation_of_duty_scoped |  |
| [gcp-compliance.control.cis_v300_1_9](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v300/section_1.pp#L147) | mapped-active | gcp.reviewed.kms.no_public_iam |  |
| [gcp-compliance.control.cis_v300_2_1](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v300/section_2.pp#L34) | mapped-active | gcp.ports.audit_logging_configured_for_all_service |  |
| [gcp-compliance.control.cis_v300_2_10](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v300/section_2.pp#L160) | mapped-active | gcp.claude2.logging.metric_alert_bucket_iam_changes |  |
| [gcp-compliance.control.cis_v300_2_11](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v300/section_2.pp#L174) | mapped-active | gcp.claude2.logging.metric_alert_sql_instance_configuration_changes |  |
| [gcp-compliance.control.cis_v300_2_12](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v300/section_2.pp#L188) | mapped-active | gcp.claude.network.dns_logging |  |
| [gcp-compliance.control.cis_v300_2_13](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v300/section_2.pp#L202) | mapped-active | gcp.ports.project_service_cloudasset_api_enabled |  |
| [gcp-compliance.control.cis_v300_2_14](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v300/section_2.pp#L216) | rejected |  |  |
| [gcp-compliance.control.cis_v300_2_15](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v300/section_2.pp#L230) | mapped-active | gcp.ports.access_approval_explicit_enrollment |  |
| [gcp-compliance.control.cis_v300_2_16](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v300/section_2.pp#L244) | mapped-active | gcp.ports.compute_url_map_backend_logging |  |
| [gcp-compliance.control.cis_v300_2_2](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v300/section_2.pp#L48) | mapped-active | gcp.claude2.logging.sink_all_log_entries |  |
| [gcp-compliance.control.cis_v300_2_3](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v300/section_2.pp#L62) | mapped-active | gcp.claude.bucket.log_sink_retention_locked |  |
| [gcp-compliance.control.cis_v300_2_4](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v300/section_2.pp#L76) | mapped-active | gcp.claude2.logging.metric_alert_project_ownership_changes |  |
| [gcp-compliance.control.cis_v300_2_5](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v300/section_2.pp#L90) | mapped-active | gcp.claude2.logging.metric_alert_audit_configuration_changes |  |
| [gcp-compliance.control.cis_v300_2_6](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v300/section_2.pp#L104) | mapped-active | gcp.claude2.logging.metric_alert_custom_role_changes |  |
| [gcp-compliance.control.cis_v300_2_7](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v300/section_2.pp#L118) | mapped-active | gcp.claude2.logging.metric_alert_firewall_rule_changes |  |
| [gcp-compliance.control.cis_v300_2_8](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v300/section_2.pp#L132) | mapped-active | gcp.claude2.logging.metric_alert_route_changes |  |
| [gcp-compliance.control.cis_v300_2_9](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v300/section_2.pp#L146) | mapped-active | gcp.claude2.logging.metric_alert_network_changes |  |
| [gcp-compliance.control.cis_v300_3_1](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v300/section_3.pp#L28) | mapped-active | gcp.reviewed.network.no_default_vpc |  |
| [gcp-compliance.control.cis_v300_3_10](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v300/section_3.pp#L154) | mapped-active | gcp.gap.firewall_tcp_ingress_iap_health_check_sources_only |  |
| [gcp-compliance.control.cis_v300_3_2](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v300/section_3.pp#L42) | mapped-active | gcp.ports.compute_network_contains_no_legacy_network |  |
| [gcp-compliance.control.cis_v300_3_3](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v300/section_3.pp#L56) | mapped-active | gcp.claude.dns_zone.dnssec_enabled |  |
| [gcp-compliance.control.cis_v300_3_4](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v300/section_3.pp#L70) | mapped-active | gcp.claude.dns_zone.ksk_not_rsasha1 |  |
| [gcp-compliance.control.cis_v300_3_5](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v300/section_3.pp#L84) | mapped-active | gcp.claude.dns_zone.zsk_not_rsasha1 |  |
| [gcp-compliance.control.cis_v300_3_6](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v300/section_3.pp#L98) | mapped-active | gcp.ports.compute_firewall_rule_ssh_access_restricted |  |
| [gcp-compliance.control.cis_v300_3_7](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v300/section_3.pp#L112) | mapped-active | gcp.ports.compute_firewall_rule_rdp_access_restricted |  |
| [gcp-compliance.control.cis_v300_3_8](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v300/section_3.pp#L126) | mapped-active | gcp.reviewed.network.flow_logs |  |
| [gcp-compliance.control.cis_v300_3_9](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v300/section_3.pp#L140) | mapped-active | gcp.ports.compute_ssl_policy_strict_declaration |  |
| [gcp-compliance.control.cis_v300_4_1](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v300/section_4.pp#L30) | mapped-active | gcp.ports.compute_instance_with_no_default_service_account |  |
| [gcp-compliance.control.cis_v300_4_10](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v300/section_4.pp#L156) | rejected |  |  |
| [gcp-compliance.control.cis_v300_4_11](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v300/section_4.pp#L170) | mapped-active | gcp.reviewed.compute.confidential_computing |  |
| [gcp-compliance.control.cis_v300_4_12](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v300/section_4.pp#L184) | rejected |  |  |
| [gcp-compliance.control.cis_v300_4_2](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v300/section_4.pp#L44) | mapped-active | gcp.ports.compute_instance_with_no_default_service_account_with_full_access |  |
| [gcp-compliance.control.cis_v300_4_3](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v300/section_4.pp#L58) | mapped-active | gcp.ports.compute_instance_block_project_wide_ssh_enabled |  |
| [gcp-compliance.control.cis_v300_4_4](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v300/section_4.pp#L72) | mapped-active | gcp.ports.compute_oslogin_metadata_precedence |  |
| [gcp-compliance.control.cis_v300_4_5](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v300/section_4.pp#L86) | mapped-active | gcp.reviewed.compute.no_serial_console |  |
| [gcp-compliance.control.cis_v300_4_6](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v300/section_4.pp#L100) | mapped-active | gcp.ports.compute_instance_ip_forwarding_disabled |  |
| [gcp-compliance.control.cis_v300_4_7](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v300/section_4.pp#L114) | mapped-active | gcp.ports.compute_disk_encrypted_with_csk |  |
| [gcp-compliance.control.cis_v300_4_8](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v300/section_4.pp#L128) | mapped-active | gcp.ports.compute_instance_shielded_vm_enabled |  |
| [gcp-compliance.control.cis_v300_4_9](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v300/section_4.pp#L142) | mapped-active | gcp.ports.compute_instance_with_no_public_ip_addresses |  |
| [gcp-compliance.control.cis_v300_5_1](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v300/section_5.pp#L21) | mapped-active | gcp.storage.no_public_iam |  |
| [gcp-compliance.control.cis_v300_5_2](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v300/section_5.pp#L35) | mapped-active | gcp.storage.uniform_access |  |
| [gcp-compliance.control.cis_v300_6_1_1](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v300/section_6.pp#L59) | rejected |  |  |
| [gcp-compliance.control.cis_v300_6_1_2](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v300/section_6.pp#L73) | mapped-active | gcp.reviewed.sql.mysql_skip_show_database |  |
| [gcp-compliance.control.cis_v300_6_1_3](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v300/section_6.pp#L87) | mapped-active | gcp.reviewed.sql.mysql_local_infile |  |
| [gcp-compliance.control.cis_v300_6_2_1](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v300/section_6.pp#L121) | mapped-active | gcp.ports.sql_instance_postgresql_log_error_verbosity_database_flag_default_or_stricter |  |
| [gcp-compliance.control.cis_v300_6_2_2](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v300/section_6.pp#L135) | mapped-active | gcp.reviewed.sql.postgres_log_connections |  |
| [gcp-compliance.control.cis_v300_6_2_3](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v300/section_6.pp#L149) | mapped-active | gcp.reviewed.sql.postgres_log_disconnections |  |
| [gcp-compliance.control.cis_v300_6_2_4](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v300/section_6.pp#L163) | mapped-active | gcp.reviewed.sql.postgres_log_statement |  |
| [gcp-compliance.control.cis_v300_6_2_5](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v300/section_6.pp#L176) | mapped-active | gcp.ports.sql_instance_postgresql_log_min_messages_database_flag_error |  |
| [gcp-compliance.control.cis_v300_6_2_6](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v300/section_6.pp#L188) | mapped-active | gcp.ports.sql_instance_postgresql_log_min_error_statement_database_flag_configured |  |
| [gcp-compliance.control.cis_v300_6_2_7](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v300/section_6.pp#L201) | mapped-active | gcp.ports.sql_instance_postgresql_log_min_duration_statement_database_flag_disabled |  |
| [gcp-compliance.control.cis_v300_6_2_8](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v300/section_6.pp#L214) | mapped-active | gcp.reviewed.sql.postgres_pgaudit |  |
| [gcp-compliance.control.cis_v300_6_3_1](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v300/section_6.pp#L246) | mapped-active | gcp.ports.sql_instance_sql_external_scripts_enabled_database_flag_off |  |
| [gcp-compliance.control.cis_v300_6_3_2](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v300/section_6.pp#L259) | mapped-active | gcp.ports.sql_instance_sql_cross_db_ownership_chaining_database_flag_off |  |
| [gcp-compliance.control.cis_v300_6_3_3](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v300/section_6.pp#L272) | mapped-active | gcp.ports.sql_instance_sql_user_connections_database_flag_configured |  |
| [gcp-compliance.control.cis_v300_6_3_4](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v300/section_6.pp#L285) | mapped-active | gcp.ports.sql_instance_sql_user_options_database_flag_not_configured |  |
| [gcp-compliance.control.cis_v300_6_3_5](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v300/section_6.pp#L298) | mapped-active | gcp.ports.sql_instance_sql_remote_access_database_flag_off |  |
| [gcp-compliance.control.cis_v300_6_3_6](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v300/section_6.pp#L311) | mapped-active | gcp.ports.sql_instance_sql_3625_trace_database_flag_on |  |
| [gcp-compliance.control.cis_v300_6_3_7](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v300/section_6.pp#L324) | mapped-active | gcp.ports.sql_instance_sql_contained_database_authentication_database_flag_off |  |
| [gcp-compliance.control.cis_v300_6_4](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v300/section_6.pp#L337) | mapped-active | gcp.ports.sql_instance_require_ssl_enabled |  |
| [gcp-compliance.control.cis_v300_6_5](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v300/section_6.pp#L350) | mapped-active | gcp.ports.sql_instance_not_open_to_internet |  |
| [gcp-compliance.control.cis_v300_6_6](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v300/section_6.pp#L363) | mapped-active | gcp.claude.sql_instance.second_gen_no_public_ip |  |
| [gcp-compliance.control.cis_v300_6_7](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v300/section_6.pp#L376) | mapped-active | gcp.sql.backups |  |
| [gcp-compliance.control.cis_v300_7_1](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v300/section_7.pp#L23) | mapped-active | gcp.reviewed.bigquery.no_public_acl |  |
| [gcp-compliance.control.cis_v300_7_2](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v300/section_7.pp#L37) | mapped-active | gcp.ports.bigquery_table_encrypted_with_cmk |  |
| [gcp-compliance.control.cis_v300_7_3](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v300/section_7.pp#L51) | mapped-active | gcp.reviewed.bigquery.cmek |  |
| [gcp-compliance.control.cis_v300_7_4](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v300/section_7.pp#L65) | rejected |  |  |
| [gcp-compliance.control.cis_v300_8_1](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v300/section_8.pp#L20) | mapped-active | gcp.ports.dataproc_cluster_encryption_with_cmek |  |
| [gcp-compliance.control.cis_v400_1_1](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v400/section_1.pp#L35) | mapped-only-archived |  |  |
| [gcp-compliance.control.cis_v400_1_10](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v400/section_1.pp#L161) | mapped-active | gcp.ports.kms_key_rotated_within_90_day |  |
| [gcp-compliance.control.cis_v400_1_11](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v400/section_1.pp#L175) | mapped-active | gcp.ports.kms_key_separation_of_duties_enforced |  |
| [gcp-compliance.control.cis_v400_1_12](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v400/section_1.pp#L189) | mapped-active | gcp.claude.project.no_api_keys |  |
| [gcp-compliance.control.cis_v400_1_13](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v400/section_1.pp#L203) | mapped-active | gcp.ports.iam_api_key_restricts_websites_hosts_apps |  |
| [gcp-compliance.control.cis_v400_1_14](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v400/section_1.pp#L217) | mapped-active | gcp.ports.iam_api_key_restricts_apis |  |
| [gcp-compliance.control.cis_v400_1_15](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v400/section_1.pp#L231) | mapped-active | gcp.ports.iam_api_key_age_90 |  |
| [gcp-compliance.control.cis_v400_1_16](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v400/section_1.pp#L245) | mapped-active | gcp.ports.organization_essential_contacts_complete |  |
| [gcp-compliance.control.cis_v400_1_17](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v400/section_1.pp#L259) | rejected |  |  |
| [gcp-compliance.control.cis_v400_1_2](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v400/section_1.pp#L49) | rejected |  |  |
| [gcp-compliance.control.cis_v400_1_3](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v400/section_1.pp#L63) | rejected |  |  |
| [gcp-compliance.control.cis_v400_1_4](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v400/section_1.pp#L77) | mapped-active | gcp.ports.iam_service_account_gcp_managed_key |  |
| [gcp-compliance.control.cis_v400_1_5](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v400/section_1.pp#L91) | mapped-active | gcp.gap.iam_user_managed_sa_no_admin_roles |  |
| [gcp-compliance.control.cis_v400_1_6](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v400/section_1.pp#L105) | mapped-active | gcp.ports.iam_user_not_assigned_service_account_user_role_project_level |  |
| [gcp-compliance.control.cis_v400_1_7](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v400/section_1.pp#L119) | mapped-active | gcp.ports.iam_service_account_key_age_90 |  |
| [gcp-compliance.control.cis_v400_1_8](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v400/section_1.pp#L133) | mapped-active | gcp.ports.iam_user_separation_of_duty_scoped |  |
| [gcp-compliance.control.cis_v400_1_9](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v400/section_1.pp#L147) | mapped-active | gcp.reviewed.kms.no_public_iam |  |
| [gcp-compliance.control.cis_v400_2_1](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v400/section_2.pp#L34) | mapped-active | gcp.ports.audit_logging_configured_for_all_service |  |
| [gcp-compliance.control.cis_v400_2_10](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v400/section_2.pp#L160) | mapped-active | gcp.claude2.logging.metric_alert_bucket_iam_changes |  |
| [gcp-compliance.control.cis_v400_2_11](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v400/section_2.pp#L174) | mapped-active | gcp.claude2.logging.metric_alert_sql_instance_configuration_changes |  |
| [gcp-compliance.control.cis_v400_2_12](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v400/section_2.pp#L188) | mapped-active | gcp.claude.network.dns_logging |  |
| [gcp-compliance.control.cis_v400_2_13](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v400/section_2.pp#L202) | mapped-active | gcp.ports.project_service_cloudasset_api_enabled |  |
| [gcp-compliance.control.cis_v400_2_14](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v400/section_2.pp#L216) | rejected |  |  |
| [gcp-compliance.control.cis_v400_2_15](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v400/section_2.pp#L230) | mapped-active | gcp.ports.access_approval_explicit_enrollment |  |
| [gcp-compliance.control.cis_v400_2_16](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v400/section_2.pp#L244) | mapped-active | gcp.ports.compute_url_map_backend_logging |  |
| [gcp-compliance.control.cis_v400_2_2](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v400/section_2.pp#L48) | mapped-active | gcp.claude2.logging.sink_all_log_entries |  |
| [gcp-compliance.control.cis_v400_2_3](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v400/section_2.pp#L62) | mapped-active | gcp.claude.bucket.log_sink_retention_locked |  |
| [gcp-compliance.control.cis_v400_2_4](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v400/section_2.pp#L76) | mapped-active | gcp.claude2.logging.metric_alert_project_ownership_changes |  |
| [gcp-compliance.control.cis_v400_2_5](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v400/section_2.pp#L90) | mapped-active | gcp.claude2.logging.metric_alert_audit_configuration_changes |  |
| [gcp-compliance.control.cis_v400_2_6](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v400/section_2.pp#L104) | mapped-active | gcp.claude2.logging.metric_alert_custom_role_changes_with_undelete |  |
| [gcp-compliance.control.cis_v400_2_7](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v400/section_2.pp#L118) | mapped-active | gcp.claude2.logging.metric_alert_firewall_rule_changes |  |
| [gcp-compliance.control.cis_v400_2_8](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v400/section_2.pp#L132) | mapped-active | gcp.claude2.logging.metric_alert_route_changes |  |
| [gcp-compliance.control.cis_v400_2_9](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v400/section_2.pp#L146) | mapped-active | gcp.claude2.logging.metric_alert_network_changes |  |
| [gcp-compliance.control.cis_v400_3_1](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v400/section_3.pp#L28) | mapped-active | gcp.reviewed.network.no_default_vpc |  |
| [gcp-compliance.control.cis_v400_3_10](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v400/section_3.pp#L154) | mapped-active | gcp.gap.firewall_tcp_ingress_iap_health_check_sources_only |  |
| [gcp-compliance.control.cis_v400_3_2](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v400/section_3.pp#L42) | mapped-active | gcp.ports.compute_network_contains_no_legacy_network |  |
| [gcp-compliance.control.cis_v400_3_3](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v400/section_3.pp#L56) | mapped-active | gcp.claude.dns_zone.dnssec_enabled |  |
| [gcp-compliance.control.cis_v400_3_4](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v400/section_3.pp#L70) | mapped-active | gcp.claude.dns_zone.ksk_not_rsasha1 |  |
| [gcp-compliance.control.cis_v400_3_5](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v400/section_3.pp#L84) | mapped-active | gcp.claude.dns_zone.zsk_not_rsasha1 |  |
| [gcp-compliance.control.cis_v400_3_6](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v400/section_3.pp#L98) | mapped-active | gcp.ports.compute_firewall_rule_ssh_access_restricted |  |
| [gcp-compliance.control.cis_v400_3_7](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v400/section_3.pp#L112) | mapped-active | gcp.ports.compute_firewall_rule_rdp_access_restricted |  |
| [gcp-compliance.control.cis_v400_3_8](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v400/section_3.pp#L126) | mapped-active | gcp.reviewed.network.flow_logs |  |
| [gcp-compliance.control.cis_v400_3_9](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v400/section_3.pp#L140) | mapped-active | gcp.ports.compute_ssl_policy_strict_declaration |  |
| [gcp-compliance.control.cis_v400_4_1](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v400/section_4.pp#L30) | mapped-active | gcp.ports.compute_instance_with_no_default_service_account |  |
| [gcp-compliance.control.cis_v400_4_10](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v400/section_4.pp#L156) | rejected |  |  |
| [gcp-compliance.control.cis_v400_4_11](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v400/section_4.pp#L170) | mapped-active | gcp.reviewed.compute.confidential_computing |  |
| [gcp-compliance.control.cis_v400_4_12](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v400/section_4.pp#L184) | rejected |  |  |
| [gcp-compliance.control.cis_v400_4_2](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v400/section_4.pp#L44) | mapped-active | gcp.ports.compute_instance_with_no_default_service_account_with_full_access |  |
| [gcp-compliance.control.cis_v400_4_3](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v400/section_4.pp#L58) | mapped-active | gcp.ports.compute_instance_block_project_wide_ssh_enabled |  |
| [gcp-compliance.control.cis_v400_4_4](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v400/section_4.pp#L72) | mapped-active | gcp.ports.compute_oslogin_metadata_precedence |  |
| [gcp-compliance.control.cis_v400_4_5](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v400/section_4.pp#L86) | mapped-active | gcp.reviewed.compute.no_serial_console |  |
| [gcp-compliance.control.cis_v400_4_6](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v400/section_4.pp#L100) | mapped-active | gcp.ports.compute_instance_ip_forwarding_disabled |  |
| [gcp-compliance.control.cis_v400_4_7](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v400/section_4.pp#L114) | mapped-active | gcp.ports.compute_disk_encrypted_with_csk |  |
| [gcp-compliance.control.cis_v400_4_8](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v400/section_4.pp#L128) | mapped-active | gcp.ports.compute_instance_shielded_vm_enabled |  |
| [gcp-compliance.control.cis_v400_4_9](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v400/section_4.pp#L142) | mapped-active | gcp.ports.compute_instance_with_no_public_ip_addresses |  |
| [gcp-compliance.control.cis_v400_5_1](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v400/section_5.pp#L21) | mapped-active | gcp.storage.no_public_iam |  |
| [gcp-compliance.control.cis_v400_5_2](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v400/section_5.pp#L35) | mapped-active | gcp.storage.uniform_access |  |
| [gcp-compliance.control.cis_v400_6_1_1](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v400/section_6.pp#L59) | rejected |  |  |
| [gcp-compliance.control.cis_v400_6_1_2](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v400/section_6.pp#L73) | mapped-active | gcp.reviewed.sql.mysql_skip_show_database |  |
| [gcp-compliance.control.cis_v400_6_1_3](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v400/section_6.pp#L87) | mapped-active | gcp.reviewed.sql.mysql_local_infile |  |
| [gcp-compliance.control.cis_v400_6_2_1](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v400/section_6.pp#L121) | mapped-active | gcp.ports.sql_instance_postgresql_log_error_verbosity_database_flag_default_or_stricter |  |
| [gcp-compliance.control.cis_v400_6_2_2](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v400/section_6.pp#L135) | mapped-active | gcp.reviewed.sql.postgres_log_connections |  |
| [gcp-compliance.control.cis_v400_6_2_3](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v400/section_6.pp#L149) | mapped-active | gcp.reviewed.sql.postgres_log_disconnections |  |
| [gcp-compliance.control.cis_v400_6_2_4](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v400/section_6.pp#L163) | mapped-active | gcp.reviewed.sql.postgres_log_statement |  |
| [gcp-compliance.control.cis_v400_6_2_5](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v400/section_6.pp#L176) | mapped-active | gcp.ports.sql_instance_postgresql_log_min_messages_database_flag_error |  |
| [gcp-compliance.control.cis_v400_6_2_6](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v400/section_6.pp#L188) | mapped-active | gcp.ports.sql_instance_postgresql_log_min_error_statement_database_flag_configured |  |
| [gcp-compliance.control.cis_v400_6_2_7](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v400/section_6.pp#L201) | mapped-active | gcp.ports.sql_instance_postgresql_log_min_duration_statement_database_flag_disabled |  |
| [gcp-compliance.control.cis_v400_6_2_8](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v400/section_6.pp#L214) | mapped-active | gcp.reviewed.sql.postgres_pgaudit |  |
| [gcp-compliance.control.cis_v400_6_3_1](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v400/section_6.pp#L246) | mapped-active | gcp.ports.sql_instance_sql_external_scripts_enabled_database_flag_off |  |
| [gcp-compliance.control.cis_v400_6_3_2](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v400/section_6.pp#L259) | mapped-active | gcp.ports.sql_instance_sql_cross_db_ownership_chaining_database_flag_off |  |
| [gcp-compliance.control.cis_v400_6_3_3](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v400/section_6.pp#L272) | mapped-active | gcp.ports.sql_instance_sql_user_connections_database_flag_configured |  |
| [gcp-compliance.control.cis_v400_6_3_4](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v400/section_6.pp#L285) | mapped-active | gcp.ports.sql_instance_sql_user_options_database_flag_not_configured |  |
| [gcp-compliance.control.cis_v400_6_3_5](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v400/section_6.pp#L298) | mapped-active | gcp.ports.sql_instance_sql_remote_access_database_flag_off |  |
| [gcp-compliance.control.cis_v400_6_3_6](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v400/section_6.pp#L311) | mapped-active | gcp.ports.sql_instance_sql_3625_trace_database_flag_on |  |
| [gcp-compliance.control.cis_v400_6_3_7](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v400/section_6.pp#L324) | mapped-active | gcp.ports.sql_instance_sql_contained_database_authentication_database_flag_off |  |
| [gcp-compliance.control.cis_v400_6_4](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v400/section_6.pp#L337) | mapped-active | gcp.ports.sql_instance_require_ssl_enabled |  |
| [gcp-compliance.control.cis_v400_6_5](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v400/section_6.pp#L350) | mapped-active | gcp.ports.sql_instance_not_open_to_internet |  |
| [gcp-compliance.control.cis_v400_6_6](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v400/section_6.pp#L363) | mapped-active | gcp.claude.sql_instance.second_gen_no_public_ip |  |
| [gcp-compliance.control.cis_v400_6_7](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v400/section_6.pp#L376) | mapped-active | gcp.sql.backups |  |
| [gcp-compliance.control.cis_v400_7_1](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v400/section_7.pp#L23) | mapped-active | gcp.reviewed.bigquery.no_public_acl |  |
| [gcp-compliance.control.cis_v400_7_2](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v400/section_7.pp#L37) | mapped-active | gcp.ports.bigquery_table_encrypted_with_cmk |  |
| [gcp-compliance.control.cis_v400_7_3](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v400/section_7.pp#L51) | mapped-active | gcp.reviewed.bigquery.cmek |  |
| [gcp-compliance.control.cis_v400_7_4](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v400/section_7.pp#L65) | rejected |  |  |
| [gcp-compliance.control.cis_v400_8_1](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/cis_v400/section_8.pp#L20) | mapped-active | gcp.ports.dataproc_cluster_encryption_with_cmek |  |
| [gcp-compliance.control.cloudfunction_function_no_deployments_manager_permission](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/cloudfunction.pp#L41) | mapped-active | gcp.ports.function_legacy_deployment_role_declarations |  |
| [gcp-compliance.control.cloudfunction_function_no_disrupt_logging_permission](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/cloudfunction.pp#L49) | mapped-active | gcp.ports.function_logging_mutation_declarations |  |
| [gcp-compliance.control.cloudfunction_function_no_ingress_settings_allow_all](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/cloudfunction.pp#L17) | mapped-active | gcp.claude2.function.ingress_not_allow_all |  |
| [gcp-compliance.control.cloudfunction_function_restrict_public_access](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/cloudfunction.pp#L33) | mapped-active | gcp.claude2.function.not_publicly_accessible |  |
| [gcp-compliance.control.cloudfunction_function_restricted_permission](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/cloudfunction.pp#L25) | mapped-active | gcp.ports.function_basic_role_declarations |  |
| [gcp-compliance.control.cloudfunction_function_vpc_connector_enabled](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/cloudfunction.pp#L7) | mapped-active | gcp.claude2.function.vpc_connector_configured |  |
| [gcp-compliance.control.cloudrun_service_restrict_public_access](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/cloudrun.pp#L7) | mapped-active | gcp.claude2.cloudrun_service.invoker_not_public |  |
| [gcp-compliance.control.cmek_rotation_one_hundred_days](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/kms.pp#L7) | mapped-active | gcp.claude.kms_key.rotation_100_days |  |
| [gcp-compliance.control.compute_backend_bucket_no_dangling_storage_bucket](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/compute.pp#L424) | mapped-active | gcp.claude.backend_bucket.bucket_exists |  |
| [gcp-compliance.control.compute_disk_encrypted_with_csk](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/compute.pp#L73) | mapped-active | gcp.ports.compute_disk_encrypted_with_csk |  |
| [gcp-compliance.control.compute_external_backend_service_iap_enabled](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/compute.pp#L538) | mapped-active | gcp.claude.backend_service.external_iap |  |
| [gcp-compliance.control.compute_firewall_allow_connections_proxied_by_iap](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/compute.pp#L87) | mapped-active | gcp.ports.firewall_http_lb_proxy_source_restriction |  |
| [gcp-compliance.control.compute_firewall_allow_tcp_connections_proxied_by_iap](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/compute.pp#L97) | mapped-active | gcp.gap.firewall_tcp_ingress_iap_health_check_sources_only |  |
| [gcp-compliance.control.compute_firewall_default_rule_restrict_ingress_access_except_http_and_https](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/compute.pp#L596) | mapped-active | gcp.claude.firewall.default_rules_not_open |  |
| [gcp-compliance.control.compute_firewall_rule_ingress_access_restricted_to_dns_port_53](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/compute.pp#L284) | mapped-active | gcp.claude.firewall.public_ingress_dns_port_53 |  |
| [gcp-compliance.control.compute_firewall_rule_ingress_access_restricted_to_ftp_port_21](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/compute.pp#L295) | mapped-active | gcp.claude.firewall.public_ingress_ftp_port_21 |  |
| [gcp-compliance.control.compute_firewall_rule_ingress_access_restricted_to_http_port_80](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/compute.pp#L306) | mapped-active | gcp.claude.firewall.public_ingress_http_port_80 |  |
| [gcp-compliance.control.compute_firewall_rule_ingress_access_restricted_to_microsoft_ds_port_445](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/compute.pp#L328) | mapped-active | gcp.claude.firewall.public_ingress_microsoft_ds_port_445 |  |
| [gcp-compliance.control.compute_firewall_rule_ingress_access_restricted_to_mongo_db_port_27017](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/compute.pp#L339) | mapped-active | gcp.claude.firewall.public_ingress_mongo_db_port_27017 |  |
| [gcp-compliance.control.compute_firewall_rule_ingress_access_restricted_to_mysql_db_port_3306](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/compute.pp#L349) | mapped-active | gcp.claude.firewall.public_ingress_mysql_db_port_3306 |  |
| [gcp-compliance.control.compute_firewall_rule_ingress_access_restricted_to_netbios_snn_port_139](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/compute.pp#L360) | mapped-active | gcp.claude.firewall.public_ingress_netbios_snn_port_139 |  |
| [gcp-compliance.control.compute_firewall_rule_ingress_access_restricted_to_oracle_db_port_1521](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/compute.pp#L370) | mapped-active | gcp.claude.firewall.public_ingress_oracle_db_port_1521 |  |
| [gcp-compliance.control.compute_firewall_rule_ingress_access_restricted_to_pop3_port_110](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/compute.pp#L381) | mapped-active | gcp.claude.firewall.public_ingress_pop3_port_110 |  |
| [gcp-compliance.control.compute_firewall_rule_ingress_access_restricted_to_postgresql_port_10250](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/compute.pp#L557) | mapped-active | gcp.claude.firewall.public_ingress_postgresql_port_10250 |  |
| [gcp-compliance.control.compute_firewall_rule_ingress_access_restricted_to_postgresql_port_10255](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/compute.pp#L567) | mapped-active | gcp.claude.firewall.public_ingress_postgresql_port_10255 |  |
| [gcp-compliance.control.compute_firewall_rule_ingress_access_restricted_to_postgresql_port_5432](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/compute.pp#L392) | mapped-active | gcp.claude.firewall.public_ingress_postgresql_port_5432 |  |
| [gcp-compliance.control.compute_firewall_rule_ingress_access_restricted_to_smtp_port_25](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/compute.pp#L317) | mapped-active | gcp.claude.firewall.public_ingress_smtp_port_25 |  |
| [gcp-compliance.control.compute_firewall_rule_ingress_access_restricted_to_tcp_port_137_to_139](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/compute.pp#L716) | mapped-active | gcp.claude.firewall.public_ingress_tcp_port_137_to_139 |  |
| [gcp-compliance.control.compute_firewall_rule_ingress_access_restricted_to_tcp_port_27017_to_27019](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/compute.pp#L727) | mapped-active | gcp.claude.firewall.public_ingress_tcp_port_27017_to_27019 |  |
| [gcp-compliance.control.compute_firewall_rule_ingress_access_restricted_to_tcp_port_61620_61621](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/compute.pp#L694) | mapped-active | gcp.claude.firewall.public_ingress_tcp_port_61620_61621 |  |
| [gcp-compliance.control.compute_firewall_rule_ingress_access_restricted_to_tcp_port_636](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/compute.pp#L738) | mapped-active | gcp.claude.firewall.public_ingress_tcp_port_636 |  |
| [gcp-compliance.control.compute_firewall_rule_ingress_access_restricted_to_tcp_port_6379](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/compute.pp#L705) | mapped-active | gcp.claude.firewall.public_ingress_tcp_port_6379 |  |
| [gcp-compliance.control.compute_firewall_rule_ingress_access_restricted_to_tcp_port_7000_7001](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/compute.pp#L639) | mapped-active | gcp.claude.firewall.public_ingress_tcp_port_7000_7001 |  |
| [gcp-compliance.control.compute_firewall_rule_ingress_access_restricted_to_tcp_port_7199](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/compute.pp#L650) | mapped-active | gcp.claude.firewall.public_ingress_tcp_port_7199 |  |
| [gcp-compliance.control.compute_firewall_rule_ingress_access_restricted_to_tcp_port_8888](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/compute.pp#L661) | mapped-active | gcp.claude.firewall.public_ingress_tcp_port_8888 |  |
| [gcp-compliance.control.compute_firewall_rule_ingress_access_restricted_to_tcp_port_9042](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/compute.pp#L672) | mapped-active | gcp.claude.firewall.public_ingress_tcp_port_9042 |  |
| [gcp-compliance.control.compute_firewall_rule_ingress_access_restricted_to_tcp_port_9090](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/compute.pp#L606) | mapped-active | gcp.claude.firewall.public_ingress_tcp_port_9090 |  |
| [gcp-compliance.control.compute_firewall_rule_ingress_access_restricted_to_tcp_port_9160](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/compute.pp#L683) | mapped-active | gcp.claude.firewall.public_ingress_tcp_port_9160 |  |
| [gcp-compliance.control.compute_firewall_rule_ingress_access_restricted_to_tcp_port_9200_9300](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/compute.pp#L617) | mapped-active | gcp.claude.firewall.public_ingress_tcp_port_9200_9300 |  |
| [gcp-compliance.control.compute_firewall_rule_ingress_access_restricted_to_tcp_udp_port_11211](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/compute.pp#L760) | mapped-active | gcp.claude.firewall.public_ingress_tcp_udp_port_11211 |  |
| [gcp-compliance.control.compute_firewall_rule_ingress_access_restricted_to_tcp_udp_port_11214_to_11215](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/compute.pp#L771) | mapped-active | gcp.claude.firewall.public_ingress_tcp_udp_port_11214_to_11215 |  |
| [gcp-compliance.control.compute_firewall_rule_ingress_access_restricted_to_tcp_udp_port_2483_to_2484](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/compute.pp#L782) | mapped-active | gcp.claude.firewall.public_ingress_tcp_udp_port_2483_to_2484 |  |
| [gcp-compliance.control.compute_firewall_rule_ingress_access_restricted_to_tcp_udp_port_389](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/compute.pp#L749) | mapped-active | gcp.claude.firewall.public_ingress_tcp_udp_port_389 |  |
| [gcp-compliance.control.compute_firewall_rule_ingress_access_restricted_to_telnet_port_23](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/compute.pp#L403) | mapped-active | gcp.claude.firewall.public_ingress_telnet_port_23 |  |
| [gcp-compliance.control.compute_firewall_rule_logging_enabled](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/compute.pp#L628) | mapped-active | gcp.claude.firewall.logging_enabled |  |
| [gcp-compliance.control.compute_firewall_rule_restrict_ingress_all](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/compute.pp#L577) | mapped-active | gcp.claude.firewall.public_ingress_all_protocols |  |
| [gcp-compliance.control.compute_firewall_rule_restrict_ingress_all_with_no_specific_target](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/compute.pp#L546) | mapped-active | gcp.claude.firewall.public_ingress_without_target |  |
| [gcp-compliance.control.compute_https_load_balancer_logging_enabled](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/compute.pp#L107) | mapped-active | gcp.ports.compute_url_map_backend_logging |  |
| [gcp-compliance.control.compute_instance_block_project_wide_ssh_enabled](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/compute.pp#L120) | mapped-active | gcp.ports.compute_instance_block_project_wide_ssh_enabled |  |
| [gcp-compliance.control.compute_instance_confidential_computing_enabled](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/compute.pp#L133) | mapped-active | gcp.reviewed.compute.confidential_computing |  |
| [gcp-compliance.control.compute_instance_ip_forwarding_disabled](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/compute.pp#L146) | mapped-active | gcp.ports.compute_instance_ip_forwarding_disabled |  |
| [gcp-compliance.control.compute_instance_no_data_destruction_permission](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/compute.pp#L496) | mapped-active | gcp.claude.instance.sa_no_data_destruction_permission |  |
| [gcp-compliance.control.compute_instance_no_database_write_permission](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/compute.pp#L488) | mapped-active | gcp.claude.instance.sa_no_database_write_permission |  |
| [gcp-compliance.control.compute_instance_no_deployments_manager_permission](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/compute.pp#L480) | mapped-active | gcp.claude.instance.sa_no_deployments_manager_permission |  |
| [gcp-compliance.control.compute_instance_no_disrupt_logging_permission](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/compute.pp#L472) | mapped-active | gcp.claude.instance.sa_no_disrupt_logging_permission |  |
| [gcp-compliance.control.compute_instance_no_iam_write_permission](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/compute.pp#L588) | mapped-active | gcp.claude.instance.sa_no_iam_write_permission |  |
| [gcp-compliance.control.compute_instance_no_service_account_impersonate_permission](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/compute.pp#L504) | mapped-active | gcp.claude.instance.sa_no_service_account_impersonate_permission |  |
| [gcp-compliance.control.compute_instance_no_write_permission_on_deny_policy](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/compute.pp#L512) | mapped-active | gcp.claude.instance.sa_no_deny_policy_write_permission |  |
| [gcp-compliance.control.compute_instance_oslogin_enabled](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/compute.pp#L157) | mapped-active | gcp.ports.compute_oslogin_metadata_precedence |  |
| [gcp-compliance.control.compute_instance_preemptible_termination_disabled](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/compute.pp#L432) | mapped-active | gcp.claude.instance.not_preemptible |  |
| [gcp-compliance.control.compute_instance_serial_port_connection_disabled](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/compute.pp#L169) | mapped-active | gcp.reviewed.compute.no_serial_console |  |
| [gcp-compliance.control.compute_instance_shielded_vm_enabled](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/compute.pp#L181) | mapped-active | gcp.ports.compute_instance_shielded_vm_enabled |  |
| [gcp-compliance.control.compute_instance_template_ip_forwarding_disabled](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/compute.pp#L448) | mapped-active | gcp.claude.instance_template.no_ip_forwarding |  |
| [gcp-compliance.control.compute_instance_with_custom_metadata](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/compute.pp#L440) | rejected |  |  |
| [gcp-compliance.control.compute_instance_with_no_default_service_account](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/compute.pp#L204) | mapped-active | gcp.ports.compute_instance_with_no_default_service_account |  |
| [gcp-compliance.control.compute_instance_with_no_default_service_account_with_full_access](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/compute.pp#L191) | mapped-active | gcp.ports.compute_instance_with_no_default_service_account_with_full_access |  |
| [gcp-compliance.control.compute_instance_with_no_public_ip_addresses](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/compute.pp#L218) | mapped-active | gcp.ports.compute_instance_with_no_public_ip_addresses |  |
| [gcp-compliance.control.compute_instance_wth_no_high_level_basic_role](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/compute.pp#L520) | mapped-active | gcp.claude.instance.sa_no_basic_role |  |
| [gcp-compliance.control.compute_network_auto_create_subnetwork_enabled](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/compute.pp#L414) | mapped-active | gcp.ports.compute_network_contains_no_legacy_network |  |
| [gcp-compliance.control.compute_network_contains_no_default_network](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/compute.pp#L233) | mapped-active | gcp.reviewed.network.no_default_vpc |  |
| [gcp-compliance.control.compute_network_contains_no_legacy_network](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/compute.pp#L246) | mapped-active | gcp.ports.compute_network_contains_no_legacy_network |  |
| [gcp-compliance.control.compute_network_dns_logging_enabled](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/compute.pp#L259) | mapped-active | gcp.claude.network.dns_logging |  |
| [gcp-compliance.control.compute_ssl_policy_with_no_weak_cipher](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/compute.pp#L273) | mapped-active | gcp.ports.compute_ssl_policy_strict_declaration |  |
| [gcp-compliance.control.compute_target_https_proxy_quic_protocol_enabled](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/compute.pp#L456) | rejected |  |  |
| [gcp-compliance.control.compute_target_https_proxy_quic_protocol_no_default_ssl_policy](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/compute.pp#L464) | mapped-active | gcp.claude.target_proxy.https_custom_ssl_policy |  |
| [gcp-compliance.control.compute_target_https_uses_latest_tls_version](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/compute.pp#L528) | mapped-active | gcp.claude.target_proxy.https_min_tls_1_2 |  |
| [gcp-compliance.control.dataproc_cluster_encryption_with_cmek](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/dataproc.pp#L7) | mapped-active | gcp.ports.dataproc_cluster_encryption_with_cmek |  |
| [gcp-compliance.control.denylist_public_users](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/iam.pp#L7) | mapped-active | gcp.claude.iam_policy.no_all_users |  |
| [gcp-compliance.control.disable_gke_dashboard](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/kubernetes.pp#L18) | mapped-active | gcp.claude.gke.dashboard_disabled |  |
| [gcp-compliance.control.disable_gke_default_service_account](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/kubernetes.pp#L29) | mapped-active | gcp.claude.gke.nodes_no_default_service_account |  |
| [gcp-compliance.control.disable_gke_legacy_abac](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/kubernetes.pp#L39) | mapped-active | gcp.gke.no_legacy_abac |  |
| [gcp-compliance.control.disable_gke_legacy_endpoints](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/kubernetes.pp#L50) | mapped-active | gcp.ports.kubernetes_cluster_legacy_endpoints_disabled |  |
| [gcp-compliance.control.dns_managed_zone_dnssec_enabled](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/dns.pp#L30) | mapped-active | gcp.claude.dns_zone.dnssec_enabled |  |
| [gcp-compliance.control.dnssec_prevent_rsasha1_ksk](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/dns.pp#L7) | mapped-active | gcp.claude.dns_zone.ksk_not_rsasha1 |  |
| [gcp-compliance.control.dnssec_prevent_rsasha1_zsk](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/dns.pp#L20) | mapped-active | gcp.claude.dns_zone.zsk_not_rsasha1 |  |
| [gcp-compliance.control.enable_alias_ip_ranges](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/kubernetes.pp#L60) | mapped-active | gcp.ports.kubernetes_cluster_use_ip_aliases |  |
| [gcp-compliance.control.enable_auto_repair](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/kubernetes.pp#L71) | mapped-active | gcp.ports.kubernetes_cluster_auto_repair_enabled |  |
| [gcp-compliance.control.enable_auto_upgrade](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/kubernetes.pp#L82) | mapped-active | gcp.ports.kubernetes_cluster_auto_upgrade_enabled |  |
| [gcp-compliance.control.enable_gke_master_authorized_networks](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/kubernetes.pp#L94) | mapped-active | gcp.gke.authorized_networks |  |
| [gcp-compliance.control.enable_network_flow_logs](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/compute.pp#L20) | mapped-active | gcp.reviewed.network.flow_logs |  |
| [gcp-compliance.control.enable_network_private_google_access](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/compute.pp#L35) | mapped-active | gcp.subnetwork.private_google_access |  |
| [gcp-compliance.control.gke_container_optimized_os](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/kubernetes.pp#L106) | mapped-active | gcp.ports.kubernetes_cluster_node_config_image_cos_containerd |  |
| [gcp-compliance.control.gke_restrict_pod_traffic](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/kubernetes.pp#L117) | mapped-active | gcp.gke.network_policy |  |
| [gcp-compliance.control.iam_api_key_age_90](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/iam.pp#L61) | mapped-active | gcp.ports.iam_api_key_age_90 |  |
| [gcp-compliance.control.iam_api_key_restricts_apis](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/iam.pp#L72) | mapped-active | gcp.ports.iam_api_key_restricts_apis |  |
| [gcp-compliance.control.iam_api_key_restricts_websites_hosts_apps](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/iam.pp#L83) | mapped-active | gcp.ports.iam_api_key_restricts_websites_hosts_apps |  |
| [gcp-compliance.control.iam_restrict_service_account_key_age_one_hundred_days](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/iam.pp#L30) | mapped-active | gcp.claude.service_account_key.age_100_days |  |
| [gcp-compliance.control.iam_service_account_gcp_managed_key](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/iam.pp#L41) | mapped-active | gcp.ports.iam_service_account_gcp_managed_key |  |
| [gcp-compliance.control.iam_service_account_key_age_90](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/iam.pp#L51) | mapped-active | gcp.ports.iam_service_account_key_age_90 |  |
| [gcp-compliance.control.iam_service_account_without_admin_privilege](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/iam.pp#L93) | mapped-active | gcp.gap.iam_user_managed_sa_no_admin_roles |  |
| [gcp-compliance.control.iam_user_kms_separation_of_duty_enforced](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/iam.pp#L134) | mapped-active | gcp.ports.kms_key_separation_of_duties_enforced |  |
| [gcp-compliance.control.iam_user_not_assigned_service_account_user_role_project_level](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/iam.pp#L106) | mapped-active | gcp.ports.iam_user_not_assigned_service_account_user_role_project_level |  |
| [gcp-compliance.control.iam_user_separation_of_duty_enforced](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/iam.pp#L121) | mapped-active | gcp.ports.iam_user_separation_of_duty_scoped |  |
| [gcp-compliance.control.kms_key_not_publicly_accessible](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/kms.pp#L18) | mapped-active | gcp.reviewed.kms.no_public_iam |  |
| [gcp-compliance.control.kms_key_rotated_within_90_day](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/kms.pp#L32) | mapped-active | gcp.ports.kms_key_rotated_within_90_day |  |
| [gcp-compliance.control.kms_key_separation_of_duties_enforced](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/kms.pp#L47) | mapped-active | gcp.ports.kms_key_separation_of_duties_enforced |  |
| [gcp-compliance.control.kms_key_users_limited_to_3](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/kms.pp#L61) | mapped-active | gcp.claude.kms_key.users_limited_to_3 |  |
| [gcp-compliance.control.kubernetes_cluster_binary_authorization_enabled](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/kubernetes.pp#L202) | mapped-active | gcp.claude.gke.binary_authorization |  |
| [gcp-compliance.control.kubernetes_cluster_client_certificate_authentication_enabled](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/kubernetes.pp#L249) | mapped-active | gcp.claude.gke.no_client_certificate |  |
| [gcp-compliance.control.kubernetes_cluster_database_encryption_enabled](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/kubernetes.pp#L174) | mapped-active | gcp.gke.secrets_encryption |  |
| [gcp-compliance.control.kubernetes_cluster_http_load_balancing_enabled](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/kubernetes.pp#L287) | mapped-active | gcp.claude.gke.http_load_balancing |  |
| [gcp-compliance.control.kubernetes_cluster_incoming_traffic_open_to_all](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/kubernetes.pp#L279) | mapped-active | gcp.claude.gke.network_no_untargeted_public_ingress |  |
| [gcp-compliance.control.kubernetes_cluster_intra_node_visibility_enabled](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/kubernetes.pp#L295) | mapped-active | gcp.ports.kubernetes_cluster_intra_node_visibility_enabled |  |
| [gcp-compliance.control.kubernetes_cluster_kubernetes_alpha_enabled](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/kubernetes.pp#L127) | mapped-active | gcp.claude.gke.no_kubernetes_alpha |  |
| [gcp-compliance.control.kubernetes_cluster_logging_enabled](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/kubernetes.pp#L135) | mapped-active | gcp.claude.gke.logging_enabled |  |
| [gcp-compliance.control.kubernetes_cluster_monitoring_enabled](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/kubernetes.pp#L146) | mapped-active | gcp.claude.gke.monitoring_enabled |  |
| [gcp-compliance.control.kubernetes_cluster_network_policy_enabled](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/kubernetes.pp#L238) | mapped-active | gcp.gke.network_policy |  |
| [gcp-compliance.control.kubernetes_cluster_no_default_network](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/kubernetes.pp#L156) | mapped-active | gcp.claude.gke.no_default_network |  |
| [gcp-compliance.control.kubernetes_cluster_node_no_default_service_account](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/kubernetes.pp#L259) | mapped-active | gcp.claude.gke.nodes_no_default_service_account |  |
| [gcp-compliance.control.kubernetes_cluster_private_nodes_configured](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/kubernetes.pp#L228) | mapped-active | gcp.gke.private_nodes |  |
| [gcp-compliance.control.kubernetes_cluster_release_channel_configured](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/kubernetes.pp#L212) | mapped-active | gcp.claude.gke.release_channel |  |
| [gcp-compliance.control.kubernetes_cluster_shielded_instance_integrity_monitoring_enabled](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/kubernetes.pp#L192) | mapped-active | gcp.ports.kubernetes_cluster_shielded_instance_integrity_monitoring_enabled |  |
| [gcp-compliance.control.kubernetes_cluster_shielded_node_secure_boot_enabled](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/kubernetes.pp#L303) | mapped-active | gcp.ports.kubernetes_cluster_shielded_node_secure_boot_enabled |  |
| [gcp-compliance.control.kubernetes_cluster_shielded_nodes_enabled](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/kubernetes.pp#L182) | mapped-active | gcp.gke.shielded_nodes |  |
| [gcp-compliance.control.kubernetes_cluster_subnetwork_private_ip_google_access_enabled](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/kubernetes.pp#L313) | mapped-active | gcp.claude.gke.subnetwork_private_google_access |  |
| [gcp-compliance.control.kubernetes_cluster_with_less_than_three_node_auto_upgrade_enabled](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/kubernetes.pp#L269) | rejected |  |  |
| [gcp-compliance.control.kubernetes_cluster_with_resource_labels](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/kubernetes.pp#L166) | rejected |  |  |
| [gcp-compliance.control.kubernetes_cluster_zone_redundant](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/kubernetes.pp#L220) | mapped-active | gcp.claude.gke.zone_redundant |  |
| [gcp-compliance.control.logging_bucket_retention_policy_enabled](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/logging.pp#L7) | mapped-active | gcp.claude.bucket.log_sink_retention_locked |  |
| [gcp-compliance.control.logging_metric_alert_audit_configuration_changes](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/logging.pp#L17) | mapped-active | gcp.claude.logging.metric_alert_audit_configuration_changes |  |
| [gcp-compliance.control.logging_metric_alert_custom_role_changes](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/logging.pp#L30) | mapped-active | gcp.claude.logging.metric_alert_custom_role_changes |  |
| [gcp-compliance.control.logging_metric_alert_custom_role_changes_with_iam_admin_undelete_role](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/logging.pp#L43) | mapped-active | gcp.claude.logging.metric_alert_custom_role_changes_with_undelete |  |
| [gcp-compliance.control.logging_metric_alert_firewall_rule_changes](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/logging.pp#L53) | mapped-active | gcp.claude.logging.metric_alert_firewall_rule_changes |  |
| [gcp-compliance.control.logging_metric_alert_network_changes](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/logging.pp#L66) | mapped-active | gcp.claude.logging.metric_alert_network_changes_beta_methods |  |
| [gcp-compliance.control.logging_metric_alert_network_route_changes](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/logging.pp#L79) | mapped-active | gcp.claude.logging.metric_alert_route_changes |  |
| [gcp-compliance.control.logging_metric_alert_project_ownership_assignment](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/logging.pp#L92) | mapped-active | gcp.claude.logging.metric_alert_project_ownership_changes |  |
| [gcp-compliance.control.logging_metric_alert_sql_instance_configuration_changes](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/logging.pp#L105) | mapped-active | gcp.claude.logging.metric_alert_sql_instance_configuration_changes |  |
| [gcp-compliance.control.logging_metric_alert_storage_iam_permission_changes](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/logging.pp#L118) | mapped-active | gcp.claude.logging.metric_alert_bucket_iam_changes |  |
| [gcp-compliance.control.logging_sink_configured_for_all_resource](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/logging.pp#L131) | mapped-active | gcp.claude.logging.project_sink_all_entries |  |
| [gcp-compliance.control.only_my_domain](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/iam.pp#L19) | mapped-only-archived |  |  |
| [gcp-compliance.control.organization_essential_contacts_configured](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/organization.pp#L7) | mapped-active | gcp.ports.organization_essential_contacts_complete |  |
| [gcp-compliance.control.prevent_public_ip_cloudsql](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/sql.pp#L20) | mapped-active | gcp.claude.sql_instance.second_gen_no_public_ip |  |
| [gcp-compliance.control.project_access_approval_settings_enabled](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/project.pp#L7) | mapped-active | gcp.ports.access_approval_explicit_enrollment |  |
| [gcp-compliance.control.project_no_api_key](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/project.pp#L31) | mapped-active | gcp.claude.project.no_api_keys |  |
| [gcp-compliance.control.project_oslogin_enabled](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/project.pp#L49) | mapped-active | gcp.claude.project.oslogin_enabled |  |
| [gcp-compliance.control.project_service_cloudasset_api_enabled](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/project.pp#L17) | mapped-active | gcp.ports.project_service_cloudasset_api_enabled |  |
| [gcp-compliance.control.project_service_container_scanning_api_enabled](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/project.pp#L39) | mapped-active | gcp.claude.project.container_scanning_api_enabled |  |
| [gcp-compliance.control.require_bq_table_iam](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/bigquery.pp#L7) | mapped-active | gcp.reviewed.bigquery.no_public_acl |  |
| [gcp-compliance.control.require_bucket_policy_only](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/storage.pp#L7) | mapped-active | gcp.storage.uniform_access |  |
| [gcp-compliance.control.require_ssl_sql](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/sql.pp#L33) | mapped-active | gcp.ports.sql_instance_require_ssl_enabled |  |
| [gcp-compliance.control.restrict_firewall_rule_rdp_world_open](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/compute.pp#L7) | mapped-active | gcp.ports.compute_firewall_rule_rdp_access_restricted |  |
| [gcp-compliance.control.restrict_firewall_rule_ssh_world_open](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/compute.pp#L46) | mapped-active | gcp.ports.compute_firewall_rule_ssh_access_restricted |  |
| [gcp-compliance.control.restrict_firewall_rule_world_open_tcp_udp_all_ports](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/compute.pp#L61) | mapped-active | gcp.claude.firewall.public_ingress_tcp_udp |  |
| [gcp-compliance.control.restrict_gmail_bigquery_dataset](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/bigquery.pp#L23) | mapped-active | gcp.claude.bigquery_dataset.no_gmail_access |  |
| [gcp-compliance.control.restrict_googlegroups_bigquery_dataset](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/bigquery.pp#L35) | mapped-active | gcp.claude.bigquery_dataset.no_googlegroups_access |  |
| [gcp-compliance.control.service_versions](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/appengine.pp#L7) | rejected |  |  |
| [gcp-compliance.control.sql_instance_automated_backups_enabled](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/sql.pp#L45) | mapped-active | gcp.sql.backups |  |
| [gcp-compliance.control.sql_instance_mysql_binary_log_enabled](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/sql.pp#L367) | mapped-active | gcp.ports.sql_instance_mysql_binary_log_enabled |  |
| [gcp-compliance.control.sql_instance_mysql_local_infile_database_flag_off](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/sql.pp#L57) | mapped-active | gcp.reviewed.sql.mysql_local_infile |  |
| [gcp-compliance.control.sql_instance_mysql_skip_show_database_flag_on](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/sql.pp#L68) | mapped-active | gcp.reviewed.sql.mysql_skip_show_database |  |
| [gcp-compliance.control.sql_instance_not_publicly_accessible](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/sql.pp#L81) | mapped-active | gcp.claude.sql_instance.private_ip_only |  |
| [gcp-compliance.control.sql_instance_postgresql_cloudsql_pgaudit_database_flag_enabled](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/sql.pp#L94) | mapped-active | gcp.reviewed.sql.postgres_pgaudit |  |
| [gcp-compliance.control.sql_instance_postgresql_log_checkpoints_database_flag_on](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/sql.pp#L105) | mapped-active | gcp.ports.sql_instance_postgresql_log_checkpoints_database_flag_on |  |
| [gcp-compliance.control.sql_instance_postgresql_log_connections_database_flag_on](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/sql.pp#L115) | mapped-active | gcp.reviewed.sql.postgres_log_connections |  |
| [gcp-compliance.control.sql_instance_postgresql_log_disconnections_database_flag_on](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/sql.pp#L128) | mapped-active | gcp.reviewed.sql.postgres_log_disconnections |  |
| [gcp-compliance.control.sql_instance_postgresql_log_duration_database_flag_on](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/sql.pp#L140) | mapped-active | gcp.ports.sql_instance_postgresql_log_duration_database_flag_on |  |
| [gcp-compliance.control.sql_instance_postgresql_log_error_verbosity_database_flag_default_or_stricter](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/sql.pp#L148) | mapped-active | gcp.ports.sql_instance_postgresql_log_error_verbosity_database_flag_default_or_stricter |  |
| [gcp-compliance.control.sql_instance_postgresql_log_executor_stats_database_flag_off](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/sql.pp#L160) | mapped-active | gcp.ports.sql_instance_postgresql_log_executor_stats_database_flag_off |  |
| [gcp-compliance.control.sql_instance_postgresql_log_hostname_database_flag_configured](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/sql.pp#L168) | mapped-active | gcp.ports.sql_instance_postgresql_log_hostname_database_flag_configured |  |
| [gcp-compliance.control.sql_instance_postgresql_log_lock_waits_database_flag_on](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/sql.pp#L176) | mapped-active | gcp.ports.sql_instance_postgresql_log_lock_waits_database_flag_on |  |
| [gcp-compliance.control.sql_instance_postgresql_log_min_duration_statement_database_flag_disabled](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/sql.pp#L184) | mapped-active | gcp.ports.sql_instance_postgresql_log_min_duration_statement_database_flag_disabled |  |
| [gcp-compliance.control.sql_instance_postgresql_log_min_error_statement_database_flag_configured](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/sql.pp#L196) | mapped-active | gcp.ports.sql_instance_postgresql_log_min_error_statement_database_flag_configured |  |
| [gcp-compliance.control.sql_instance_postgresql_log_min_messages_database_flag_error](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/sql.pp#L208) | mapped-active | gcp.ports.sql_instance_postgresql_log_min_messages_database_flag_error |  |
| [gcp-compliance.control.sql_instance_postgresql_log_parser_stats_database_flag_off](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/sql.pp#L220) | mapped-active | gcp.ports.sql_instance_postgresql_log_parser_stats_database_flag_off |  |
| [gcp-compliance.control.sql_instance_postgresql_log_planner_stats_database_flag_off](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/sql.pp#L228) | mapped-active | gcp.ports.sql_instance_postgresql_log_planner_stats_database_flag_off |  |
| [gcp-compliance.control.sql_instance_postgresql_log_statement_database_flag_ddl](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/sql.pp#L236) | mapped-active | gcp.reviewed.sql.postgres_log_statement |  |
| [gcp-compliance.control.sql_instance_postgresql_log_statement_stats_database_flag_off](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/sql.pp#L248) | mapped-active | gcp.ports.sql_instance_postgresql_log_statement_stats_database_flag_off |  |
| [gcp-compliance.control.sql_instance_postgresql_log_temp_files_database_flag_0](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/sql.pp#L256) | mapped-active | gcp.ports.sql_instance_postgresql_log_temp_files_database_flag_0 |  |
| [gcp-compliance.control.sql_instance_sql_3625_trace_database_flag_off](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/sql.pp#L264) | mapped-active | gcp.ports.sql_instance_sql_3625_trace_database_flag_on |  |
| [gcp-compliance.control.sql_instance_sql_3625_trace_database_flag_on](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/sql.pp#L274) | mapped-active | gcp.ports.sql_instance_sql_3625_trace_database_flag_on |  |
| [gcp-compliance.control.sql_instance_sql_contained_database_authentication_database_flag_off](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/sql.pp#L285) | mapped-active | gcp.ports.sql_instance_sql_contained_database_authentication_database_flag_off |  |
| [gcp-compliance.control.sql_instance_sql_cross_db_ownership_chaining_database_flag_off](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/sql.pp#L299) | mapped-active | gcp.ports.sql_instance_sql_cross_db_ownership_chaining_database_flag_off |  |
| [gcp-compliance.control.sql_instance_sql_external_scripts_enabled_database_flag_off](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/sql.pp#L312) | mapped-active | gcp.ports.sql_instance_sql_external_scripts_enabled_database_flag_off |  |
| [gcp-compliance.control.sql_instance_sql_remote_access_database_flag_off](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/sql.pp#L324) | mapped-active | gcp.ports.sql_instance_sql_remote_access_database_flag_off |  |
| [gcp-compliance.control.sql_instance_sql_user_connections_database_flag_configured](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/sql.pp#L335) | mapped-active | gcp.ports.sql_instance_sql_user_connections_database_flag_configured |  |
| [gcp-compliance.control.sql_instance_sql_user_options_database_flag_not_configured](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/sql.pp#L347) | mapped-active | gcp.ports.sql_instance_sql_user_options_database_flag_not_configured |  |
| [gcp-compliance.control.sql_instance_with_labels](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/sql.pp#L359) | rejected |  |  |
| [gcp-compliance.control.sql_world_readable](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/sql.pp#L7) | mapped-active | gcp.ports.sql_instance_not_open_to_internet |  |
| [gcp-compliance.control.storage_bucket_log_not_publicly_accessible](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/storage.pp#L80) | mapped-active | gcp.claude.bucket.log_sink_not_public |  |
| [gcp-compliance.control.storage_bucket_log_object_versioning_enabled](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/storage.pp#L69) | mapped-active | gcp.claude.bucket.log_sink_versioning |  |
| [gcp-compliance.control.storage_bucket_log_retention_policy_enabled](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/storage.pp#L58) | mapped-active | gcp.claude.bucket.log_sink_retention_policy |  |
| [gcp-compliance.control.storage_bucket_log_retention_policy_lock_enabled](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/storage.pp#L44) | mapped-active | gcp.claude.bucket.log_sink_retention_locked |  |
| [gcp-compliance.control.storage_bucket_not_publicly_accessible](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/storage.pp#L22) | mapped-active | gcp.storage.no_public_iam |  |
| [gcp-compliance.control.storage_bucket_uniform_access_enabled](https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/storage.pp#L36) | mapped-active | gcp.storage.uniform_access |  |
| [gcp-perimeter.control.bigquery_dataset_policy_prohibit_public_access](https://github.com/turbot/steampipe-mod-gcp-perimeter/blob/e2c5a299d1927a41fe8bbd748bdffd295237937c/perimeter/iam_policy_public_access.pp#L118) | mapped-active | gcp.reviewed.bigquery.no_public_acl |  |
| [gcp-perimeter.control.bigtable_instance_policy_shared_access](https://github.com/turbot/steampipe-mod-gcp-perimeter/blob/e2c5a299d1927a41fe8bbd748bdffd295237937c/perimeter/iam_policy_shared_access.pp#L649) | mapped-only-archived |  |  |
| [gcp-perimeter.control.billing_account_policy_shared_access](https://github.com/turbot/steampipe-mod-gcp-perimeter/blob/e2c5a299d1927a41fe8bbd748bdffd295237937c/perimeter/iam_policy_shared_access.pp#L618) | mapped-only-archived |  |  |
| [gcp-perimeter.control.cloud_function_policy_shared_access](https://github.com/turbot/steampipe-mod-gcp-perimeter/blob/e2c5a299d1927a41fe8bbd748bdffd295237937c/perimeter/iam_policy_shared_access.pp#L587) | mapped-only-archived |  |  |
| [gcp-perimeter.control.cloud_run_job_policy_shared_access](https://github.com/turbot/steampipe-mod-gcp-perimeter/blob/e2c5a299d1927a41fe8bbd748bdffd295237937c/perimeter/iam_policy_shared_access.pp#L526) | mapped-only-archived |  |  |
| [gcp-perimeter.control.cloud_run_not_publicly_accessible](https://github.com/turbot/steampipe-mod-gcp-perimeter/blob/e2c5a299d1927a41fe8bbd748bdffd295237937c/perimeter/network_access.pp#L284) | mapped-active | gcp.ports.cloud_run_not_publicly_accessible |  |
| [gcp-perimeter.control.cloud_run_service_policy_prohibit_public_access](https://github.com/turbot/steampipe-mod-gcp-perimeter/blob/e2c5a299d1927a41fe8bbd748bdffd295237937c/perimeter/iam_policy_public_access.pp#L108) | mapped-active | gcp.ports.cloud_run_service_policy_prohibit_public_access |  |
| [gcp-perimeter.control.cloud_run_service_policy_shared_access](https://github.com/turbot/steampipe-mod-gcp-perimeter/blob/e2c5a299d1927a41fe8bbd748bdffd295237937c/perimeter/iam_policy_shared_access.pp#L556) | mapped-only-archived |  |  |
| [gcp-perimeter.control.cloud_sql_not_publicly_accessible](https://github.com/turbot/steampipe-mod-gcp-perimeter/blob/e2c5a299d1927a41fe8bbd748bdffd295237937c/perimeter/network_access.pp#L310) | mapped-active | gcp.sql.no_public_ip |  |
| [gcp-perimeter.control.cloudfunction_function_not_publicly_accessible](https://github.com/turbot/steampipe-mod-gcp-perimeter/blob/e2c5a299d1927a41fe8bbd748bdffd295237937c/perimeter/network_access.pp#L256) | mapped-active | gcp.ports.function_internal_ingress_declaration |  |
| [gcp-perimeter.control.compute_disk_policy_shared_access](https://github.com/turbot/steampipe-mod-gcp-perimeter/blob/e2c5a299d1927a41fe8bbd748bdffd295237937c/perimeter/iam_policy_shared_access.pp#L315) | mapped-only-archived |  |  |
| [gcp-perimeter.control.compute_image_policy_prohibit_public_access](https://github.com/turbot/steampipe-mod-gcp-perimeter/blob/e2c5a299d1927a41fe8bbd748bdffd295237937c/perimeter/iam_policy_public_access.pp#L157) | mapped-active | gcp.claude.image.not_public |  |
| [gcp-perimeter.control.compute_image_policy_shared_access](https://github.com/turbot/steampipe-mod-gcp-perimeter/blob/e2c5a299d1927a41fe8bbd748bdffd295237937c/perimeter/iam_policy_shared_access.pp#L345) | mapped-only-archived |  |  |
| [gcp-perimeter.control.compute_instance_policy_shared_access](https://github.com/turbot/steampipe-mod-gcp-perimeter/blob/e2c5a299d1927a41fe8bbd748bdffd295237937c/perimeter/iam_policy_shared_access.pp#L375) | mapped-only-archived |  |  |
| [gcp-perimeter.control.compute_node_group_policy_shared_access](https://github.com/turbot/steampipe-mod-gcp-perimeter/blob/e2c5a299d1927a41fe8bbd748bdffd295237937c/perimeter/iam_policy_shared_access.pp#L405) | mapped-only-archived |  |  |
| [gcp-perimeter.control.compute_node_template_policy_shared_access](https://github.com/turbot/steampipe-mod-gcp-perimeter/blob/e2c5a299d1927a41fe8bbd748bdffd295237937c/perimeter/iam_policy_shared_access.pp#L435) | mapped-only-archived |  |  |
| [gcp-perimeter.control.compute_resource_policy_shared_access](https://github.com/turbot/steampipe-mod-gcp-perimeter/blob/e2c5a299d1927a41fe8bbd748bdffd295237937c/perimeter/iam_policy_shared_access.pp#L465) | mapped-only-archived |  |  |
| [gcp-perimeter.control.compute_subnetwork_policy_shared_access](https://github.com/turbot/steampipe-mod-gcp-perimeter/blob/e2c5a299d1927a41fe8bbd748bdffd295237937c/perimeter/iam_policy_shared_access.pp#L495) | mapped-only-archived |  |  |
| [gcp-perimeter.control.gke_cluster_master_authorized_networks_not_publicly_accessible](https://github.com/turbot/steampipe-mod-gcp-perimeter/blob/e2c5a299d1927a41fe8bbd748bdffd295237937c/perimeter/network_access.pp#L362) | mapped-active | gcp.claude.gke.master_authorized_networks_restricted |  |
| [gcp-perimeter.control.gke_cluster_nodes_not_publicly_accessible](https://github.com/turbot/steampipe-mod-gcp-perimeter/blob/e2c5a299d1927a41fe8bbd748bdffd295237937c/perimeter/network_access.pp#L336) | mapped-active | gcp.claude.gke.private_nodes |  |
| [gcp-perimeter.control.iam_service_account_policy_shared_access](https://github.com/turbot/steampipe-mod-gcp-perimeter/blob/e2c5a299d1927a41fe8bbd748bdffd295237937c/perimeter/iam_policy_shared_access.pp#L253) | mapped-only-archived |  |  |
| [gcp-perimeter.control.kms_key_policy_prohibit_public_access](https://github.com/turbot/steampipe-mod-gcp-perimeter/blob/e2c5a299d1927a41fe8bbd748bdffd295237937c/perimeter/iam_policy_public_access.pp#L98) | mapped-active | gcp.reviewed.kms.no_public_iam |  |
| [gcp-perimeter.control.kms_key_policy_shared_access](https://github.com/turbot/steampipe-mod-gcp-perimeter/blob/e2c5a299d1927a41fe8bbd748bdffd295237937c/perimeter/iam_policy_shared_access.pp#L680) | mapped-only-archived |  |  |
| [gcp-perimeter.control.kms_key_ring_policy_shared_access](https://github.com/turbot/steampipe-mod-gcp-perimeter/blob/e2c5a299d1927a41fe8bbd748bdffd295237937c/perimeter/iam_policy_shared_access.pp#L710) | mapped-only-archived |  |  |
| [gcp-perimeter.control.pubsub_snapshot_policy_prohibit_public_access](https://github.com/turbot/steampipe-mod-gcp-perimeter/blob/e2c5a299d1927a41fe8bbd748bdffd295237937c/perimeter/iam_policy_public_access.pp#L88) | mapped-active | gcp.claude.pubsub_snapshot.not_public |  |
| [gcp-perimeter.control.pubsub_subscription_policy_prohibit_public_access](https://github.com/turbot/steampipe-mod-gcp-perimeter/blob/e2c5a299d1927a41fe8bbd748bdffd295237937c/perimeter/iam_policy_public_access.pp#L78) | mapped-active | gcp.claude.pubsub_subscription.not_public |  |
| [gcp-perimeter.control.pubsub_subscription_policy_shared_access](https://github.com/turbot/steampipe-mod-gcp-perimeter/blob/e2c5a299d1927a41fe8bbd748bdffd295237937c/perimeter/iam_policy_shared_access.pp#L771) | mapped-only-archived |  |  |
| [gcp-perimeter.control.pubsub_topic_policy_prohibit_public_access](https://github.com/turbot/steampipe-mod-gcp-perimeter/blob/e2c5a299d1927a41fe8bbd748bdffd295237937c/perimeter/iam_policy_public_access.pp#L68) | mapped-active | gcp.claude.pubsub_topic.not_public |  |
| [gcp-perimeter.control.pubsub_topic_policy_shared_access](https://github.com/turbot/steampipe-mod-gcp-perimeter/blob/e2c5a299d1927a41fe8bbd748bdffd295237937c/perimeter/iam_policy_shared_access.pp#L741) | mapped-only-archived |  |  |
| [gcp-perimeter.control.storage_bucket_policy_prohibit_public_access](https://github.com/turbot/steampipe-mod-gcp-perimeter/blob/e2c5a299d1927a41fe8bbd748bdffd295237937c/perimeter/iam_policy_public_access.pp#L58) | mapped-active | gcp.storage.no_public_iam |  |
| [gcp-perimeter.control.storage_bucket_policy_shared_access](https://github.com/turbot/steampipe-mod-gcp-perimeter/blob/e2c5a299d1927a41fe8bbd748bdffd295237937c/perimeter/iam_policy_shared_access.pp#L284) | mapped-only-archived |  |  |
| [gcp-perimeter.control.vpc_firewall_restrict_ingress_common_ports](https://github.com/turbot/steampipe-mod-gcp-perimeter/blob/e2c5a299d1927a41fe8bbd748bdffd295237937c/perimeter/network_access.pp#L73) | mapped-active | gcp.claude.firewall.public_ingress_common_ports |  |
| [gcp-perimeter.control.vpc_firewall_restrict_ingress_tcp_udp_all](https://github.com/turbot/steampipe-mod-gcp-perimeter/blob/e2c5a299d1927a41fe8bbd748bdffd295237937c/perimeter/network_access.pp#L30) | mapped-active | gcp.claude.firewall.public_ingress_tcp_udp |  |
| [prowler.gcp.apikeys_api_restricted_with_gemini_api](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/apikeys/apikeys_api_restricted_with_gemini_api/apikeys_api_restricted_with_gemini_api.metadata.json) | mapped-active | gcp.ports.apikeys_api_restricted_with_gemini_api |  |
| [prowler.gcp.apikeys_api_restrictions_configured](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/apikeys/apikeys_api_restrictions_configured/apikeys_api_restrictions_configured.metadata.json) | mapped-active | gcp.ports.iam_api_key_restricts_apis |  |
| [prowler.gcp.apikeys_key_exists](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/apikeys/apikeys_key_exists/apikeys_key_exists.metadata.json) | mapped-active | gcp.claude.project.no_api_keys |  |
| [prowler.gcp.apikeys_key_rotated_in_90_days](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/apikeys/apikeys_key_rotated_in_90_days/apikeys_key_rotated_in_90_days.metadata.json) | mapped-active | gcp.claude2.api_key.created_within_90_days |  |
| [prowler.gcp.artifacts_container_analysis_enabled](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/artifacts/artifacts_container_analysis_enabled/artifacts_container_analysis_enabled.metadata.json) | mapped-active | gcp.ports.artifacts_container_analysis_enabled |  |
| [prowler.gcp.bigquery_dataset_cmk_encryption](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/bigquery/bigquery_dataset_cmk_encryption/bigquery_dataset_cmk_encryption.metadata.json) | mapped-active | gcp.claude2.bigquery_dataset.default_cmek |  |
| [prowler.gcp.bigquery_dataset_public_access](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/bigquery/bigquery_dataset_public_access/bigquery_dataset_public_access.metadata.json) | mapped-active | gcp.reviewed.bigquery.no_public_acl |  |
| [prowler.gcp.bigquery_table_cmk_encryption](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/bigquery/bigquery_table_cmk_encryption/bigquery_table_cmk_encryption.metadata.json) | mapped-active | gcp.ports.bigquery_table_encrypted_with_cmk |  |
| [prowler.gcp.cloudfunction_function_inside_vpc](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/cloudfunction/cloudfunction_function_inside_vpc/cloudfunction_function_inside_vpc.metadata.json) | mapped-active | gcp.claude2.function.vpc_connector_configured |  |
| [prowler.gcp.cloudfunction_function_not_publicly_accessible](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/cloudfunction/cloudfunction_function_not_publicly_accessible/cloudfunction_function_not_publicly_accessible.metadata.json) | mapped-active | gcp.claude2.function.not_publicly_accessible |  |
| [prowler.gcp.cloudsql_instance_automated_backups](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/cloudsql/cloudsql_instance_automated_backups/cloudsql_instance_automated_backups.metadata.json) | mapped-active | gcp.sql.backups |  |
| [prowler.gcp.cloudsql_instance_cmek_encryption_enabled](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/cloudsql/cloudsql_instance_cmek_encryption_enabled/cloudsql_instance_cmek_encryption_enabled.metadata.json) | mapped-active | gcp.reviewed.sql.cmek |  |
| [prowler.gcp.cloudsql_instance_high_availability_enabled](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/cloudsql/cloudsql_instance_high_availability_enabled/cloudsql_instance_high_availability_enabled.metadata.json) | mapped-active | gcp.reviewed.sql.high_availability |  |
| [prowler.gcp.cloudsql_instance_mysql_local_infile_flag](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/cloudsql/cloudsql_instance_mysql_local_infile_flag/cloudsql_instance_mysql_local_infile_flag.metadata.json) | mapped-active | gcp.reviewed.sql.mysql_local_infile |  |
| [prowler.gcp.cloudsql_instance_mysql_skip_show_database_flag](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/cloudsql/cloudsql_instance_mysql_skip_show_database_flag/cloudsql_instance_mysql_skip_show_database_flag.metadata.json) | mapped-active | gcp.reviewed.sql.mysql_skip_show_database |  |
| [prowler.gcp.cloudsql_instance_postgres_enable_pgaudit_flag](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/cloudsql/cloudsql_instance_postgres_enable_pgaudit_flag/cloudsql_instance_postgres_enable_pgaudit_flag.metadata.json) | mapped-active | gcp.reviewed.sql.postgres_pgaudit |  |
| [prowler.gcp.cloudsql_instance_postgres_log_connections_flag](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/cloudsql/cloudsql_instance_postgres_log_connections_flag/cloudsql_instance_postgres_log_connections_flag.metadata.json) | mapped-active | gcp.reviewed.sql.postgres_log_connections |  |
| [prowler.gcp.cloudsql_instance_postgres_log_disconnections_flag](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/cloudsql/cloudsql_instance_postgres_log_disconnections_flag/cloudsql_instance_postgres_log_disconnections_flag.metadata.json) | mapped-active | gcp.reviewed.sql.postgres_log_disconnections |  |
| [prowler.gcp.cloudsql_instance_postgres_log_error_verbosity_flag](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/cloudsql/cloudsql_instance_postgres_log_error_verbosity_flag/cloudsql_instance_postgres_log_error_verbosity_flag.metadata.json) | mapped-active | gcp.reviewed.sql.postgres_log_error_verbosity |  |
| [prowler.gcp.cloudsql_instance_postgres_log_min_duration_statement_flag](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/cloudsql/cloudsql_instance_postgres_log_min_duration_statement_flag/cloudsql_instance_postgres_log_min_duration_statement_flag.metadata.json) | mapped-active | gcp.ports.reference_sql_pg_min_duration |  |
| [prowler.gcp.cloudsql_instance_postgres_log_min_error_statement_flag](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/cloudsql/cloudsql_instance_postgres_log_min_error_statement_flag/cloudsql_instance_postgres_log_min_error_statement_flag.metadata.json) | mapped-active | gcp.ports.reference_sql_pg_min_error |  |
| [prowler.gcp.cloudsql_instance_postgres_log_min_messages_flag](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/cloudsql/cloudsql_instance_postgres_log_min_messages_flag/cloudsql_instance_postgres_log_min_messages_flag.metadata.json) | mapped-active | gcp.ports.reference_sql_pg_min_messages |  |
| [prowler.gcp.cloudsql_instance_postgres_log_statement_flag](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/cloudsql/cloudsql_instance_postgres_log_statement_flag/cloudsql_instance_postgres_log_statement_flag.metadata.json) | mapped-active | gcp.reviewed.sql.postgres_log_statement |  |
| [prowler.gcp.cloudsql_instance_private_ip_assignment](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/cloudsql/cloudsql_instance_private_ip_assignment/cloudsql_instance_private_ip_assignment.metadata.json) | mapped-active | gcp.claude2.sql_instance.only_private_ip_addresses |  |
| [prowler.gcp.cloudsql_instance_public_access](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/cloudsql/cloudsql_instance_public_access/cloudsql_instance_public_access.metadata.json) | mapped-active | gcp.ports.sql_instance_not_open_to_internet |  |
| [prowler.gcp.cloudsql_instance_public_ip](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/cloudsql/cloudsql_instance_public_ip/cloudsql_instance_public_ip.metadata.json) | mapped-active | gcp.claude.sql_instance.second_gen_no_public_ip |  |
| [prowler.gcp.cloudsql_instance_sqlserver_contained_database_authentication_flag](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/cloudsql/cloudsql_instance_sqlserver_contained_database_authentication_flag/cloudsql_instance_sqlserver_contained_database_authentication_flag.metadata.json) | mapped-active | gcp.ports.reference_sqlserver_contained_database_authentication |  |
| [prowler.gcp.cloudsql_instance_sqlserver_cross_db_ownership_chaining_flag](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/cloudsql/cloudsql_instance_sqlserver_cross_db_ownership_chaining_flag/cloudsql_instance_sqlserver_cross_db_ownership_chaining_flag.metadata.json) | mapped-active | gcp.ports.reference_sqlserver_cross_db_ownership_chaining |  |
| [prowler.gcp.cloudsql_instance_sqlserver_external_scripts_enabled_flag](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/cloudsql/cloudsql_instance_sqlserver_external_scripts_enabled_flag/cloudsql_instance_sqlserver_external_scripts_enabled_flag.metadata.json) | mapped-active | gcp.ports.reference_sqlserver_external_scripts_enabled |  |
| [prowler.gcp.cloudsql_instance_sqlserver_remote_access_flag](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/cloudsql/cloudsql_instance_sqlserver_remote_access_flag/cloudsql_instance_sqlserver_remote_access_flag.metadata.json) | mapped-active | gcp.ports.reference_sqlserver_remote_access |  |
| [prowler.gcp.cloudsql_instance_sqlserver_trace_flag](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/cloudsql/cloudsql_instance_sqlserver_trace_flag/cloudsql_instance_sqlserver_trace_flag.metadata.json) | mapped-active | gcp.ports.reference_sqlserver_trace3625 |  |
| [prowler.gcp.cloudsql_instance_sqlserver_user_connections_flag](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/cloudsql/cloudsql_instance_sqlserver_user_connections_flag/cloudsql_instance_sqlserver_user_connections_flag.metadata.json) | mapped-active | gcp.ports.reference_sqlserver_user_connections |  |
| [prowler.gcp.cloudsql_instance_sqlserver_user_options_flag](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/cloudsql/cloudsql_instance_sqlserver_user_options_flag/cloudsql_instance_sqlserver_user_options_flag.metadata.json) | mapped-active | gcp.ports.reference_sqlserver_user_options |  |
| [prowler.gcp.cloudsql_instance_ssl_connections](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/cloudsql/cloudsql_instance_ssl_connections/cloudsql_instance_ssl_connections.metadata.json) | mapped-active | gcp.ports.reference_sql_ssl_connections |  |
| [prowler.gcp.cloudstorage_audit_logs_enabled](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/cloudstorage/cloudstorage_audit_logs_enabled/cloudstorage_audit_logs_enabled.metadata.json) | mapped-active | gcp.claude.project.storage_data_access_audit_logs |  |
| [prowler.gcp.cloudstorage_bucket_lifecycle_management_enabled](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/cloudstorage/cloudstorage_bucket_lifecycle_management_enabled/cloudstorage_bucket_lifecycle_management_enabled.metadata.json) | mapped-active | gcp.reviewed.storage.lifecycle |  |
| [prowler.gcp.cloudstorage_bucket_log_retention_policy_lock](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/cloudstorage/cloudstorage_bucket_log_retention_policy_lock/cloudstorage_bucket_log_retention_policy_lock.metadata.json) | mapped-active | gcp.claude.bucket.log_sink_retention_locked |  |
| [prowler.gcp.cloudstorage_bucket_logging_enabled](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/cloudstorage/cloudstorage_bucket_logging_enabled/cloudstorage_bucket_logging_enabled.metadata.json) | mapped-active | gcp.reviewed.storage.access_logging |  |
| [prowler.gcp.cloudstorage_bucket_public_access](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/cloudstorage/cloudstorage_bucket_public_access/cloudstorage_bucket_public_access.metadata.json) | mapped-active | gcp.storage.no_public_iam |  |
| [prowler.gcp.cloudstorage_bucket_soft_delete_enabled](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/cloudstorage/cloudstorage_bucket_soft_delete_enabled/cloudstorage_bucket_soft_delete_enabled.metadata.json) | mapped-active | gcp.reviewed.storage.soft_delete |  |
| [prowler.gcp.cloudstorage_bucket_sufficient_retention_period](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/cloudstorage/cloudstorage_bucket_sufficient_retention_period/cloudstorage_bucket_sufficient_retention_period.metadata.json) | mapped-active | gcp.claude.bucket.retention_90_days |  |
| [prowler.gcp.cloudstorage_bucket_uniform_bucket_level_access](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/cloudstorage/cloudstorage_bucket_uniform_bucket_level_access/cloudstorage_bucket_uniform_bucket_level_access.metadata.json) | mapped-active | gcp.storage.uniform_access |  |
| [prowler.gcp.cloudstorage_bucket_versioning_enabled](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/cloudstorage/cloudstorage_bucket_versioning_enabled/cloudstorage_bucket_versioning_enabled.metadata.json) | mapped-active | gcp.reviewed.storage.versioning |  |
| [prowler.gcp.cloudstorage_uses_vpc_service_controls](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/cloudstorage/cloudstorage_uses_vpc_service_controls/cloudstorage_uses_vpc_service_controls.metadata.json) | mapped-active | gcp.claude.project.storage_vpc_service_controls |  |
| [prowler.gcp.compute_firewall_rdp_access_from_the_internet_allowed](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/compute/compute_firewall_rdp_access_from_the_internet_allowed/compute_firewall_rdp_access_from_the_internet_allowed.metadata.json) | mapped-active | gcp.ports.compute_firewall_rule_rdp_access_restricted |  |
| [prowler.gcp.compute_firewall_ssh_access_from_the_internet_allowed](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/compute/compute_firewall_ssh_access_from_the_internet_allowed/compute_firewall_ssh_access_from_the_internet_allowed.metadata.json) | mapped-active | gcp.ports.compute_firewall_rule_ssh_access_restricted |  |
| [prowler.gcp.compute_image_not_publicly_shared](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/compute/compute_image_not_publicly_shared/compute_image_not_publicly_shared.metadata.json) | mapped-active | gcp.claude.image.not_public |  |
| [prowler.gcp.compute_instance_automatic_restart_enabled](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/compute/compute_instance_automatic_restart_enabled/compute_instance_automatic_restart_enabled.metadata.json) | mapped-active | gcp.reviewed.compute.automatic_restart |  |
| [prowler.gcp.compute_instance_block_project_wide_ssh_keys_disabled](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/compute/compute_instance_block_project_wide_ssh_keys_disabled/compute_instance_block_project_wide_ssh_keys_disabled.metadata.json) | mapped-active | gcp.reviewed.compute.block_project_ssh_keys |  |
| [prowler.gcp.compute_instance_confidential_computing_enabled](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/compute/compute_instance_confidential_computing_enabled/compute_instance_confidential_computing_enabled.metadata.json) | mapped-active | gcp.reviewed.compute.confidential_computing |  |
| [prowler.gcp.compute_instance_default_service_account_in_use](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/compute/compute_instance_default_service_account_in_use/compute_instance_default_service_account_in_use.metadata.json) | mapped-active | gcp.ports.compute_instance_with_no_default_service_account |  |
| [prowler.gcp.compute_instance_default_service_account_in_use_with_full_api_access](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/compute/compute_instance_default_service_account_in_use_with_full_api_access/compute_instance_default_service_account_in_use_with_full_api_access.metadata.json) | mapped-active | gcp.ports.compute_instance_with_no_default_service_account_with_full_access |  |
| [prowler.gcp.compute_instance_deletion_protection_enabled](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/compute/compute_instance_deletion_protection_enabled/compute_instance_deletion_protection_enabled.metadata.json) | mapped-active | gcp.reviewed.compute.deletion_protection |  |
| [prowler.gcp.compute_instance_disk_auto_delete_disabled](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/compute/compute_instance_disk_auto_delete_disabled/compute_instance_disk_auto_delete_disabled.metadata.json) | mapped-active | gcp.reviewed.compute.disk_auto_delete |  |
| [prowler.gcp.compute_instance_encryption_with_csek_enabled](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/compute/compute_instance_encryption_with_csek_enabled/compute_instance_encryption_with_csek_enabled.metadata.json) | mapped-active | gcp.claude.instance.disks_csek |  |
| [prowler.gcp.compute_instance_group_autohealing_enabled](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/compute/compute_instance_group_autohealing_enabled/compute_instance_group_autohealing_enabled.metadata.json) | mapped-active | gcp.claude.instance_group_manager.autohealing |  |
| [prowler.gcp.compute_instance_group_load_balancer_attached](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/compute/compute_instance_group_load_balancer_attached/compute_instance_group_load_balancer_attached.metadata.json) | mapped-active | gcp.claude.instance_group_manager.load_balancer_attached |  |
| [prowler.gcp.compute_instance_group_multiple_zones](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/compute/compute_instance_group_multiple_zones/compute_instance_group_multiple_zones.metadata.json) | mapped-active | gcp.claude.instance_group_manager.multiple_zones |  |
| [prowler.gcp.compute_instance_ip_forwarding_is_enabled](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/compute/compute_instance_ip_forwarding_is_enabled/compute_instance_ip_forwarding_is_enabled.metadata.json) | mapped-active | gcp.ports.compute_instance_ip_forwarding_disabled |  |
| [prowler.gcp.compute_instance_on_host_maintenance_migrate](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/compute/compute_instance_on_host_maintenance_migrate/compute_instance_on_host_maintenance_migrate.metadata.json) | mapped-active | gcp.reviewed.compute.maintenance_migrate |  |
| [prowler.gcp.compute_instance_preemptible_vm_disabled](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/compute/compute_instance_preemptible_vm_disabled/compute_instance_preemptible_vm_disabled.metadata.json) | mapped-active | gcp.claude.instance.not_preemptible_or_spot |  |
| [prowler.gcp.compute_instance_public_ip](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/compute/compute_instance_public_ip/compute_instance_public_ip.metadata.json) | mapped-active | gcp.compute.no_external_ip |  |
| [prowler.gcp.compute_instance_serial_ports_in_use](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/compute/compute_instance_serial_ports_in_use/compute_instance_serial_ports_in_use.metadata.json) | mapped-active | gcp.reviewed.compute.no_serial_console |  |
| [prowler.gcp.compute_instance_shielded_vm_enabled](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/compute/compute_instance_shielded_vm_enabled/compute_instance_shielded_vm_enabled.metadata.json) | mapped-active | gcp.ports.compute_instance_shielded_vm_enabled |  |
| [prowler.gcp.compute_instance_single_network_interface](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/compute/compute_instance_single_network_interface/compute_instance_single_network_interface.metadata.json) | mapped-active | gcp.reviewed.compute.single_interface |  |
| [prowler.gcp.compute_instance_suspended_without_persistent_disks](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/compute/compute_instance_suspended_without_persistent_disks/compute_instance_suspended_without_persistent_disks.metadata.json) | mapped-active | gcp.claude.instance.suspended_without_disks |  |
| [prowler.gcp.compute_loadbalancer_logging_enabled](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/compute/compute_loadbalancer_logging_enabled/compute_loadbalancer_logging_enabled.metadata.json) | mapped-active | gcp.ports.compute_url_map_backend_logging |  |
| [prowler.gcp.compute_network_default_in_use](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/compute/compute_network_default_in_use/compute_network_default_in_use.metadata.json) | mapped-active | gcp.reviewed.network.no_default_vpc |  |
| [prowler.gcp.compute_network_dns_logging_enabled](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/compute/compute_network_dns_logging_enabled/compute_network_dns_logging_enabled.metadata.json) | mapped-active | gcp.claude.network.dns_logging |  |
| [prowler.gcp.compute_network_not_legacy](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/compute/compute_network_not_legacy/compute_network_not_legacy.metadata.json) | mapped-active | gcp.ports.compute_network_contains_no_legacy_network |  |
| [prowler.gcp.compute_project_os_login_2fa_enabled](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/compute/compute_project_os_login_2fa_enabled/compute_project_os_login_2fa_enabled.metadata.json) | mapped-active | gcp.reviewed.project.os_login_2fa |  |
| [prowler.gcp.compute_project_os_login_enabled](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/compute/compute_project_os_login_enabled/compute_project_os_login_enabled.metadata.json) | mapped-active | gcp.claude.project.oslogin_enabled |  |
| [prowler.gcp.compute_public_address_shodan](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/compute/compute_public_address_shodan/compute_public_address_shodan.metadata.json) | rejected |  |  |
| [prowler.gcp.compute_snapshot_not_outdated](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/compute/compute_snapshot_not_outdated/compute_snapshot_not_outdated.metadata.json) | mapped-active | gcp.claude.snapshot.not_outdated |  |
| [prowler.gcp.compute_subnet_flow_logs_enabled](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/compute/compute_subnet_flow_logs_enabled/compute_subnet_flow_logs_enabled.metadata.json) | mapped-active | gcp.reviewed.network.flow_logs |  |
| [prowler.gcp.dataproc_encrypted_with_cmks_disabled](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/dataproc/dataproc_encrypted_with_cmks_disabled/dataproc_encrypted_with_cmks_disabled.metadata.json) | mapped-active | gcp.ports.dataproc_cluster_encryption_with_cmek |  |
| [prowler.gcp.dns_dnssec_disabled](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/dns/dns_dnssec_disabled/dns_dnssec_disabled.metadata.json) | mapped-active | gcp.claude.dns_zone.dnssec_enabled |  |
| [prowler.gcp.dns_rsasha1_in_use_to_key_sign_in_dnssec](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/dns/dns_rsasha1_in_use_to_key_sign_in_dnssec/dns_rsasha1_in_use_to_key_sign_in_dnssec.metadata.json) | mapped-active | gcp.claude.dns_zone.ksk_not_rsasha1 |  |
| [prowler.gcp.dns_rsasha1_in_use_to_zone_sign_in_dnssec](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/dns/dns_rsasha1_in_use_to_zone_sign_in_dnssec/dns_rsasha1_in_use_to_zone_sign_in_dnssec.metadata.json) | mapped-active | gcp.claude.dns_zone.zsk_not_rsasha1 |  |
| [prowler.gcp.gcr_container_scanning_enabled](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/gcr/gcr_container_scanning_enabled/gcr_container_scanning_enabled.metadata.json) | mapped-active | gcp.claude.project.container_scanning_api_enabled |  |
| [prowler.gcp.gemini_api_disabled](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/gemini/gemini_api_disabled/gemini_api_disabled.metadata.json) | mapped-active | gcp.claude.project.gemini_api_disabled |  |
| [prowler.gcp.gke_cluster_no_default_service_account](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/gke/gke_cluster_no_default_service_account/gke_cluster_no_default_service_account.metadata.json) | mapped-active | gcp.claude.gke.nodes_no_default_service_account |  |
| [prowler.gcp.iam_account_access_approval_enabled](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/iam/iam_account_access_approval_enabled/iam_account_access_approval_enabled.metadata.json) | mapped-active | gcp.ports.access_approval_explicit_enrollment |  |
| [prowler.gcp.iam_audit_logs_enabled](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/iam/iam_audit_logs_enabled/iam_audit_logs_enabled.metadata.json) | mapped-active | gcp.claude.project.audit_logs_configured |  |
| [prowler.gcp.iam_cloud_asset_inventory_enabled](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/iam/iam_cloud_asset_inventory_enabled/iam_cloud_asset_inventory_enabled.metadata.json) | mapped-active | gcp.ports.project_service_cloudasset_api_enabled |  |
| [prowler.gcp.iam_no_service_roles_at_project_level](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/iam/iam_no_service_roles_at_project_level/iam_no_service_roles_at_project_level.metadata.json) | mapped-active | gcp.claude.iam_policy.no_project_sa_user_or_token_creator |  |
| [prowler.gcp.iam_organization_essential_contacts_configured](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/iam/iam_organization_essential_contacts_configured/iam_organization_essential_contacts_configured.metadata.json) | mapped-active | gcp.claude.organization.essential_contacts_any |  |
| [prowler.gcp.iam_role_kms_enforce_separation_of_duties](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/iam/iam_role_kms_enforce_separation_of_duties/iam_role_kms_enforce_separation_of_duties.metadata.json) | mapped-active | gcp.ports.kms_key_separation_of_duties_enforced |  |
| [prowler.gcp.iam_role_sa_enforce_separation_of_duties](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/iam/iam_role_sa_enforce_separation_of_duties/iam_role_sa_enforce_separation_of_duties.metadata.json) | mapped-active | gcp.ports.iam_user_separation_of_duty_scoped |  |
| [prowler.gcp.iam_sa_no_administrative_privileges](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/iam/iam_sa_no_administrative_privileges/iam_sa_no_administrative_privileges.metadata.json) | mapped-active | gcp.gap.iam_user_managed_sa_no_admin_roles |  |
| [prowler.gcp.iam_sa_no_user_managed_keys](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/iam/iam_sa_no_user_managed_keys/iam_sa_no_user_managed_keys.metadata.json) | mapped-active | gcp.iam.no_user_managed_sa_keys |  |
| [prowler.gcp.iam_sa_user_managed_key_rotate_90_days](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/iam/iam_sa_user_managed_key_rotate_90_days/iam_sa_user_managed_key_rotate_90_days.metadata.json) | mapped-active | gcp.ports.iam_service_account_key_age_90 |  |
| [prowler.gcp.iam_sa_user_managed_key_unused](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/iam/iam_sa_user_managed_key_unused/iam_sa_user_managed_key_unused.metadata.json) | mapped-active | gcp.claude.service_account_key.recently_used |  |
| [prowler.gcp.iam_service_account_unused](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/iam/iam_service_account_unused/iam_service_account_unused.metadata.json) | mapped-active | gcp.claude.service_account.recently_used |  |
| [prowler.gcp.iam_workload_identity_pool_provider_attribute_condition](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/iam/iam_workload_identity_pool_provider_attribute_condition/iam_workload_identity_pool_provider_attribute_condition.metadata.json) | mapped-active | gcp.claude.workload_identity_provider.multi_tenant_condition |  |
| [prowler.gcp.kms_key_not_publicly_accessible](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/kms/kms_key_not_publicly_accessible/kms_key_not_publicly_accessible.metadata.json) | mapped-active | gcp.reviewed.kms.no_public_iam |  |
| [prowler.gcp.kms_key_rotation_enabled](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/kms/kms_key_rotation_enabled/kms_key_rotation_enabled.metadata.json) | mapped-active | gcp.reviewed.kms.rotation_enabled |  |
| [prowler.gcp.kms_key_rotation_max_90_days](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/kms/kms_key_rotation_max_90_days/kms_key_rotation_max_90_days.metadata.json) | mapped-active | gcp.reviewed.kms.rotation_90_days |  |
| [prowler.gcp.logging_log_metric_filter_and_alert_for_audit_configuration_changes_enabled](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/logging/logging_log_metric_filter_and_alert_for_audit_configuration_changes_enabled/logging_log_metric_filter_and_alert_for_audit_configuration_changes_enabled.metadata.json) | mapped-active | gcp.claude.logging.metric_alert_audit_configuration_changes |  |
| [prowler.gcp.logging_log_metric_filter_and_alert_for_bucket_permission_changes_enabled](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/logging/logging_log_metric_filter_and_alert_for_bucket_permission_changes_enabled/logging_log_metric_filter_and_alert_for_bucket_permission_changes_enabled.metadata.json) | mapped-active | gcp.claude.logging.metric_alert_bucket_iam_changes |  |
| [prowler.gcp.logging_log_metric_filter_and_alert_for_compute_configuration_changes_enabled](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/logging/logging_log_metric_filter_and_alert_for_compute_configuration_changes_enabled/logging_log_metric_filter_and_alert_for_compute_configuration_changes_enabled.metadata.json) | mapped-active | gcp.claude.logging.metric_alert_compute_configuration_changes |  |
| [prowler.gcp.logging_log_metric_filter_and_alert_for_custom_role_changes_enabled](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/logging/logging_log_metric_filter_and_alert_for_custom_role_changes_enabled/logging_log_metric_filter_and_alert_for_custom_role_changes_enabled.metadata.json) | mapped-active | gcp.claude.logging.metric_alert_custom_role_changes |  |
| [prowler.gcp.logging_log_metric_filter_and_alert_for_project_ownership_changes_enabled](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/logging/logging_log_metric_filter_and_alert_for_project_ownership_changes_enabled/logging_log_metric_filter_and_alert_for_project_ownership_changes_enabled.metadata.json) | mapped-active | gcp.claude.logging.metric_alert_project_ownership_changes |  |
| [prowler.gcp.logging_log_metric_filter_and_alert_for_sql_instance_configuration_changes_enabled](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/logging/logging_log_metric_filter_and_alert_for_sql_instance_configuration_changes_enabled/logging_log_metric_filter_and_alert_for_sql_instance_configuration_changes_enabled.metadata.json) | mapped-active | gcp.claude.logging.metric_alert_sql_instance_configuration_changes |  |
| [prowler.gcp.logging_log_metric_filter_and_alert_for_vpc_firewall_rule_changes_enabled](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/logging/logging_log_metric_filter_and_alert_for_vpc_firewall_rule_changes_enabled/logging_log_metric_filter_and_alert_for_vpc_firewall_rule_changes_enabled.metadata.json) | mapped-active | gcp.claude.logging.metric_alert_firewall_rule_changes |  |
| [prowler.gcp.logging_log_metric_filter_and_alert_for_vpc_network_changes_enabled](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/logging/logging_log_metric_filter_and_alert_for_vpc_network_changes_enabled/logging_log_metric_filter_and_alert_for_vpc_network_changes_enabled.metadata.json) | mapped-active | gcp.claude.logging.metric_alert_network_changes |  |
| [prowler.gcp.logging_log_metric_filter_and_alert_for_vpc_network_route_changes_enabled](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/logging/logging_log_metric_filter_and_alert_for_vpc_network_route_changes_enabled/logging_log_metric_filter_and_alert_for_vpc_network_route_changes_enabled.metadata.json) | mapped-active | gcp.claude.logging.metric_alert_route_changes |  |
| [prowler.gcp.logging_sink_created](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/logging/logging_sink_created/logging_sink_created.metadata.json) | mapped-active | gcp.claude.logging.project_sink_all_entries |  |
| [prowler.gcp.secretmanager_secret_not_publicly_accessible](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/secretmanager/secretmanager_secret_not_publicly_accessible/secretmanager_secret_not_publicly_accessible.metadata.json) | mapped-active | gcp.claude.secret.not_public |  |
| [prowler.gcp.secretmanager_secret_rotation_enabled](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/secretmanager/secretmanager_secret_rotation_enabled/secretmanager_secret_rotation_enabled.metadata.json) | mapped-active | gcp.claude.secret.rotation_90_days |  |
| [prowler.gcp.vertexai_workbench_instance_public_ip_disabled](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/vertexai/vertexai_workbench_instance_public_ip_disabled/vertexai_workbench_instance_public_ip_disabled.metadata.json) | mapped-active | gcp.review.workbench.public_ip_disabled |  |
| [prowler.gcp.vertexai_workbench_instance_root_access_disabled](https://github.com/prowler-cloud/prowler/blob/4d922da2a6a29fdf49287176bae11401aaf02b75/prowler/providers/gcp/services/vertexai/vertexai_workbench_instance_root_access_disabled/vertexai_workbench_instance_root_access_disabled.metadata.json) | mapped-active | gcp.review.workbench.root_access_disabled |  |
