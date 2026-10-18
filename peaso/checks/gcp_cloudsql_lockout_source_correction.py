"""Transparent successor for Cloud SQL managed lockout evidence; no live auth."""
from copy import deepcopy
import hashlib
import json

CHECK_ID = "gcp_cloudsql_failed_attempts_lockout"
EVALUATOR_VERSION = "2.0.0"
PRIOR_FROZEN_SPEC_SHA256 = "e8a00a7a5e39d325f24a58ee7d6d5068554e680193c1447bdc3e803ed686f6ef"
SOURCE_URL = "https://docs.cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/users"
ORIGINAL_REQUIREMENT = "When repeated failed login attempts are made in a short timeframe, the account must be locked out or rate-limited to prevent further login attempts."
TITLE = "Cloud SQL protection against repeated failed sign-ins"
DESCRIPTION_TEXT = 'Preserves the original lockout-or-rate-limit requirement. A positive configured-lockout verdict requires a dated explicitly approved customer-account responsibility boundary matching the entire complete API-visible account universe, and documented managed MySQL lockout on every account. It does not assert protection of provider-internal principals or observed runtime login behavior.'
DATA_SOURCE = "Read-only SQL Admin instances.list and exact project/instance users.list: databaseVersion, state, instance passwordValidationPolicy.enablePasswordPolicy, User.passwordPolicy.enableFailedAttemptsCheck and allowedFailedAttempts, host-qualified identity and collection provenance."
PREDICATE = 'Retain the original account lockout-or-rate-limit requirement. For serving managed MySQL 8.0+ with enabled instance password policy, complete current exact-bound users.list and a dated approved customer-controlled account scope equal to the entire API-visible user universe, PASS only when every account is BUILT_IN with enableFailedAttemptsCheck=true and positive integer allowedFailedAttempts. The operator-approved responsibility boundary is normative input, not a cloud observation; provider-internal managed accounts are outside the asserted customer scope. Missing, expired, mismatched, broader, mixed-authentication, malformed, denied, partial or unsupported scope/evidence remains UNKNOWN with any valid bounded configuration witness. Disabled or absent policy never proves FAIL because independent rate limiting may exist. No runtime login test is claimed.'
REMEDIATION = "Establish the full in-scope authentication-account inventory and approved lockout or rate-limiting controls. For supported managed MySQL built-in accounts, review instance password-policy enablement and each user's passwordPolicy.enableFailedAttemptsCheck and positive allowedFailedAttempts; verify other authentication paths separately without inferring a violation from missing metadata."
CORRECTED_SPEC = {"id": CHECK_ID, "provider": "gcp", "resource_kind": "sql_instance", "category": "identity", "severity": "medium", "title": TITLE, "description": DESCRIPTION_TEXT, "data_source": DATA_SOURCE, "predicate": PREDICATE, "remediation_hint": REMEDIATION}
CORRECTED_SPEC_SHA256 = hashlib.sha256(json.dumps(CORRECTED_SPEC, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
PREDICATE_SHA256 = hashlib.sha256(PREDICATE.encode()).hexdigest()
SOURCE_CORRECTION = {"version": "peaso-source-correction-v1", "status": "source_erratum_successor", "prior_frozen_signed_spec_sha256": PRIOR_FROZEN_SPEC_SHA256, "prior_frozen_status": "historical_superseded_for_this_check", "current_canonical_spec_sha256": CORRECTED_SPEC_SHA256, "current_predicate_sha256": PREDICATE_SHA256, "source_url": SOURCE_URL, "framework_id": "ccc_gcp", "requirement_ids": ["CCC.RDMS.CN02.AR01"], "original_requirement": ORIGINAL_REQUIREMENT, "criterion_scope": "Original account lockout or rate limiting: configured PASS is limited to the explicitly approved customer-account boundary, exactly matched to the complete API-visible roster; native witness alone does not establish that boundary or provider-internal/runtime protection"}
DESCRIPTION = {"title": TITLE, "description": DESCRIPTION_TEXT, "evaluated": [DATA_SOURCE], "pass_when": "A dated approved customer-account scope exactly equals the entire complete API-visible user universe, and every account has supported managed configured lockout. API-visible configuration alone never supplies PASS.", "fail_when": "A sufficiently bound actual violation of the original lockout-or-rate-limit requirement would be needed; missing native policy alone never supplies FAIL.", "unknown_when": "The approved customer-account scope, supported managed protection, or current exact source is unresolved; a native witness without the approved complete customer scope remains UNKNOWN.", "remediation": REMEDIATION, "evaluator_version": EVALUATOR_VERSION, "source_correction": SOURCE_CORRECTION}

def description():
    return deepcopy(DESCRIPTION)

def correction_provenance():
    return deepcopy(SOURCE_CORRECTION)
