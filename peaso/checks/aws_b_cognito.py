"""Cognito password/sign-up/threat-protection policies over native metadata."""
from . import result, unknown
from .facts import get, optional
from .fixtures import nest
from .aws_b_core import install, IDS as ALL_IDS

_before = set(ALL_IDS)
UPSTREAM = {}
PREFIX = "Configuration.UserPool."


def setting(item, path, default, expected):
    pool = get(item, "Configuration.UserPool", dict)
    configuration = get(item, "Configuration", dict)
    observed = configuration.get("collection_status") == "collected" and isinstance(pool.get("Id"), str) and bool(pool["Id"])
    if not observed:
        return get(pool, path, expected)
    parts = path.split(".")
    value = pool
    for part in parts[:-1]:
        value = optional(value, part, {}, dict)
    value = optional(value, parts[-1], default)
    if type(value) is not expected:
        raise ValueError("malformed Cognito setting: " + path)
    return value


def policy(cid, upstream, path, good, bad, default, *, allowed=None):
    UPSTREAM[upstream] = cid
    @install(cid, "cognito_user_pool", "Cognito user pool enforces " + upstream.removeprefix("cognito_user_pool_").replace("_", " "),
             nest(PREFIX + path, good), nest(PREFIX + path, bad))
    def evaluate(item, index):
        value = setting(item, path, default, type(good))
        if allowed is not None and value not in allowed:
            return unknown("unrecognized Cognito setting", field=path, configured=value)
        return result(value != good, field=path, configured=value)


for _suffix, _field in (("lowercase", "RequireLowercase"), ("uppercase", "RequireUppercase"),
                       ("number", "RequireNumbers"), ("symbol", "RequireSymbols")):
    policy("aws.b.cognito.password_" + _suffix, "cognito_user_pool_password_policy_" + _suffix,
           "Policies.PasswordPolicy." + _field, True, False, False)

policy("aws.b.cognito.deletion_protection", "cognito_user_pool_deletion_protection_enabled", "DeletionProtection", "ACTIVE", "INACTIVE", "INACTIVE", allowed={"ACTIVE", "INACTIVE"})
policy("aws.b.cognito.required_mfa", "cognito_user_pool_mfa_enabled", "MfaConfiguration", "ON", "OFF", "OFF", allowed={"ON", "OFF", "OPTIONAL"})
policy("aws.b.cognito.enforced_threat_protection", "cognito_user_pool_advanced_security_enabled", "UserPoolAddOns.AdvancedSecurityMode", "ENFORCED", "AUDIT", "OFF", allowed={"ENFORCED", "AUDIT", "OFF"})
policy("aws.b.cognito.admin_only_signup", "cognito_user_pool_self_registration_disabled", "AdminCreateUserConfig.AllowAdminCreateUserOnly", True, False, False)


UPSTREAM["cognito_user_pool_password_policy_minimum_length_14"] = "aws.b.cognito.password_minimum_fourteen"
@install("aws.b.cognito.password_minimum_fourteen", "cognito_user_pool", "Cognito password policy requires at least fourteen characters",
         nest(PREFIX + "Policies.PasswordPolicy.MinimumLength", 14), nest(PREFIX + "Policies.PasswordPolicy.MinimumLength", 13))
def minimum(item, index):
    length = setting(item, "Policies.PasswordPolicy.MinimumLength", 0, int)
    if length < 0 or length > 99:
        return unknown("malformed password minimum length")
    return result(length < 14, minimum_length=length, source_threshold=14)


UPSTREAM["cognito_user_pool_temporary_password_expiration"] = "aws.b.cognito.temporary_password_seven_days"
@install("aws.b.cognito.temporary_password_seven_days", "cognito_user_pool", "Cognito temporary passwords expire within seven days",
         nest(PREFIX + "Policies.PasswordPolicy.TemporaryPasswordValidityDays", 7), nest(PREFIX + "Policies.PasswordPolicy.TemporaryPasswordValidityDays", 8))
def temporary(item, index):
    days = setting(item, "Policies.PasswordPolicy.TemporaryPasswordValidityDays", 0, int)
    if not 0 <= days <= 365:
        return unknown("malformed temporary password validity")
    return result(days > 7, declared_validity_days=days, effective_default_days=7 if days == 0 else days,
                  semantics="Pinned source adapter maps omission to zero; AWS treats zero/omission as the seven-day default, preserving this threshold outcome.")


def threat_mode(item):
    mode = setting(item, "UserPoolAddOns.AdvancedSecurityMode", "OFF", str)
    if mode not in {"OFF", "AUDIT", "ENFORCED"}:
        raise ValueError("unknown threat-protection mode")
    return mode


_good_compromised = {"Configuration": {"UserPool": {"UserPoolAddOns": {"AdvancedSecurityMode": "ENFORCED"}}},
    "Risk": {"RiskConfiguration": {"CompromisedCredentialsRiskConfiguration": {"EventFilter": ["SIGN_IN"], "Actions": {"EventAction": "BLOCK"}}}}}
_bad_compromised = {"Configuration": {"UserPool": {"UserPoolAddOns": {"AdvancedSecurityMode": "AUDIT"}}}}
UPSTREAM["cognito_user_pool_blocks_compromised_credentials_sign_in_attempts"] = "aws.b.cognito.block_compromised_signin"
@install("aws.b.cognito.block_compromised_signin", "cognito_user_pool", "Cognito enforces compromised-credential sign-in blocking", _good_compromised, _bad_compromised)
def compromised(item, index):
    mode = threat_mode(item)
    if mode != "ENFORCED":
        return result(True, threat_protection_mode=mode)
    risk = get(item, "Risk", dict)
    known = risk.get("collection_status") == "collected"
    configuration = optional(risk, "RiskConfiguration", {}, dict) if known else get(risk, "RiskConfiguration", dict)
    block = optional(configuration, "CompromisedCredentialsRiskConfiguration", {}, dict) if known else get(configuration, "CompromisedCredentialsRiskConfiguration", dict)
    events = optional(block, "EventFilter", [], list) if known else get(block, "EventFilter", list)
    if any(not isinstance(value, str) for value in events):
        return unknown("malformed compromised-credential event list")
    actions = optional(block, "Actions", {}, dict) if known else get(block, "Actions", dict)
    action = optional(actions, "EventAction", "", str) if known else get(actions, "EventAction", str)
    if action not in {"BLOCK", "NO_ACTION", ""}:
        return unknown("unknown compromised-credential policy action")
    return result("SIGN_IN" not in events or action != "BLOCK", threat_protection_mode=mode, event_filter=events, configured_response=action)


_good_takeover = {"Configuration": {"UserPool": {"UserPoolAddOns": {"AdvancedSecurityMode": "ENFORCED"}}},
    "Risk": {"RiskConfiguration": {"AccountTakeoverRiskConfiguration": {"Actions": {level: {"EventAction": "BLOCK"} for level in ("LowAction", "MediumAction", "HighAction")}}}}}
UPSTREAM["cognito_user_pool_blocks_potential_malicious_sign_in_attempts"] = "aws.b.cognito.block_all_takeover_risks"
@install("aws.b.cognito.block_all_takeover_risks", "cognito_user_pool", "Cognito enforces blocking at every account-takeover risk level", _good_takeover, _bad_compromised)
def takeover(item, index):
    mode = threat_mode(item)
    if mode != "ENFORCED":
        return result(True, threat_protection_mode=mode)
    risk = get(item, "Risk", dict)
    known = risk.get("collection_status") == "collected"
    configuration = optional(risk, "RiskConfiguration", {}, dict) if known else get(risk, "RiskConfiguration", dict)
    block = optional(configuration, "AccountTakeoverRiskConfiguration", {}, dict) if known else get(configuration, "AccountTakeoverRiskConfiguration", dict)
    actions = optional(block, "Actions", {}, dict) if known else get(block, "Actions", dict)
    levels = {}
    for level in ("LowAction", "MediumAction", "HighAction"):
        policy = optional(actions, level, {}, dict) if known else get(actions, level, dict)
        response = optional(policy, "EventAction", "", str) if known else get(policy, "EventAction", str)
        if response not in {"BLOCK", "NO_ACTION", "MFA_IF_CONFIGURED", "MFA_REQUIRED", ""}:
            return unknown("unknown account-takeover policy response", risk_level=level)
        levels[level] = response
    return result(any(response != "BLOCK" for response in levels.values()), threat_protection_mode=mode, configured_responses=levels)


IDS = [cid for cid in ALL_IDS if cid not in _before]
