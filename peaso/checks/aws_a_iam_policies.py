"""Exact declared managed-policy variants; no effective-access simulation."""
from . import register, result, unknown, statements, array
from .facts import get, optional, list_of_objects, Unavailable
from .fixtures import CASES

NATIVE_IDS = []
SHELL = "arn:aws:iam::aws:policy/AWSCloudShellFullAccess"


for kind in ("iam_user", "iam_group", "iam_role"):
    def install(kind=kind):
        cid = "aws.a.iam." + kind.removeprefix("iam_") + "_no_cloudshell_full_access"
        @register(cid, "aws", "least_privilege", kind, "IAM " + kind.removeprefix("iam_") + " avoids direct AWSCloudShellFullAccess attachment",
            "medium", "AC-6", "Review direct AWSCloudShellFullAccess attachment separately from equivalent inline or inherited permissions.")
        def evaluate(item, index):
            attached = list_of_objects(get(item, "AttachedManagedPolicies", list))
            arns = [get(policy, "PolicyArn", str) for policy in attached]
            return result(SHELL in arns, matching_attachment_count=arns.count(SHELL),
                semantics="Exact source managed-policy ARN test; no inference about effective CloudShell permissions")
        CASES[cid] = {"pass": {"AttachedManagedPolicies": []}, "fail": {"AttachedManagedPolicies": [{"PolicyArn": SHELL}]}, "missing": {}, "malformed": None}
        NATIVE_IDS.append(cid)
    install()


@register("aws.a.iam.attached_policy_no_star_star", "aws", "least_privilege", "iam_policy", "Attached customer-managed policy has no declared wildcard administrator statement",
    "high", "AC-6", "Review attached declared full-action/full-resource grants; AWS managed wildcard grants require manual review under the source.")
def attached_admin(item, index):
    count = get(item, "AttachmentCount", int)
    if count < 0:
        return unknown("negative policy attachment count")
    if count == 0:
        return "NOT_APPLICABLE", {"reason": "Source attached-policy-only filter"}
    arn = get(item, "Arn", str)
    parts = arn.split(":", 5)
    if len(parts) != 6 or parts[2] != "iam" or not parts[5].startswith("policy/"):
        return unknown("malformed managed-policy ARN")
    managed = parts[4] == "aws"
    if not managed and (len(parts[4]) != 12 or not parts[4].isdigit()):
        return unknown("malformed policy account")
    versions = list_of_objects(get(item, "PolicyVersionList", list))
    default = [version for version in versions if get(version, "IsDefaultVersion", bool)]
    if len(default) != 1:
        raise Unavailable("exactly one default managed policy version required")
    bad = unresolved = 0
    for statement in statements(get(default[0], "Document")):
        try:
            effect = get(statement, "Effect", str)
            if effect not in {"Allow", "Deny"}:
                raise Unavailable("malformed IAM statement Effect")
            if effect != "Allow":
                continue
            # This signed source tests explicit literals, not NotAction/NotResource
            # interpretation or effective permissions.
            actions = array(optional(statement, "Action", []))
            resources = array(optional(statement, "Resource", []))
            if any(not isinstance(value, str) for value in actions + resources):
                raise Unavailable("malformed IAM action/resource values")
        except (Unavailable, ValueError):
            unresolved += 1
            continue
        if "*" in resources and any(action in {"*", "*:*"} for action in actions):
            bad += 1
    if unresolved and not bad:
        return unknown("declared policy statement fields unavailable", unresolved_statements=unresolved)
    if bad and managed:
        return "MANUAL", {"reason": "Pinned source AWS managed wildcard-policy informational review", "wildcard_statement_count": bad}
    return result(bool(bad), wildcard_statement_count=bad,
        semantics="Declared source literals including conditioned statements; denies, boundaries and effective access are not simulated")
POLICY = {"AttachmentCount": 1, "Arn": "arn:aws:iam::123456789012:policy/inert", "PolicyVersionList": [{"IsDefaultVersion": True,
    "Document": {"Statement": [{"Effect": "Allow", "Action": "s3:ListAllMyBuckets", "Resource": "*"}]}}]}
BAD = {**POLICY, "PolicyVersionList": [{"IsDefaultVersion": True, "Document": {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}}]}
CASES["aws.a.iam.attached_policy_no_star_star"] = {"pass": POLICY, "fail": BAD, "missing": {}, "malformed": None,
    "not_applicable": {"AttachmentCount": 0}, "manual": {**BAD, "Arn": "arn:aws:iam::aws:policy/AdministratorAccess"}}
NATIVE_IDS.append("aws.a.iam.attached_policy_no_star_star")
