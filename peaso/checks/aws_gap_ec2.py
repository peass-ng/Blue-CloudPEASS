"""EC2 instance-profile role permissions (Steampipe ``ec2_instance_no_iam_*``).

The pinned Steampipe queries join instance -> instance profile -> role and then read the
role's *trust* policy (``assume_role_policy_std``) for statements whose Action is in a
sensitive-action list, so they test which actions EC2 may call ``sts:AssumeRole`` with
(always ``sts:assumerole``), never what the role can do. Several lists contain typos
(``iam:updateassumerolerolicy``, ``srds-data:ExecuteStatement``) and the "creation with
attached policy" / "pass role and Lambda" queries require one action to equal two values.

These natives evaluate the documented requirement: the identity policies of the role
attached to the instance (inline ``RolePolicyList`` and the default version of each attached
managed policy, from GetAccountAuthorizationDetails) must not allow any listed action
(``all_of``: the combination). Action and NotAction use IAM wildcard matching. A definite grant requires an
unconditional Allow on Resource ``*``, no applicable uncertain Deny, and (when present)
a matching permissions boundary. Scoped resources and conditions are UNKNOWN when
they could change authorization; Organizations SCPs and session policies are out of scope.
An unresolved instance-profile role or managed policy join is UNKNOWN.
"""
from __future__ import annotations

from . import result
from .facts import Unavailable, get, list_of_objects, optional
from .claude_aws_a_common import items, absent_or, as_list, strings, iam_pattern_matches, policy_document, idx
from .claude_aws_a_ec2 import w, INST, DROP
from .claude_aws_a_iam import ROLE, default_document, pol, allow, doc
from .aws_gap_core import install

NATIVE_IDS = []
PROFILE = INST["IamInstanceProfile"]["Arn"]
APP = w(ROLE, InstanceProfileList=[{"InstanceProfileName": "app", "Arn": PROFILE}])

# Steampipe query suffix -> (title, actions, all_of). Action lists are the pinned query
# lists, lower-cased, with the two upstream typos corrected and the literal '*:*' dropped
# (wildcard statements are matched by the evaluator).
QUERIES = {
    "role_with_management_level_access": ("IAM management-level access", [
        "iam:attachgrouppolicy", "iam:attachrolepolicy", "iam:attachuserpolicy", "iam:createpolicy", "iam:createpolicyversion",
        "iam:deleteaccountpasswordpolicy", "iam:deletegrouppolicy", "iam:deletepolicy", "iam:deletepolicyversion", "iam:deleterolepermissionsboundary",
        "iam:deleterolepolicy", "iam:deleteuserpermissionsboundary", "iam:deleteuserpolicy", "iam:detachgrouppolicy", "iam:detachrolepolicy",
        "iam:detachuserpolicy", "iam:putgrouppolicy", "iam:putrolepermissionsboundary", "iam:putrolepolicy", "iam:putuserpermissionsboundary",
        "iam:putuserpolicy", "iam:setdefaultpolicyversion", "iam:updateassumerolepolicy"], False),
    "role_with_data_destruction_access": ("data destruction access", [
        "s3:deletebucket", "rds:deletedbcluster", "rds:deletedbinstance", "rds:deletedbsnapshot", "rds:deletedbclustersnapshot",
        "rds:deleteglobalcluster", "ec2:deletesnapshot", "ec2:deletevolume"], False),
    "with_write_level_access": ("IAM write-level access", [
        "iam:addclientidtoopenidconnectprovider", "iam:addroletoinstanceprofile", "iam:addusertogroup", "iam:changepassword", "iam:createaccesskey",
        "iam:createaccountalias", "iam:creategroup", "iam:createinstanceprofile", "iam:createloginprofile", "iam:createopenidconnectprovider",
        "iam:createrole", "iam:createsamlprovider", "iam:createservicelinkedrole", "iam:createservicespecificcredential", "iam:createuser",
        "iam:createvirtualmfadevice", "iam:deactivatemfadevice", "iam:deleteaccesskey", "iam:deleteaccountalias", "iam:deletegroup",
        "iam:deleteinstanceprofile", "iam:deleteloginprofile", "iam:deleteopenidconnectprovider", "iam:deleterole", "iam:deletesamlprovider",
        "iam:deletesshpublickey", "iam:deleteservercertificate", "iam:deleteservicelinkedrole", "iam:deleteservicespecificcredential",
        "iam:deletesigningcertificate", "iam:deleteuser", "iam:deletevirtualmfadevice", "iam:enablemfadevice", "iam:passrole",
        "iam:removeclientidfromopenidconnectprovider", "iam:removerolefrominstanceprofile", "iam:removeuserfromgroup",
        "iam:resetservicespecificcredential", "iam:resyncmfadevice", "iam:setsecuritytokenservicepreferences", "iam:updateaccesskey",
        "iam:updateaccountpasswordpolicy", "iam:updategroup", "iam:updateloginprofile", "iam:updateopenidconnectproviderthumbprint",
        "iam:updaterole", "iam:updateroledescription", "iam:updatesamlprovider", "iam:updatesshpublickey", "iam:updateservercertificate",
        "iam:updateservicespecificcredential", "iam:updatesigningcertificate", "iam:updateuser", "iam:uploadsshpublickey",
        "iam:uploadservercertificate", "iam:uploadsigningcertificate"], False),
    "role_with_database_management_write_access": ("database management write access", [
        "rds:modifydbcluster", "rds:modifydbclusterendpoint", "rds:modifydbinstance", "rds:modifydbsnapshot", "rds:modifyglobalcluster",
        "dynamodb:updateitem", "dynamodb:updatetable", "memorydb:updatecluster", "neptune-db:resetdatabase", "neptune-db:writedataviaquery",
        "docdb-elastic:updatecluster", "elasticache:modifycachecluster", "cassandra:alter", "cassandra:modify", "qldb:executestatement",
        "qldb:partiqlupdate", "qldb:sendcommand", "qldb:updateledger", "redshift:modifycluster", "redshift:modifyclustersnapshot",
        "redshift:modifyendpointaccess", "timestream:updatedatabase", "timestream:updatetable", "timestream:writerecords"], False),
    "role_with_org_write_access": ("AWS Organizations write access", [
        "organizations:accepthandshake", "organizations:attachpolicy", "organizations:cancelhandshake", "organizations:createaccount",
        "organizations:creategovcloudaccount", "organizations:createorganization", "organizations:createorganizationalunit",
        "organizations:createpolicy", "organizations:declinehandshake", "organizations:deleteorganization", "organizations:deleteorganizationalunit",
        "organizations:deletepolicy", "organizations:deregisterdelegatedadministrator", "organizations:detachpolicy",
        "organizations:disableawsserviceaccess", "organizations:disablepolicytype", "organizations:enableawsserviceaccess",
        "organizations:enableallfeatures", "organizations:enablepolicytype", "organizations:inviteaccounttoorganization",
        "organizations:leaveorganization", "organizations:moveaccount", "organizations:registerdelegatedadministrator",
        "organizations:removeaccountfromorganization", "organizations:updateorganizationalunit", "organizations:updatepolicy"], False),
    "role_with_privilege_escalation_risk_access": ("privilege escalation risk access", [
        "iam:createpolicy", "iam:createpolicyversion", "iam:setdefaultpolicyversion", "iam:passrole", "iam:createaccesskey",
        "iam:createloginprofile", "iam:updateloginprofile", "iam:attachuserpolicy", "iam:attachgrouppolicy", "iam:attachrolepolicy",
        "iam:putuserpolicy", "iam:putgrouppolicy", "iam:putrolepolicy", "iam:addusertogroup", "iam:updateassumerolepolicy"], False),
    "role_with_new_group_creation_with_attached_policy_access": ("new group creation with attached policy access",
        ["iam:creategroup", "iam:attachgrouppolicy"], True),
    "role_with_new_role_creation_with_attached_policy_access": ("new role creation with attached policy access",
        ["iam:createrole", "iam:attachrolepolicy"], True),
    "role_with_new_user_creation_with_attached_policy_access": ("new user creation with attached policy access",
        ["iam:createuser", "iam:attachuserpolicy"], True),
    "role_with_write_access_to_resource_based_policies": ("write access to resource-based policies", [
        "ecr:setrepositorypolicy", "serverlessrepo:putapplicationpolicy", "backup:putbackupvaultaccesspolicy", "elasticfilesystem:putfilesystempolicy",
        "glacier:setvaultaccesspolicy", "secretsmanager:putresourcepolicy", "events:putpermission", "mediastore:putcontainerpolicy",
        "glue:putresourcepolicy", "ses:putidentitypolicy", "lambda:addpermission", "lambda:addlayerversionpermission", "s3:putbucketpolicy",
        "s3:putbucketacl", "s3:putobject", "s3:putobjectacl", "kms:creategrant", "kms:putkeypolicy", "es:updateelasticsearchdomainconfig",
        "sns:addpermission", "sqs:addpermission"], False),
    "role_attached_with_credentials_exposure_access": ("credentials exposure access", [
        "chime:createapikey", "codepipeline:pollforjobs", "cognito-identity:getopenidtoken", "cognito-identity:getopenidtokenfordeveloperidentity",
        "cognito-identity:getcredentialsforidentity", "connect:getfederationtoken", "connect:getfederationtokens", "ec2:getpassworddata",
        "ecr:getauthorizationtoken", "gamelift:requestuploadcredentials", "iam:createaccesskey", "iam:createloginprofile",
        "iam:createservicespecificcredential", "iam:resetservicespecificcredential", "iam:updateaccesskey", "lightsail:getinstanceaccessdetails",
        "lightsail:getrelationaldatabasemasteruserpassword", "rds-db:connect", "redshift:getclustercredentials", "sso:getrolecredentials",
        "mediapackage:rotatechannelcredentials", "mediapackage:rotateingestendpointcredentials", "sts:assumerole", "sts:assumerolewithsaml",
        "sts:assumerolewithwebidentity", "sts:getfederationtoken", "sts:getsessiontoken"], False),
    "role_with_destruction_kms_access": ("KMS decrypt / secret value access", ["secretsmanager:getsecretvalue", "kms:decrypt"], False),
    "role_with_destruction_rds_access": ("RDS Data API statement execution access", ["rds-data:executestatement", "rds-data:batchexecutestatement"], False),
    "role_with_cloud_log_tampering_access": ("cloud log tampering access", [
        "cloudtrail:deletetrail", "cloudtrail:puteventselectors", "cloudtrail:stoplogging", "ec2:deleteflowlogs", "s3:putbucketlogging",
        "logs:deletelogstream", "logs:deleteloggroup", "waf:deleteloggingconfiguration", "waf:putloggingconfiguration"], False),
    "role_with_alter_critical_s3_permissions_configuration": ("alter critical S3 permissions configuration", [
        "s3:putobjectretention", "s3:putlifecycleconfiguration", "s3:putbucketpolicy", "s3:putbucketversioning"], False),
    "role_with_write_permission_on_critical_s3_configuration": ("write permission on critical S3 configuration", [
        "s3:putobjectretention", "s3:putlifecycleconfiguration", "s3:putbucketpolicy", "s3:putbucketversioning"], False),
    "role_with_security_group_write_access": ("security group write access", [
        "rds:createdbsecuritygroup", "rds:deletedbsecuritygroup", "rds:revokedbsecuritygroupingress", "ec2:authorizesecuritygroupegress",
        "ec2:authorizesecuritygroupingress", "ec2:createsecuritygroup", "ec2:deletesecuritygroup", "ec2:modifysecuritygrouprules",
        "ec2:revokesecuritygroupegress", "ec2:revokesecuritygroupingress", "elasticloadbalancing:applysecuritygroupstoloadbalancer",
        "elasticloadbalancing:setsecuritygroups", "redshift:authorizeclustersecuritygroupingress", "redshift:createclustersecuritygroup",
        "redshift:deleteclustersecuritygroup"], False),
    "role_with_defense_evasion_impact_of_aws_security_services_access": ("defense evasion of AWS security services access", [
        "guardduty:updatedetector", "guardduty:deletedetector", "guardduty:deletemembers", "guardduty:updatefilter", "guardduty:deletefilter",
        "shield:disableapplicationlayerautomaticresponse", "shield:updateprotectiongroup", "shield:deletesubscription",
        "detective:disassociatemembership", "detective:deletemembers", "inspector:disable", "config:stopconfigurationrecorder",
        "config:deleteconfigurationrecorder", "config:deleteconfigrule", "config:deleteorganizationconfigrule", "cloudwatch:disablealarmactions",
        "cloudwatch:disableinsightrules"], False),
    "role_with_elastic_ip_hijacking_access": ("Elastic IP hijacking access", ["ec2:disassociateaddress", "ec2:enableaddresstransfer"], False),
    "passrole_and_lambda_invoke_function_access": ("iam:PassRole with Lambda create and invoke function access",
        ["iam:passrole", "lambda:createfunction", "lambda:invokefunction"], True),
}


def _matches(statement, action):
    action_value = optional(statement, "Action", None)
    not_action_value = optional(statement, "NotAction", None)
    if ("Action" in statement) == ("NotAction" in statement):
        raise Unavailable("policy statement requires exactly one Action/NotAction")
    key = "Action" if "Action" in statement else "NotAction"
    patterns = strings(as_list(action_value if key == "Action" else not_action_value), key)
    if not patterns or any(not pattern for pattern in patterns):
        raise Unavailable("empty policy action")
    matched = any(iam_pattern_matches(pattern, action) for pattern in patterns)
    return matched if key == "Action" else not matched


def _effect(statement):
    effect = get(statement, "Effect", str)
    if effect not in ("Allow", "Deny"):
        raise Unavailable("malformed policy statement effect")
    return effect


def _statement_scope(statement):
    """True for every resource, None when authorization needs resource/condition context."""
    resource_value = optional(statement, "Resource", None)
    not_resource_value = optional(statement, "NotResource", None)
    if ("Resource" in statement) == ("NotResource" in statement):
        raise Unavailable("policy statement requires exactly one Resource/NotResource")
    key = "Resource" if "Resource" in statement else "NotResource"
    resources = strings(as_list(resource_value if key == "Resource" else not_resource_value), key)
    if not resources or any(not resource for resource in resources):
        raise Unavailable("empty policy resource")
    condition = optional(statement, "Condition", None)
    if condition is not None:
        if not isinstance(condition, dict) or not condition:
            raise Unavailable("malformed policy condition")
        return None
    if key == "NotResource":
        return False if "*" in resources else None
    return True if "*" in resources else None


def allowed(statements, action):
    """True/False for proven authorization/absence; None when effective grant is unresolved."""
    allow_hit = uncertain_allow = uncertain_deny = deny_hit = False
    for statement in statements:
        try:
            if not _matches(statement, action):
                continue
            effect = _effect(statement)
            scope = _statement_scope(statement)
        except Unavailable:
            # An unreadable candidate cannot establish a grant or deny. Retain
            # its possible effect while allowing independent authoritative proof.
            try:
                effect = _effect(statement)
            except Unavailable:
                effect = None
            uncertain_allow |= effect in (None, "Allow")
            uncertain_deny |= effect in (None, "Deny")
            continue
        if effect == "Allow":
            allow_hit |= scope is True
            uncertain_allow |= scope is None
        else:
            deny_hit |= scope is True
            uncertain_deny |= scope is None
    if deny_hit:
        return False
    if allow_hit:
        return None if uncertain_deny else True
    return None if uncertain_allow else False


def _policy(index, arn):
    for policy in items(index, "iam_policy"):
        if get(policy, "Arn", str) == arn:
            return policy_document(default_document(policy))
    raise Unavailable("managed policy %s not in inventory" % arn)


def role_statements(role, index):
    """(identity statements, permissions boundary statements or None) of one GAAD role."""
    statements = []
    for inline in list_of_objects(absent_or(role, "RoleName", "RolePolicyList", [], list)):
        statements.extend(policy_document(get(inline, "PolicyDocument")))
    for attached in list_of_objects(absent_or(role, "RoleName", "AttachedManagedPolicies", [], list)):
        statements.extend(_policy(index, get(attached, "PolicyArn", str)))
    boundary = absent_or(role, "RoleName", "PermissionsBoundary", None, dict)
    if boundary:
        return statements, _policy(index, get(boundary, "PermissionsBoundaryArn", str))
    return statements, None


def instance_roles(item, index):
    profile = absent_or(item, "InstanceId", "IamInstanceProfile", None, dict)
    if profile is None:
        return None
    arn = get(profile, "Arn", str)
    roles = [r for r in items(index, "iam_role")
             if any(get(p, "Arn", str) == arn for p in list_of_objects(absent_or(r, "RoleName", "InstanceProfileList", [], list)))]
    if not roles:
        raise Unavailable("instance profile role not in inventory: " + arn)
    return roles


def granted(role, index, actions):
    statements, boundary = role_statements(role, index)
    found, unresolved = [], []
    for action in actions:
        identity = allowed(statements, action)
        bound = True if boundary is None or identity is False else allowed(boundary, action)
        if identity is True and bound is True:
            found.append(action)
        elif (identity is None and bound is not False) or (identity is True and bound is None):
            unresolved.append(action)
    return found, unresolved


def _install(suffix, spec):
    title, actions, all_of = spec
    query = "ec2_instance_no_iam_" + suffix
    cid = "aws.gap.ec2.instance_no_iam_" + suffix
    first = actions[0]
    services = sorted({action.split(":")[0] + ":*" for action in actions})
    attached_arn = "arn:aws:iam::123456789012:policy/broad"
    grant = pol(allow(actions if all_of else first), arn=attached_arn)
    fail_role = w(APP, AttachedManagedPolicies=[{"PolicyArn": attached_arn, "PolicyName": "broad"}])
    star_role = w(APP, RolePolicyList=[{"PolicyName": "admin", "PolicyDocument": doc(allow("*"))}])
    service_role = w(APP, RolePolicyList=[{"PolicyName": "svc", "PolicyDocument": doc(allow(services))}])
    denied_role = w(APP, RolePolicyList=[{"PolicyName": "admin", "PolicyDocument": doc(allow("*"), {"Effect": "Deny", "Action": "*", "Resource": "*"})}])
    not_action = w(APP, RolePolicyList=[{"PolicyName": "na", "PolicyDocument": doc({"Effect": "Allow", "NotAction": "ec2:DescribeInstances", "Resource": "*"})}])
    bounded = w(star_role, PermissionsBoundary={"PermissionsBoundaryType": "Policy", "PermissionsBoundaryArn": "arn:aws:iam::123456789012:policy/boundary"})
    boundary = pol(allow("ec2:Describe*"), arn="arn:aws:iam::123456789012:policy/boundary")
    variants = [
        ("FAIL", INST, idx(iam_role=[star_role], iam_policy=[])),
        ("FAIL", INST, idx(iam_role=[service_role], iam_policy=[])),
        ("FAIL", INST, idx(iam_role=[not_action], iam_policy=[])),
        ("PASS", INST, idx(iam_role=[denied_role], iam_policy=[])),
        ("PASS", INST, idx(iam_role=[bounded], iam_policy=[boundary])),
        ("UNKNOWN", INST, idx(iam_role=[bounded], iam_policy=[])),
        ("PASS", w(INST, IamInstanceProfile=DROP), idx(iam_role=[fail_role], iam_policy=[grant])),
        ("UNKNOWN", INST, idx(iam_role=[ROLE], iam_policy=[])),
        ("UNKNOWN", INST, idx(iam_role=[fail_role], iam_policy=[])),
        ("UNKNOWN", INST, idx(iam_role=None, iam_policy=[])),
    ]
    if all_of:
        partial = pol(allow(actions[:-1]), arn=attached_arn)
        variants.append(("PASS", INST, idx(iam_role=[fail_role], iam_policy=[partial])))

    @install(cid, "instance", "EC2 instance role does not allow %s" % title, "high", "AC-6",
        "Remove %s from the policies of the instance profile role, or use a role scoped to the workload." % title,
        category="least_privilege", dependencies=["instance", "iam_role", "iam_policy"], ids=NATIVE_IDS,
        cases={"pass": INST, "index": idx(iam_role=[APP], iam_policy=[]), "fail": INST,
               "fail_index": idx(iam_role=[fail_role], iam_policy=[grant]), "variants": variants})
    def evaluate(item, index):
        roles = instance_roles(item, index)
        if roles is None:
            return result(False, instance_profile=False)
        hits, unresolved = {}, {}
        for role in roles:
            found, uncertain = granted(role, index, actions)
            name = get(role, "RoleName", str)
            if found and (not all_of or len(found) == len(actions)):
                hits[name] = found
            elif uncertain and (not all_of or len(found) + len(uncertain) == len(actions)):
                unresolved[name] = uncertain
        if hits:
            return result(True, roles={k: v for k, v in sorted(hits.items())}, all_of=all_of)
        if unresolved:
            raise Unavailable("instance role effective authorization unresolved: " + ", ".join(sorted(unresolved)))
        return result(False, roles={}, all_of=all_of)
    evaluate.__doc__ = "Corrected requirement of Steampipe %s." % query
    return query, cid


STEAMPIPE_NATIVES = dict(_install(suffix, spec) for suffix, spec in QUERIES.items())
