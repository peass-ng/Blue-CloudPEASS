"""Lambda code update paths require one runnable function and matching grants."""

from peaso import privesc
from tests.test_peaso_privesc_schema_ext import reached
from test_peaso_privesc_lambda_role_swap_wrapper import _case as role_swap_case


SOURCE = "arn:aws:iam::111111111111:user/alice"
TARGET = "arn:aws:iam::111111111111:role/victim"
FUNCTION = "arn:aws:lambda:us-east-1:111111111111:function:existing"
CONFIG = "arn:aws:lambda:us-east-1:111111111111:code-signing-config:csc-0123456789abcdef0"


def _case(ident, actions, *, signing=False, package="Zip", concurrency=1,
          trust="lambda.amazonaws.com", deny_code=False):
    entry = next(row for row in privesc.load_catalog()["entries"] if row["id"] == ident)
    snap = role_swap_case(code=False, layer=False, read_layer=False)
    source = next(c for c in snap["collections"] if c["type"] == "iam_user")["items"][0]
    role = next(c for c in snap["collections"] if c["type"] == "iam_role")["items"][0]
    function = next(c for c in snap["collections"] if c["type"] == "lambda_function")["items"][0]
    function["Role"] = TARGET
    function["Configuration"]["Role"] = TARGET
    function["Configuration"]["PackageType"] = package
    function["Concurrency"]["ReservedConcurrentExecutions"] = concurrency
    role["AssumeRolePolicyDocument"]["Statement"][0]["Principal"]["Service"] = trust
    statements = [{"Effect": "Allow", "Action": action, "Resource": FUNCTION}
                  for action in actions]
    if deny_code:
        statements.append({"Effect": "Deny", "Action": "lambda:UpdateFunctionCode",
                           "Resource": FUNCTION})
    source["UserPolicyList"][0]["PolicyDocument"]["Statement"] = statements
    if signing:
        function["CodeSigning"]["CodeSigningConfigArn"] = CONFIG
        function["CodeSigningConfig"] = {"collection_status": "collected",
            "CodeSigningConfig": {"CodeSigningConfigArn": CONFIG,
                                  "CodeSigningPolicies": {"UntrustedArtifactOnDeployment": "Enforce"}}}
    return entry, snap


def _reached(entry, snap):
    return reached(privesc.analyze(snap, entries=[entry], include_unknown=False), SOURCE, entry["id"])


def test_direct_code_update_needs_invoke_and_unsigned_runnable_zip():
    ident = "aws-lambda-updatefunctioncode"
    actions = ("lambda:UpdateFunctionCode", "lambda:InvokeFunction")
    entry, snap = _case(ident, actions)
    assert _reached(entry, snap) == {TARGET: "conditional"}
    for missing in actions:
        entry, snap = _case(ident, tuple(a for a in actions if a != missing))
        assert TARGET not in _reached(entry, snap)
    for option in ({"signing": True}, {"package": "Image"}, {"concurrency": 0},
                   {"trust": "ec2.amazonaws.com"}):
        entry, snap = _case(ident, actions, **option)
        assert TARGET not in _reached(entry, snap)


def test_enforced_signing_needs_real_bypass_and_invoke():
    ident = "aws-lambda-codesigning-bypass-updatefunctioncode"
    actions = ("lambda:UpdateFunctionCode", "lambda:InvokeFunction",
               "lambda:DeleteFunctionCodeSigningConfig")
    entry, snap = _case(ident, actions, signing=True)
    assert _reached(entry, snap) == {TARGET: "conditional"}
    for missing in actions:
        entry, snap = _case(ident, tuple(a for a in actions if a != missing), signing=True)
        assert TARGET not in _reached(entry, snap)
    entry, snap = _case(ident, actions)
    assert TARGET not in _reached(entry, snap)


def test_resource_policy_rewrite_needs_all_writes_and_no_code_deny():
    ident = "aws-lambda-putresourcepolicy-grant-updatefunctioncode"
    actions = ("lambda:PutResourcePolicy", "lambda:AddPermission", "lambda:RemovePermission")
    entry, snap = _case(ident, actions)
    assert _reached(entry, snap) == {TARGET: "conditional"}
    for missing in actions:
        entry, snap = _case(ident, tuple(a for a in actions if a != missing))
        assert TARGET not in _reached(entry, snap)
    entry, snap = _case(ident, actions, deny_code=True)
    assert TARGET not in _reached(entry, snap)
    entry, snap = _case(ident, actions, signing=True)
    assert TARGET not in _reached(entry, snap)
