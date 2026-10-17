"""ARN field semantics, complete API omission and unavailable parent guards."""
import copy
from peaso.checks import CHECKS,aws_a_ec2 as rules
from peaso.checks.fixtures import CASES

CHECK=next(c for c in CHECKS if c.id==rules.NATIVE_IDS[0])


def test_exact_arn_source_states_and_purity():
    for state,expected in (("pass","PASS"),("fail","FAIL"),("missing","UNKNOWN"),("malformed","UNKNOWN")):
        item=copy.deepcopy(CASES[CHECK.id][state]);before=copy.deepcopy(item)
        assert CHECK.evaluate(item,{})[0]==expected
        assert item==before
    assert CHECK.evaluate({"IamInstanceProfile":{"collection_status":"denied"}},{})[0]=="UNKNOWN"


def test_profile_object_existence_cannot_substitute_for_declared_arn():
    assert CHECK.evaluate({"IamInstanceProfile":{"Id":"AIPAINERT"}},{})[0]=="UNKNOWN"
    assert CHECK.evaluate({"IamInstanceProfile":{}},{})[0]=="UNKNOWN"
    assert CHECK.evaluate({"IamInstanceProfile":{"Arn":"not-an-arn"}},{})[0]=="UNKNOWN"
    assert CHECK.evaluate({"_provenance":rules.PROOF},{})[0]=="FAIL"
    assert CHECK.evaluate({},{})[0]=="UNKNOWN"


def test_user_data_projection_before_cache_contains_only_booleans(monkeypatch):
    import base64,json
    import pytest
    boto3=pytest.importorskip("boto3")
    from botocore.stub import Stubber
    from peaso.collectors import aws
    session=boto3.Session(aws_access_key_id="inert",aws_secret_access_key="inert",region_name="us-east-1")
    client=session.client("ec2",region_name="us-east-1");stub=Stubber(client)
    marker="INERT_USER_DATA_SECRET_NEVER_CACHE"
    text="secret="+marker
    value=base64.b64encode(text.encode()).decode()
    stub.add_response("describe_instance_attribute",{"InstanceId":"i-inert","UserData":{"Value":value}},{"InstanceId":"i-inert","Attribute":"userData"})
    monkeypatch.setattr(aws.Requests,"client",lambda *args:client)
    with stub:
        requests=aws.Requests({});response=requests.call(session,"ec2","us-east-1","describe_instance_attribute",InstanceId="i-inert",Attribute="userData")
        assert response["UserDataIndicators"]["KeywordMatch"] is True
        serialized=json.dumps(response)
        assert marker not in serialized and value not in serialized and "UserData\"" not in serialized
        assert all(marker not in json.dumps(future.result()) and value not in json.dumps(future.result()) for future in requests._cache.values())
        assert requests.call(session,"ec2","us-east-1","describe_instance_attribute",InstanceId="i-inert",Attribute="userData")==response
        assert requests.calls==1
        stub.assert_no_pending_responses()


def test_user_data_exact_case_and_linear_password_shape_source_semantics():
    import base64,re
    from peaso.collectors import aws
    examples=["", "PASS SECRET TOKEN KEY", "monkey", "aA1!", "aA\n1!", "aA1", "lower123!", "A1!UPPER", "#!/bin/bash\necho ordinary"]
    pattern=r"(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]"
    check=next(c for c in CHECKS if c.id=="aws.a.ec2.user_data_source_indicators")
    for text in examples:
        response=aws._project_user_data_indicators({"InstanceId":"i-inert","UserData":{"Value":base64.b64encode(text.encode()).decode()}},"i-inert")
        keywords=any(word in text for word in ("pass","secret","token","key"))
        shape=bool(re.search(pattern,text,re.DOTALL))
        assert response["UserDataIndicators"]["KeywordMatch"]==keywords
        assert response["UserDataIndicators"]["PasswordShapeMatch"]==shape
        assert check.evaluate(response,{})[0]==("FAIL" if keywords or shape else "PASS")
    assert check.evaluate({"UserDataIndicators":{"collection_status":"denied"}},{})[0]=="UNKNOWN"
    assert check.evaluate({"UserDataIndicators":{"KeywordMatch":"false","PasswordShapeMatch":False}},{})[0]=="UNKNOWN"


def test_user_data_bad_encoding_and_dryrun_are_not_values_or_probes(monkeypatch):
    import pytest
    from peaso.collectors import aws
    with pytest.raises(aws.ReadFailure,match="malformed_user_data_encoding"):
        aws._project_user_data_indicators({"InstanceId":"i-inert","UserData":{"Value":"not-base64!"}},"i-inert")
    requests=aws.Requests({});monkeypatch.setattr(requests,"client",lambda *args:pytest.fail("probe reached SDKclient"))
    with pytest.raises(aws.ReadFailure,match="undeclared_instance_attribute_query"):
        requests.call(object(),"ec2","us-east-1","describe_instance_attribute",InstanceId="i-inert",Attribute="userData",DryRun=True)


def test_failed_user_data_projection_cache_exception_has_no_payload_traceback(monkeypatch):
    import pytest
    from peaso.collectors import aws
    class Client:
        def describe_instance_attribute(self,**kwargs):
            return {"InstanceId":"i-inert","UserData":{"Value":"INERT_SECRET_INVALID_ENCODING!"}}
    requests=aws.Requests({});monkeypatch.setattr(requests,"client",lambda *args:Client())
    with pytest.raises(aws.ReadFailure,match="malformed_user_data_encoding"):
        requests.call(object(),"ec2","us-east-1","describe_instance_attribute",InstanceId="i-inert",Attribute="userData")
    cached=next(iter(requests._cache.values())).exception()
    assert cached.__traceback__ is None and cached.__context__ is None and cached.__cause__ is None
    assert str(cached)=="malformed_user_data_encoding"
