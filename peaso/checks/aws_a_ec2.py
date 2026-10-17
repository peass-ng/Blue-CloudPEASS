"""IAM instance-profile ARN source predicate with explicit native omission proof."""
from . import register, result, unknown
from .facts import get
from .fixtures import CASES
from .aws_a_facts import api_optional

NATIVE_IDS=["aws.a.ec2.instance_profile_arn"]
PROOF={"operation":"ec2:DescribeInstances","native_response_complete":True}


@register(NATIVE_IDS[0],"aws","least_privilege","instance","EC2 instance declares an IAM instance-profile ARN",
    "medium","AC-6","Review the declared instance-profile ARN and its separate IAM role permissions.")
def profile_arn(item,index):
    profile=api_optional(item,"IamInstanceProfile",dict,None,operation="ec2:DescribeInstances")
    if profile is None:
        return result(True,instance_profile_arn_present=False)
    arn=get(profile,"Arn",str)
    parts=arn.split(":",5)
    if len(parts)!=6 or parts[2]!="iam" or len(parts[4])!=12 or not parts[4].isdigit() or not parts[5].startswith("instance-profile/"):
        return unknown("malformed instance-profile ARN")
    return result(False,instance_profile_arn_present=True,semantics="Exact declared ARN presence; no role effectiveness or credential execution")
CASES[NATIVE_IDS[0]]={"pass":{"IamInstanceProfile":{"Arn":"arn:aws:iam::123456789012:instance-profile/inert"}},
    "fail":{"_provenance":PROOF},"missing":{},"malformed":None}


@register("aws.a.ec2.user_data_source_indicators","aws","hardening","instance","EC2 user data has no source-defined potential secret indicators",
    "medium","IA-5","Review potential indicators securely; the source's substring/password-shape heuristic does not prove actual credential presence or absence.")
def user_data_indicators(item,index):
    keywords=get(item,"UserDataIndicators.KeywordMatch",bool)
    shape=get(item,"UserDataIndicators.PasswordShapeMatch",bool)
    return result(keywords or shape,keyword_indicator=keywords,password_shape_indicator=shape,
        semantics="Source heuristic metadata only; no values/scripts retained or executed, no credential validation")
CASES["aws.a.ec2.user_data_source_indicators"]={"pass":{"UserDataIndicators":{"KeywordMatch":False,"PasswordShapeMatch":False}},
    "fail":{"UserDataIndicators":{"KeywordMatch":True,"PasswordShapeMatch":False}},"missing":{},"malformed":None}
NATIVE_IDS.append("aws.a.ec2.user_data_source_indicators")
