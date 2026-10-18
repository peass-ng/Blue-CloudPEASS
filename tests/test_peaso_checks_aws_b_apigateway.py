"""REST/APIv2 stage source unions and conjunctions are not narrowed."""
from peaso.checks import CHECKS,aws_b_apigateway


def evaluator(cid):
    return next(check.evaluate for check in CHECKS if check.id == cid)


def test_cache_source_requires_enabled_caching_and_encryption():
    check=evaluator("aws.b.apigateway.wildcard_cache_encryption")
    base={"stageName":"prod","methodSettings":{"*/*":{"cachingEnabled":True,"cacheDataEncrypted":True}}}
    assert check(base,{})[0]=="PASS"
    base["methodSettings"]["*/*"]["cacheDataEncrypted"]=False
    assert check(base,{})[0]=="FAIL"
    assert check({"stageName":"prod","methodSettings":{}},{})[0]=="FAIL"
    assert check({"stageName":"prod","methodSettings":{"*/*":[]}},{})[0]=="UNKNOWN"


def test_execution_logging_covers_both_stage_families():
    rest=evaluator("aws.b.apigateway.rest_execution_logging")
    http=evaluator("aws.b.apigateway.http_execution_logging")
    assert rest({"stageName":"prod","methodSettings":{"*/*":{"loggingLevel":"ERROR"}}},{})[0]=="PASS"
    assert http({"StageName":"prod","DefaultRouteSettings":{"LoggingLevel":"INFO"}},{})[0]=="PASS"
    assert rest({"stageName":"prod","methodSettings":{}},{})[0]=="FAIL"
    assert http({"StageName":"prod","DefaultRouteSettings":{}},{})[0]=="FAIL"
    assert http({"StageName":"prod","DefaultRouteSettings":{"LoggingLevel":"FUTURE"}},{})[0]=="UNKNOWN"
