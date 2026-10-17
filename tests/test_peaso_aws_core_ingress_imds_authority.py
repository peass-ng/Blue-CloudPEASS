"""Selected EC2 metadata and ingress facts through registered inert snapshots."""
import copy
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot
IMDS="aws.ec2.imdsv2"
INGRESS="aws.ec2.restrict_internet_ingress"
PRIVATE={"IpProtocol":"tcp","IpRanges":[{"CidrIp":"10.0.0.0/8"}]}
PUBLIC={"IpProtocol":"tcp","IpRanges":[{"CidrIp":"0.0.0.0/0"}]}

def deny(row,field):row.setdefault("_coverage",{})[field]={"status":"denied"}

def observed(cid,item,status="collected"):
    snapshot=make_snapshot("aws",["*"],[{"type":"instance" if cid==IMDS else "security_group","scope":"*","status":status,"items":[copy.deepcopy(item)] if status=="collected" else []}],created_at="2026-10-17T00:00:00Z")
    before=copy.deepcopy(snapshot)
    rows=[f for f in evaluate_snapshot(snapshot,checks=[cid])["findings"] if f["check_id"]==cid]
    assert snapshot==before and len(rows)==1
    return rows[0]["status"]

def test_imds_selected_endpoint_and_token_denial_cannot_prove_compliance():
    for field in ("HttpEndpoint","HttpTokens"):
        options={"HttpEndpoint":"enabled","HttpTokens":"required"};deny(options,field)
        assert observed(IMDS,{"MetadataOptions":options})=="UNKNOWN"

def test_disabled_metadata_does_not_consume_unused_tokens():
    options={"HttpEndpoint":"disabled"};deny(options,"HttpTokens")
    assert observed(IMDS,{"MetadataOptions":options})=="PASS"

def test_imds_missing_or_malformed_enums_do_not_select_safe_default():
    for options in ({},{"HttpEndpoint":True},{"HttpEndpoint":"future"},{"HttpEndpoint":"enabled","HttpTokens":True},{"HttpEndpoint":"enabled","HttpTokens":"future"}):
        assert observed(IMDS,{"MetadataOptions":options})=="UNKNOWN"
    assert observed(IMDS,{"MetadataOptions":{"HttpEndpoint":"enabled","HttpTokens":"optional"}})=="FAIL"

def test_ingress_protocol_denial_cannot_prove_safe_rules():
    rule=copy.deepcopy(PRIVATE);deny(rule,"IpProtocol")
    assert observed(INGRESS,{"IpPermissions":[rule]})=="UNKNOWN"

def test_present_or_omitted_range_denial_cannot_become_empty():
    for field in ("IpRanges","Ipv6Ranges"):
        for present in (False,True):
            rule={"IpProtocol":"tcp"}
            if present:rule[field]=[]
            deny(rule,field)
            assert observed(INGRESS,{"IpPermissions":[rule]})=="UNKNOWN"

def test_denied_nested_cidr_cannot_prove_safe_or_unsafe():
    for key,family,cidr in (("CidrIp","IpRanges","0.0.0.0/0"),("CidrIpv6","Ipv6Ranges","::/0")):
        source={key:cidr};deny(source,key)
        assert observed(INGRESS,{"IpPermissions":[{"IpProtocol":"tcp",family:[source]}]})=="UNKNOWN"

def test_independent_known_broad_rule_or_family_retains_failure():
    bad=copy.deepcopy(PRIVATE);deny(bad,"IpProtocol")
    for rules in ([bad,PUBLIC],[PUBLIC,bad]):assert observed(INGRESS,{"IpPermissions":rules})=="FAIL"
    rule={"IpProtocol":"tcp","Ipv6Ranges":[{"CidrIpv6":"::/0"}]};deny(rule,"IpRanges")
    assert observed(INGRESS,{"IpPermissions":[rule]})=="FAIL"

def test_native_protocol_names_and_numbers_and_malformed_values():
    for protocol in ("tcp","TCP","udp","icmp","icmpv6","-1","6","0006","58","255"):
        rule=copy.deepcopy(PRIVATE);rule["IpProtocol"]=protocol
        assert observed(INGRESS,{"IpPermissions":[rule]})=="PASS"
    for protocol in (None,True,6,"future","256","-2"):
        rule=copy.deepcopy(PRIVATE);rule["IpProtocol"]=protocol
        assert observed(INGRESS,{"IpPermissions":[rule]})=="UNKNOWN"

def test_documented_optional_range_omissions_and_complete_empty_rules_remain_safe():
    for rules in ([],[{"IpProtocol":"tcp"}],[PRIVATE]):assert observed(INGRESS,{"IpPermissions":rules})=="PASS"

def test_malformed_cidr_or_wrong_address_family_and_collection_denial():
    for source in ({"CidrIp":"invalid"},{"CidrIp":"::/0"}):
        assert observed(INGRESS,{"IpPermissions":[{"IpProtocol":"tcp","IpRanges":[source]}]})=="UNKNOWN"
    assert observed(IMDS,{},status="denied")=="DENIED"
    assert observed(INGRESS,{},status="denied")=="DENIED"
