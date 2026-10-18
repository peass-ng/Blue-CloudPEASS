"""Inert registered snapshots: consumed MFA and GCP declaration fact authority."""
import copy
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot
MFA="aws.iam.console_mfa"
FIREWALL="gcp.compute.restrict_internet_ingress"
IP="gcp.compute.no_external_ip"
LOGIN={"LoginProfile":{"UserName":"alice"}}
PRIVATE={"allowed":[{"IPProtocol":"tcp"}],"sourceRanges":["10.0.0.0/8"]}

def deny(row,key):row.setdefault("_coverage",{})[key]={"status":"denied"}

def observed(cid,item):
    provider,kind={MFA:("aws","iam_user"),FIREWALL:("gcp","firewall"),IP:("gcp","instance")}[cid]
    snapshot=make_snapshot(provider,["*"],[{"type":kind,"scope":"*","status":"collected","items":[copy.deepcopy(item)]}],created_at="2026-10-17T00:00:00Z")
    before=copy.deepcopy(snapshot)
    rows=[f for f in evaluate_snapshot(snapshot,checks=[cid])["findings"] if f["check_id"]==cid]
    assert snapshot==before and len(rows)==1
    return rows[0]["status"]

def test_malformed_device_is_not_mfa_observation():
    for device in ({},None,{"SerialNumber":""},{"SerialNumber":23},{"SerialNumber":"mfa","collection_status":"denied"}):
        assert observed(MFA,{"LoginProfile":LOGIN,"MFADevices":[device]})=="UNKNOWN"

def test_denied_serial_and_absence_cannot_select_safe_result():
    device={"SerialNumber":"mfa"};deny(device,"SerialNumber")
    assert observed(MFA,{"LoginProfile":LOGIN,"MFADevices":[device]})=="UNKNOWN"
    login={"absent":True};deny(login,"absent")
    assert observed(MFA,{"LoginProfile":login,"MFADevices":[]})=="UNKNOWN"

def test_independent_device_and_console_absence_and_empty_devices():
    for devices in ([{}, {"SerialNumber":"mfa"}],[{"SerialNumber":"mfa"},{}]):
        assert observed(MFA,{"LoginProfile":LOGIN,"MFADevices":devices})=="PASS"
    assert observed(MFA,{"LoginProfile":LOGIN,"MFADevices":[]})=="FAIL"
    assert observed(MFA,{"LoginProfile":{"absent":True},"MFADevices":[]})=="NOT_APPLICABLE"

def test_firewall_denied_applicability_fields_are_unknown():
    for field in ("disabled","direction","denied"):
        row=copy.deepcopy(PRIVATE);row.update(disabled=False,direction="INGRESS",denied=[]);deny(row,field)
        assert observed(FIREWALL,row)=="UNKNOWN"

def test_firewall_denied_sources_and_protocol_are_unknown():
    for field in ("sourceRanges","sourceTags","sourceServiceAccounts"):
        row=copy.deepcopy(PRIVATE);deny(row,field)
        assert observed(FIREWALL,row)=="UNKNOWN"
    row=copy.deepcopy(PRIVATE);deny(row["allowed"][0],"IPProtocol")
    assert observed(FIREWALL,row)=="UNKNOWN"

def test_firewall_known_broad_source_and_valid_rule_survive_unknown_peers():
    assert observed(FIREWALL,{"allowed":[{}, {"IPProtocol":"tcp"}]})=="FAIL"
    for ranges in (["broken","::/0"],["0.0.0.0/0","broken"]):
        row={"sourceRanges":ranges,"allowed":[{}, {"IPProtocol":"tcp"}]};deny(row,"sourceTags")
        assert observed(FIREWALL,row)=="FAIL"

def test_firewall_omission_defaults_and_authoritative_inapplicability():
    assert observed(FIREWALL,{"allowed":[{"IPProtocol":"tcp"}]})=="FAIL"
    assert observed(FIREWALL,{"allowed":[{"IPProtocol":"tcp"}],"sourceTags":["internal"]})=="PASS"
    row={"disabled":True};deny(row,"direction")
    assert observed(FIREWALL,row)=="NOT_APPLICABLE"
    assert observed(FIREWALL,{"direction":"EGRESS"})=="NOT_APPLICABLE"
    assert observed(FIREWALL,{"denied":[{"IPProtocol":"tcp"}]})=="NOT_APPLICABLE"

def test_firewall_malformed_native_values_remain_unknown():
    for field,value in (("disabled",1),("direction","future"),("denied",True),("sourceTags",[1]),("sourceRanges",None)):
        row=copy.deepcopy(PRIVATE);row[field]=value
        assert observed(FIREWALL,row)=="UNKNOWN"
    for protocol in (None,True,6,"future",""):
        row=copy.deepcopy(PRIVATE);row["allowed"][0]["IPProtocol"]=protocol
        assert observed(FIREWALL,row)=="UNKNOWN"

def test_nic_denied_present_or_omitted_optional_arrays_are_unknown():
    for field in ("accessConfigs","ipv6AccessConfigs"):
        for present in (False,True):
            nic={}
            if present:nic[field]=[]
            deny(nic,field)
            assert observed(IP,{"networkInterfaces":[nic]})=="UNKNOWN"

def test_assigned_address_is_independent_negative_not_reachability():
    for key,field,address in (("natIP","accessConfigs","203.0.113.1"),("externalIpv6","ipv6AccessConfigs","2001:db8::1")):
        nic={field:[{key:address}]};deny(nic,"ipv6AccessConfigs" if field=="accessConfigs" else "accessConfigs")
        for nics in ([{},nic,None],[None,nic]):assert observed(IP,{"networkInterfaces":nics})=="FAIL"
        deny(nic[field][0],key)
        assert observed(IP,{"networkInterfaces":[nic]})=="UNKNOWN"

def test_nic_readable_omissions_and_malformed_values():
    for nics in ([],[{}],[{"accessConfigs":[],"ipv6AccessConfigs":[]}]):
        assert observed(IP,{"networkInterfaces":nics})=="PASS"
    for nics in ([None],[{"accessConfigs":None}],[{"accessConfigs":[{}]}]):
        assert observed(IP,{"networkInterfaces":nics})=="UNKNOWN"


def test_explicit_empty_sources_without_selector_cannot_certify_restriction():
    assert observed(FIREWALL,{"allowed":[{"IPProtocol":"tcp"}],"sourceRanges":[]})=="UNKNOWN"
    assert observed(FIREWALL,{"allowed":[{"IPProtocol":"tcp"}],"sourceRanges":[],"sourceTags":["internal"]})=="PASS"
    assert observed(FIREWALL,{"allowed":[{"IPProtocol":"tcp"}],"sourceRanges":[],"sourceServiceAccounts":["svc@example.iam.gserviceaccount.com"]})=="PASS"
    assert observed(FIREWALL,{"allowed":[{"IPProtocol":"tcp"}]})=="FAIL"
