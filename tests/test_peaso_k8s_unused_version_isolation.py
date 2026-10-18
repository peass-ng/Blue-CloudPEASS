"""Version authority applies only to version-bounded component declarations."""
import copy
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot

ORDINARY = "k8s.ports.pod.container_argument_kube_scheduler_profiling_disabled"
LEGACY = "k8s.ports.pod.container_argument_pod_security_policy_enabled"
SECURITY_DENY = "k8s.ports.pod.container_argument_security_context_deny_enabled"

def observed(cid=ORDINARY, *, value="false", version="v1.24.0", version_coverage=None, flag_denied=False, complete=True):
    legacy = cid != ORDINARY
    flag = "enable-admission-plugins" if legacy else "profiling"
    config = {"component":"kube-apiserver" if legacy else "kube-scheduler", "flags_complete":complete,
              "flags":{flag:value}}
    if version is not None:
        config["version"] = version
    if version_coverage is not None:
        config["_coverage"]={"version":version_coverage}
    if flag_denied:
        config["flags"]["_coverage"]={flag:{"status":"denied"}}
    component=config["component"]
    pod={"metadata":{"name":"component","namespace":"kube-system","labels":{"component":component}},
         "spec":{"containers":[{"name":component,"_component_config":config}]}}
    snapshot=make_snapshot("k8s",["*"],[{"type":"pod","scope":"*","status":"collected","items":[pod]}],created_at="2026-10-17T00:00:00Z")
    before=copy.deepcopy(snapshot)
    rows=[f for f in evaluate_snapshot(snapshot,checks=[cid])["findings"] if f["check_id"]==cid]
    assert snapshot==before and len(rows)==1
    return rows[0]["status"]

def test_nonlegacy_safe_flag_does_not_consume_denied_version():
    assert observed(version_coverage={"status":"denied"})=="PASS"

def test_nonlegacy_unsafe_flag_does_not_consume_denied_version():
    assert observed(value="true",version_coverage={"status":"denied"})=="FAIL"

def test_nonlegacy_declaration_ignores_missing_or_malformed_unused_version():
    for version,coverage in ((None,None),(42,None),("not-a-version",None),("v1.24.0","malformed")):
        assert observed(version=version,version_coverage=coverage)=="PASS"

def test_relevant_flag_denial_or_incomplete_projection_stays_unknown():
    assert observed(flag_denied=True,version_coverage={"status":"denied"})=="UNKNOWN"
    assert observed(complete=False,version_coverage={"status":"denied"})=="UNKNOWN"

def test_legacy_plugins_still_consume_version_authority():
    for cid,value in ((LEGACY,"PodSecurityPolicy"),(SECURITY_DENY,"SecurityContextDeny")):
        assert observed(cid,value=value,version_coverage={"status":"denied"})=="UNKNOWN"
        assert observed(cid,value=value,version=None)=="UNKNOWN"

def test_legacy_version_boundary_remains_applicable():
    assert observed(LEGACY,value="PodSecurityPolicy",version="v1.24.0")=="PASS"
    assert observed(LEGACY,value="PodSecurityPolicy",version="v1.25.0")=="NOT_APPLICABLE"
