"""Separate analyzer inventory presence and active-state regional predicates."""
from . import register, result, unknown
from .facts import get
from .fixtures import CASES
from .aws_a_facts import complete_items, scope_subject, scope_fixture

NATIVE_IDS = []
SUBJECT = {"scope": "123456789012/us-east-1"}


@register("aws.a.accessanalyzer.region_present", "aws", "hardening", "access_analyzer", "Enabled AWS region has a declared IAM Access Analyzer",
    "medium", "AC-6", "Review analyzer configuration and its separate active state.", target="scope", dependencies=["access_analyzer"])
def presence(item, index):
    rows = complete_items(index, "access_analyzer", scope_subject(item))
    for row in rows:
        get(row, "arn", str)
    return result(not bool(rows), analyzer_count=len(rows), semantics="Exact source declared-inventory presence; active status is a different predicate")
CASES["aws.a.accessanalyzer.region_present"] = {"pass": SUBJECT, "fail": SUBJECT, "missing": {}, "malformed": None,
    "index": scope_fixture("access_analyzer", [{"arn": "arn:aws:access-analyzer:us-east-1:123456789012:analyzer/inert"}]), "fail_index": scope_fixture("access_analyzer", [])}
NATIVE_IDS.append("aws.a.accessanalyzer.region_present")


@register("aws.a.accessanalyzer.region_active", "aws", "hardening", "access_analyzer", "All declared regional Access Analyzers are active",
    "medium", "AC-6", "Review absent or inactive analyzers without creating a service or resource during collection.", target="scope", dependencies=["access_analyzer"])
def active(item, index):
    rows = complete_items(index, "access_analyzer", scope_subject(item))
    statuses = [get(row, "status", str) for row in rows]
    if any(state not in {"ACTIVE", "CREATING", "DISABLED", "FAILED"} for state in statuses):
        return unknown("unrecognized Access Analyzer native status")
    return result(not statuses or any(state != "ACTIVE" for state in statuses), analyzer_statuses=statuses,
        semantics="Aggregate of source per-analyzer outcomes; complete empty region is source synthetic absence FAIL")
CASES["aws.a.accessanalyzer.region_active"] = {"pass": SUBJECT, "fail": SUBJECT, "missing": {}, "malformed": None,
    "index": scope_fixture("access_analyzer", [{"status": "ACTIVE"}]), "fail_index": scope_fixture("access_analyzer", [])}
NATIVE_IDS.append("aws.a.accessanalyzer.region_active")
