"""Private APIM native candidates. No cloud access; import is inert until install()."""
from __future__ import annotations

import math
import re
from peaso.checks import register, result, unknown
from peaso.checks.facts import Unavailable, complete_items, get, list_of_objects, memoized

PROTOCOL_ID = "azure_api_management_1_2_8_1_ba319cf"
INSIGHTS_ID = "azure_api_management_appinsights_ensure_is_configured_42aac6a"
PROTOCOL_DIGEST = "0d01a758e49f3c58bbb3c169ba87576979a3bfe01c97bc33859ee849b8d45f78"
INSIGHTS_DIGEST = "72f20de1ae592d55056bf3f1347732729526985d8072f8d41faeab33d5798ba1"
SERVICE = re.compile(r"/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.apimanagement/service/[^/]+", re.I)
COMPONENT = re.compile(r"/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.insights/components/[^/]+", re.I)


def _bound_child(row, parent, segment):
    rid = get(row, "id", str).casefold()
    prefix = parent.casefold() + "/" + segment.casefold() + "/"
    if not rid.startswith(prefix) or not rid[len(prefix):] or "/" in rid[len(prefix):] or "?" in rid or "#" in rid:
        raise Unavailable("malformed or foreign APIM child identity")
    return rid


def _facts(index):
    def build():
        rows = complete_items(index, "apim_native")
        found = {}
        context = get(index, "context", dict)
        scope = get(context, "scope", str).casefold()
        if get(context, "provider", str) != "azure" or not re.fullmatch(r"/subscriptions/[^/]+", scope):
            raise Unavailable("Azure subscription scope unavailable")
        envs = get(index, "collections", dict).get("apim_native")
        if not isinstance(envs, list) or len(envs) != 1 or envs[0].get("scope", "").casefold() != scope or envs[0].get("items") != rows:
            raise Unavailable("APIM fact envelope not bound to subscription")
        for row in rows:
            rid = get(row, "id", str).casefold()
            if not SERVICE.fullmatch(rid) or not rid.startswith(scope + "/") or get(row, "parent_id", str).casefold() != rid or rid in found:
                raise Unavailable("APIM fact parent identity malformed or duplicated")
            found[rid] = row
        return found
    return memoized(index, ("apim_native", "facts"), build)


def _fact(item, index):
    rid = get(item, "id", str).casefold()
    if not SERVICE.fullmatch(rid):
        raise Unavailable("APIM target identity malformed")
    parents = memoized(index, ("apim_native", "parents"), lambda: {get(row, "id", str).casefold(): row for row in complete_items(index, "api_management")})
    if parents.get(rid) != item:
        raise Unavailable("APIM target not bound to parent inventory")
    fact = _facts(index).get(rid)
    if fact is None:
        raise Unavailable("APIM child facts missing for parent")
    return rid, fact


def _children(parent, field, segment):
    coverage = get(parent, "_coverage", dict).get(field)
    if not isinstance(coverage, dict) or coverage.get("status") not in ("collected", "empty"):
        raise Unavailable("APIM child coverage incomplete: " + field)
    rows = list_of_objects(get(parent, field, list))
    seen = set()
    for row in rows:
        rid = _bound_child(row, get(parent, "id", str), segment)
        if rid in seen:
            raise Unavailable("duplicate APIM child identity")
        seen.add(rid)
    if coverage["status"] == "empty" and rows:
        raise Unavailable("empty APIM child inventory contains rows")
    return rows


def _apis(fact):
    rows = _children(fact, "apis", "apis")
    if get(fact, "_coverage", dict).get("revisions", {}).get("status") != "collected":
        raise Unavailable("APIM revision inventory incomplete")
    online = get(fact, "online_api_ids", list)
    if any(not isinstance(value, str) for value in online) or len({v.casefold() for v in online}) != len(online):
        raise Unavailable("APIM online revision identities malformed")
    by_id = {get(row, "id", str).casefold(): row for row in rows}
    if not set(v.casefold() for v in online) <= by_id.keys():
        raise Unavailable("APIM online revision missing from API details")
    return [by_id[value.casefold()] for value in online]


def _policy(index, cid, service_id):
    context = get(index, "context", dict)
    policy = get(context, "policy_inputs", dict)
    if get(policy, "status", str) != "collected" or get(policy, "scope", str).casefold() != get(context, "scope", str).casefold():
        raise Unavailable("operator policy not bound to snapshot scope")
    row = get(policy, cid, dict)
    if get(row, "service_id", str).casefold() != service_id:
        raise Unavailable("operator policy not bound to APIM service")
    return row


def evaluate_protocol(item, index):
    """Correct offline predicate; intentionally not registered until policy producer exists."""
    try:
        service_id, fact = _fact(item, index)
        apis = _apis(fact)
        if not apis:
            return "NOT_APPLICABLE", {"reason": "complete APIM API/revision inventory empty"}
        policy = _policy(index, PROTOCOL_ID, service_id)
        expected = get(policy, "expected_by_api", dict)
        forbidden = get(policy, "forbidden_by_api", dict)
        actual_ids = {get(api, "id", str).casefold() for api in apis}
        if {x.casefold() for x in expected} != actual_ids or {x.casefold() for x in forbidden} != actual_ids:
            raise Unavailable("operator protocol rule missing or foreign API")
        mismatch = []
        for api in apis:
            aid = get(api, "id", str)
            rule = expected.get(aid)
            blocked = forbidden.get(aid)
            if rule not in ("http", "https", "ws", "wss") or not isinstance(blocked, list) or any(v not in ("http", "https", "ws", "wss") for v in blocked):
                raise Unavailable("unsupported or malformed endpoint protocol policy")
            protocols = get(api, "properties.protocols", list)
            if not protocols or any(v not in ("http", "https", "ws", "wss") for v in protocols):
                raise Unavailable("missing or unrecognized API protocol")
            if rule not in protocols or any(v in blocked for v in protocols):
                mismatch.append(aid)
        return result(bool(mismatch), mismatch_api_ids=mismatch, rule_scope="explicit snapshot policy")
    except Unavailable as exc:
        return unknown(str(exc))


def _component_index(index):
    def build():
        return {get(row, "id", str).casefold(): row for row in complete_items(index, "application_insights")}
    return memoized(index, ("apim_native", "components"), build)


def _positive_sampling(diagnostic):
    props = get(diagnostic, "properties", dict)
    sampling = get(props, "sampling", dict)
    if get(sampling, "samplingType", str) != "fixed":
        raise Unavailable("APIM sampling type or default unresolved")
    percentage = get(sampling, "percentage")
    if type(percentage) not in (float, int) or not math.isfinite(percentage) or not 0 <= percentage <= 100:
        raise Unavailable("APIM sampling percentage malformed")
    return percentage > 0


def _effective_diagnostics(service_diags, api_diags):
    """A child diagnostic shadows only its same-named service diagnostic."""
    merged = {get(row, "id", str).rsplit("/", 1)[-1].casefold(): row for row in service_diags}
    for row in api_diags:
        merged[get(row, "id", str).rsplit("/", 1)[-1].casefold()] = row
    return list(merged.values())


def evaluate_appinsights(item, index):
    """Configured APIM→Application Insights path, never a telemetry-delivery claim."""
    try:
        service_id, fact = _fact(item, index)
        apis = _apis(fact)
        if not apis:
            return "NOT_APPLICABLE", {"reason": "complete APIM API/revision inventory has no online API"}
        loggers = {get(r, "id", str).casefold(): r for r in _children(fact, "loggers", "loggers")}
        service_diags = _children(fact, "diagnostics", "diagnostics")
        components = _component_index(index)
        context_scope = get(get(index, "context", dict), "scope", str).casefold()
        unresolved = []
        failed = []
        for api in apis:
            aid = get(api, "id", str)
            api_diags = _children(api, "diagnostics", "diagnostics")
            # A same-name API diagnostic replaces its service-level definition.
            candidates = _effective_diagnostics(service_diags, api_diags)
            if not candidates:
                failed.append(aid)
                continue
            states = []
            api_diagnostic_ids = {get(d, "id", str).casefold() for d in api_diags}
            qualifying_ids = []
            for diagnostic in candidates:
                props = get(diagnostic, "properties", dict)
                logger_id = get(props, "loggerId", str).casefold()
                if not logger_id.startswith(service_id + "/loggers/") or "/" in logger_id[len(service_id + "/loggers/"):]:
                    raise Unavailable("foreign APIM logger reference")
                logger = loggers.get(logger_id)
                if logger is None:
                    states.append("FAIL")
                    continue
                if get(logger, "properties.loggerType", str) != "applicationInsights":
                    states.append("FAIL")
                    continue
                component_id = get(logger, "properties.resourceId", str).casefold()
                if not COMPONENT.fullmatch(component_id):
                    raise Unavailable("Application Insights logger target malformed")
                if not component_id.startswith(context_scope + "/"):
                    raise Unavailable("cross-subscription Application Insights target not inventoried")
                if component_id not in components:
                    states.append("FAIL")
                    continue
                if _positive_sampling(diagnostic):
                    states.append("PASS")
                    qualifying_ids.append(get(diagnostic, "id", str).casefold())
                else:
                    states.append("FAIL")
            if "PASS" in states:
                if api_diags and not any(rid in api_diagnostic_ids for rid in qualifying_ids):
                    raise Unavailable("cross-kind API/service logger routing requires evidence")
                continue
            if "UNKNOWN" in states:
                unresolved.append(aid)
            else:
                failed.append(aid)
        if unresolved:
            return unknown("effective APIM diagnostic unresolved", unresolved_api_ids=unresolved)
        return result(bool(failed), missing_tracing_api_ids=failed,
                      semantics="configured APIM Application Insights path only; telemetry delivery not measured")
    except Unavailable as exc:
        return unknown(str(exc))



def install():
    """Root integrator may call once after copying this reviewed module."""
    evaluate_appinsights.proposed_spec_sha256 = INSIGHTS_DIGEST
    register(INSIGHTS_ID, "azure", "hardening", "api_management",
             "Azure API Management (APIM) services have Azure Monitor Application Insights (AI) tracing enabled", "medium", "CM-6",
             "source_bound_pending_review", dependencies=["api_management", "apim_native", "application_insights"])(evaluate_appinsights)
