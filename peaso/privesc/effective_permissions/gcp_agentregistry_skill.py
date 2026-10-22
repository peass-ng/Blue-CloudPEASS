"""Exact, reviewed Agent Registry Skill execution paths.

Agent Registry and Agent Platform Skill Registry have similarly named resources.
Only a record tying the changed Agent Registry Skill to a real consumer and a
newly successful bounded action can establish this path.
"""
from __future__ import annotations

import hashlib
import re
from datetime import datetime
from urllib.parse import urlsplit

from . import Node, inventory_status, items


TECHNIQUE = "gcp-agentregistry-skill-default-revision-replace"
COLLECTION = "gcp_agentregistry_skill_evidence"
SKILL = re.compile(r"projects/[^/]+/locations/[^/]+/skills/[^/]+")
PERMISSION = re.compile(r"[a-z][a-z0-9.]*\.[A-Za-z][A-Za-z0-9]*")


def _exact(value):
    return (isinstance(value, str) and value == value.strip() and bool(value)
            and not any(char in value for char in ("*", "?", "\n", "\r", "\x00")))


def _instant(value):
    if not isinstance(value, str):
        raise ValueError("missing timestamp")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("naive timestamp")
    return parsed


def _resource(value):
    if not _exact(value):
        return False
    if value.startswith(("projects/", "organizations/", "folders/")):
        return len(value.split("/")) >= 2 and all(value.split("/"))
    if value.startswith("gs://"):
        return bool(re.fullmatch(r"gs://[^/]+/.+", value))
    try:
        url = urlsplit(value)
        return (url.scheme == "https" and bool(url.hostname) and bool(url.path)
                and not url.username and not url.password and not url.query
                and not url.fragment and url.port != 0)
    except ValueError:
        return False


def _consumer_resource(value):
    return (_resource(value) and not value.startswith("gs://")
            and (value.startswith("https://") or
                 (value.startswith("projects/") and len(value.split("/")) >= 6)))


def _valid(record, scope, snapshot):
    if not isinstance(record, dict):
        return False
    fields = ("TechniqueId", "SourceId", "SkillResource", "QuotaProject",
              "ConsumerResource", "ConsumerRuntimePrincipal", "ConsumerSkillSource",
              "DefaultRevisionBefore", "DefaultRevisionAfter", "ReplacementRevision",
              "ConsumerResolvedRevision", "PriorTestedPermission", "PriorTestedResource",
              "DownstreamPermission", "DownstreamResource", "ObservedRuntimePrincipal",
              "ObservedPermission", "ObservedResource", "EvidenceRef", "MutationMode")
    if any(not _exact(record.get(field)) for field in fields):
        return False
    skill = record["SkillResource"]
    if (record["TechniqueId"] != TECHNIQUE or record.get("TargetScope") != scope
            or not SKILL.fullmatch(skill) or not skill.startswith(scope + "/")
            or "/skills/private-" not in skill
            or not re.fullmatch(r"projects/[^/]+", record["QuotaProject"])
            or not _consumer_resource(record["ConsumerResource"])
            or not _resource(record["DownstreamResource"])
            or record.get("ConsumerRegistry") != "agent_registry"
            or record.get("ConsumerMountMode") != "logical_skill"
            or record["ConsumerSkillSource"] != skill
            or record["SourceId"] == record["ConsumerRuntimePrincipal"]
            or record["ObservedRuntimePrincipal"] != record["ConsumerRuntimePrincipal"]
            or not PERMISSION.fullmatch(record["DownstreamPermission"])
            or record["ObservedPermission"] != record["DownstreamPermission"]
            or record["ObservedResource"] != record["DownstreamResource"]
            or record["PriorTestedPermission"] != record["DownstreamPermission"]
            or record["PriorTestedResource"] != record["DownstreamResource"]
            or record["DefaultRevisionBefore"] == record["DefaultRevisionAfter"]
            or not record["DefaultRevisionBefore"].startswith(skill + "/revisions/")
            or record["DefaultRevisionAfter"] != record["ReplacementRevision"]
            or record["ConsumerResolvedRevision"] != record["ReplacementRevision"]
            or not record["ReplacementRevision"].startswith(skill + "/revisions/")
            or record["MutationMode"] not in ("create_auto_active", "explicit_update")
            or record.get("Status") != "verified"):
        return False
    if any(record.get(field) is not True for field in (
            "ExistingCustomSkill", "RevisionCreated", "RevisionPayloadValidated",
            "ReplacementRevisionActive", "ConsumerResolvedDefaultRevision",
            "ConsumerPayloadLoaded", "PayloadActionSucceeded", "PriorSourceAccessDenied")):
        return False
    if record["MutationMode"] == "explicit_update" and record.get("DefaultPointerUpdated") is not True:
        return False
    if record["MutationMode"] == "create_auto_active" and record.get("DefaultPointerUpdated") is not False:
        return False
    try:
        prior = _instant(record.get("PriorAccessCheckedAt"))
        created = _instant(record.get("RevisionCreatedAt"))
        updated = (_instant(record.get("DefaultPointerUpdatedAt"))
                   if record["MutationMode"] == "explicit_update" else created)
        resolved = _instant(record.get("ConsumerResolvedAt"))
        acted = _instant(record.get("DownstreamActionObservedAt"))
        observed = _instant(record.get("EvidenceObservedAt"))
        captured = _instant(snapshot.get("created_at"))
        return (prior < created <= updated <= resolved <= acted <= observed <= captured
                and (captured - prior).total_seconds() <= 900)
    except (TypeError, ValueError, OverflowError):
        return False


def load(model):
    status = inventory_status(model.snapshot, COLLECTION)
    grouped = {}
    for collection_scope, record in items(model.snapshot, COLLECTION):
        scope = model._norm_scope(collection_scope)
        if not isinstance(record, dict) or record.get("TechniqueId") != TECHNIQUE:
            continue
        key = tuple(record.get(name) for name in (
            "TechniqueId", "SourceId", "SkillResource", "ConsumerResource",
            "DownstreamPermission", "DownstreamResource"))
        if not all(_exact(value) for value in key):
            continue
        grouped.setdefault((scope, key), []).append((collection_scope, record))
    nodes, records = {}, {}
    for (scope, key), matches in grouped.items():
        if len(matches) != 1 or status.get(matches[0][0]) != "collected":
            continue
        record = matches[0][1]
        if not _valid(record, scope, model.snapshot):
            continue
        model.parents.setdefault(record["SkillResource"], scope)
        digest = hashlib.sha256("\x00".join(key).encode()).hexdigest()[:20]
        ident = f"gcp_verified_authority:agentregistry_skill:{digest}"
        nodes[ident] = Node(ident, "gcp_verified_authority", "gcp", scope,
                            f"{record['DownstreamPermission']} on {record['DownstreamResource']} through {record['ConsumerResource']}",
                            attrs={"scope": scope, "resource": record["DownstreamResource"],
                                   "artifact_arn": record["SkillResource"],
                                   "quota_project": record["QuotaProject"],
                                   "runtime_principal": record["ConsumerRuntimePrincipal"],
                                   "permission": record["DownstreamPermission"]}, entity=True)
        records[ident] = record
    return nodes, records


def select(model, candidates, source):
    if source is None:
        return {}
    out = {}
    for ident, node in candidates.items():
        record = model.agentregistry_skill_records.get(ident)
        if record is None or record["SourceId"] != source.id:
            continue
        skill = record["SkillResource"]
        required = ["agentregistry.skillRevisions.create", "serviceusage.services.use"]
        if record["MutationMode"] == "explicit_update":
            required.append("agentregistry.skills.update")
        if all((grant := model.check(source, {"action": action},
                                     record["QuotaProject"] if action == "serviceusage.services.use" else skill))
               is not None and grant.confidence != "unknown" for action in required):
            out[ident] = ("conditional", "exact_skill_consumer_and_bounded_action")
    return out
