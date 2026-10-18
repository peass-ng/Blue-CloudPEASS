"""Reviewed indirect GCP access gains through one created or authorized object.

These targets are bounded authority over one protected resource, not direct IAM
grants or credentials for the connection service account. The complete proof
must establish the exact source actions, intermediate object, protected
resource, and before/after result for the same named action.
"""
from __future__ import annotations

import hashlib
from datetime import datetime
from urllib.parse import urlsplit

from ..schema import expand_requires
from . import Node, inventory_status, items

COLLECTION = "gcp_bounded_access_gain_evidence"
MECHANISMS = frozenset({"biglake_connection_table", "bigquery_remote_function",
                        "bigquery_authorized_routine", "bigquery_authorized_view",
                        "bigquery_authorized_dataset"})
CONNECTION = frozenset({"biglake_connection_table", "bigquery_remote_function"})


def _exact(value):
    return (isinstance(value, str) and bool(value.strip()) and value == value.strip()
            and not any(char in value for char in ("*", "?", "\n", "\r", "\x00")))


def _instant(value):
    if not isinstance(value, str):
        raise ValueError("missing timestamp")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("naive timestamp")
    return parsed


def _resource(value, scope, *, external=False):
    if not _exact(value):
        return False
    if value.startswith("projects/"):
        return value == scope or value.startswith(scope + "/")
    if not external:
        return False
    if value.startswith("gs://"):
        return len(value.removeprefix("gs://").split("/")) >= 2
    try:
        url = urlsplit(value)
        return (url.scheme == "https" and bool(url.hostname) and bool(url.path)
                and not url.username and not url.password and not url.query
                and not url.fragment and url.port != 0)
    except ValueError:
        return False


def _child(resource, parent, kind):
    return (isinstance(resource, str) and resource.startswith(parent + "/" + kind + "/")
            and len(resource.removeprefix(parent + "/" + kind + "/").split("/")) == 1
            and bool(resource.removeprefix(parent + "/" + kind + "/")))


def _project_service(resource, scope):
    pieces = resource.removeprefix(scope + "/").split("/")
    return len(pieces) == 4 and pieces[0] == "locations" and pieces[2] == "services" and all(pieces)


def _project_connection(resource, scope):
    pieces = resource.removeprefix(scope + "/").split("/")
    return len(pieces) == 4 and pieces[0] == "locations" and pieces[2] == "connections" and all(pieces)


def _bigquery_object(resource, scope, kind):
    pieces = resource.removeprefix(scope + "/").split("/")
    return (len(pieces) == 4 and pieces[0] == "datasets" and pieces[2] == kind
            and all(pieces))


def _valid(record, scope, snapshot):
    if not isinstance(record, dict) or not scope.startswith("projects/"):
        return False
    fields = ("TechniqueId", "SourceId", "MutationAction", "MutationResource",
              "IntermediateResource", "ProtectedResource", "GainedAction", "EvidenceRef")
    if any(not _exact(record.get(key)) for key in fields):
        return False
    mechanism = record.get("Mechanism")
    if mechanism not in MECHANISMS or record.get("TargetScope") != scope:
        return False
    if not all(_resource(record[key], scope) for key in ("MutationResource", "IntermediateResource")):
        return False
    if not _child(record["MutationResource"], scope, "datasets"):
        return False
    if mechanism in CONNECTION and not record["IntermediateResource"].startswith(record["MutationResource"] + "/"):
        return False
    intermediate_kind = ("tables" if mechanism in ("biglake_connection_table", "bigquery_authorized_view",
                                                  "bigquery_authorized_dataset") else "routines")
    if mechanism in CONNECTION:
        if not _child(record["IntermediateResource"], record["MutationResource"], intermediate_kind):
            return False
    elif not _bigquery_object(record["IntermediateResource"], scope, intermediate_kind):
        return False
    if not _resource(record["ProtectedResource"], scope, external=True):
        return False
    if mechanism == "biglake_connection_table":
        if not record["ProtectedResource"].startswith("gs://"):
            return False
    elif mechanism == "bigquery_remote_function":
        if not _project_service(record["ProtectedResource"], scope):
            return False
    elif not ("/datasets/" in record["ProtectedResource"] and
              _child(record["ProtectedResource"], record["MutationResource"], "tables")):
        return False
    bindings = record.get("ActionResources")
    if (not isinstance(bindings, dict) or not bindings
            or any(not _exact(action) or not _resource(resource, scope)
                   for action, resource in bindings.items())):
        return False
    if bindings.get(record["MutationAction"]) != record["MutationResource"]:
        return False
    if bindings.get("bigquery.jobs.create") != scope:
        return False
    if mechanism in CONNECTION:
        if (not _resource(record.get("ConnectionResource"), scope)
                or not _project_connection(record["ConnectionResource"], scope)
                or not _exact(record.get("ConnectionPrincipalId"))
                or record.get("ConnectionBoundToIntermediate") is not True
                or record.get("ConnectionCanAccessProtectedResource") is not True):
            return False
        if (bindings.get("bigquery.connections.delegate") != record["ConnectionResource"]
                or (mechanism == "bigquery_remote_function"
                    and bindings.get("bigquery.connections.use") != record["ConnectionResource"])):
            return False
        read_action = ("bigquery.tables.get" if mechanism == "biglake_connection_table"
                       else "bigquery.routines.get")
        if bindings.get(read_action) != record["IntermediateResource"]:
            return False
        if mechanism == "biglake_connection_table" and bindings.get("bigquery.tables.getData") != record["IntermediateResource"]:
            return False
    elif (not _resource(record.get("AuthorizationEntryResource"), scope)
          or record["AuthorizationEntryResource"] != record["MutationResource"]
          or record.get("IntermediateExistingBeforeMutation") is not True):
        return False
    else:
        if mechanism == "bigquery_authorized_dataset":
            dataset = record.get("AuthorizedDatasetResource")
            if (not _resource(dataset, scope) or not _child(dataset, scope, "datasets")
                    or not _child(record["IntermediateResource"], dataset, "tables")
                    or record.get("AuthorizationEntryMatchesDataset") is not True
                    or record.get("AuthorizationTargetTypes") != ["VIEWS"]):
                return False
        elif record.get("AuthorizationEntryMatchesIntermediate") is not True:
            return False
        read_action = ("bigquery.routines.get" if mechanism == "bigquery_authorized_routine"
                       else "bigquery.tables.getData")
        if (bindings.get("bigquery.datasets.getIamPolicy") != record["MutationResource"]
                or bindings.get("bigquery.datasets.setIamPolicy") != record["MutationResource"]
                or bindings.get(read_action) != record["IntermediateResource"]):
            return False
    if not (record.get("BeforeTestedAction") == record["GainedAction"]
            == record.get("AfterTestedAction")
            and record.get("BeforeTestedResource") == record["ProtectedResource"]
            == record.get("AfterTestedResource")
            and record.get("AfterAccessPath") == record["IntermediateResource"]):
        return False
    try:
        captured = _instant(snapshot.get("created_at"))
        prior = _instant(record.get("PriorAccessCheckedAt"))
        mutation = _instant(record.get("MutationObservedAt"))
        after = _instant(record.get("AfterAccessCheckedAt"))
        observed = _instant(record.get("EvidenceObservedAt"))
        fresh = (prior < mutation <= after <= observed <= captured
                 and (captured - prior).total_seconds() <= 900)
    except (TypeError, ValueError, OverflowError):
        fresh = False
    return (fresh and record.get("Status") == "verified"
            and all(record.get(key) is True for key in (
                "PriorSourceAccessDenied", "MutationAccepted", "IntermediateUsable",
                "AfterIndirectActionAllowed")))


def _node_id(record):
    fields = ("TechniqueId", "SourceId", "IntermediateResource", "ProtectedResource")
    digest = hashlib.sha256("\x00".join(record[key] for key in fields).encode()).hexdigest()[:20]
    return f"gcp_verified_authority:bounded:{record['Mechanism']}:{digest}"


def load(model):
    status = inventory_status(model.snapshot, COLLECTION)
    grouped, poisoned = {}, set()
    for collection_scope, record in items(model.snapshot, COLLECTION):
        scope = model._norm_scope(collection_scope)
        if not isinstance(record, dict):
            continue
        technique, source = record.get("TechniqueId"), record.get("SourceId")
        if not _exact(technique) or not _exact(source):
            continue
        owner = (technique, source, scope)
        if not all(_exact(record.get(key)) for key in ("Mechanism", "IntermediateResource", "ProtectedResource")):
            poisoned.add(owner)
            continue
        key = (*owner, record["Mechanism"], record["IntermediateResource"], record["ProtectedResource"])
        grouped.setdefault(key, []).append((collection_scope, record))
    nodes, records = {}, {}
    for (technique, source, scope, _, _, _), matches in grouped.items():
        owner = (technique, source, scope)
        if owner in poisoned or len(matches) != 1 or status.get(matches[0][0]) != "collected":
            continue
        record = matches[0][1]
        if not _valid(record, scope, model.snapshot):
            poisoned.add(owner)
            continue
        ident = _node_id(record)
        for resource in record["ActionResources"].values():
            if resource != scope:
                model.parents.setdefault(resource, scope)
        nodes[ident] = Node(ident, "gcp_verified_authority", "gcp", scope,
                            f"{source} gains indirect {record['GainedAction']} on {record['ProtectedResource']} via {record['IntermediateResource']}",
                            attrs={"scope": scope, "resource": record["ProtectedResource"],
                                   "intermediate_resource": record["IntermediateResource"],
                                   "mechanism": record["Mechanism"], "source_id": source,
                                   "technique_id": technique}, entity=True)
        records[ident] = record
    for ident, record in list(records.items()):
        if (record["TechniqueId"], record["SourceId"], record["TargetScope"]) in poisoned:
            records.pop(ident)
            nodes.pop(ident)
    return nodes, records


def select(model, candidates, source):
    entry = model.current_entry or {}
    target = entry.get("target") or {}
    if source is None or target.get("outcome") != "bounded_authority":
        return {}
    required = [set(req["action"] for req in path if isinstance(req, dict) and isinstance(req.get("action"), str))
                for path in expand_requires(entry.get("requires") or {})]
    out = {}
    for ident, node in candidates.items():
        record = model.bounded_access_records.get(ident)
        if (record is None or record["TechniqueId"] != entry.get("id")
                or record["SourceId"] != source.id
                or target.get("grants") != [record["GainedAction"]]
                or record["Mechanism"] != (target.get("selector") or {}).get("gcp_bounded_mechanism")):
            continue
        bindings = record["ActionResources"]
        if not required or not any(actions and set(bindings) == actions for actions in required):
            continue
        if all((grant := model.check(source, {"action": action}, resource)) is not None
               and grant.confidence != "unknown" for action, resource in bindings.items()):
            out[ident] = ("conditional", "reviewed_bounded_access_gain")
    return out
