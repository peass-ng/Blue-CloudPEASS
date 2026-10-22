"""Bound continuous-query authority to an eligible reservation and exact tables."""

from __future__ import annotations

from .gcp_bigquery_scheduled_query import (
    _known, _has, _ordinary_table, _permission_inventory_complete,
    _source_group_membership_complete,
)


def _plain_schema(model, resource):
    """Return a simple column signature usable by INSERT/APPENDS on both tables."""
    if not _ordinary_table(model, resource):
        return None
    item = model.bigquery_tables[resource]
    fields = (item.get("schema") or {}).get("fields") or []
    signature = []
    for field in fields:
        if not isinstance(field, dict) or field.get("fields"):
            return None
        name = field.get("name")
        kind = field.get("type")
        mode = field.get("mode") or "NULLABLE"
        if (not isinstance(name, str) or not name.isidentifier()
                or kind not in {"STRING", "BYTES", "INTEGER", "INT64", "FLOAT", "FLOAT64",
                                "NUMERIC", "BIGNUMERIC", "BOOLEAN", "BOOL", "DATE",
                                "TIME", "DATETIME", "TIMESTAMP", "GEOGRAPHY", "JSON"}
                or mode != "NULLABLE"):
            return None
        signature.append((name.lower(), kind))
    return tuple(signature) if signature else None


def _eligible_assignment(model, project, location, email):
    assignments = model.continuous_assignments.get((project, location.lower()), ())
    for assignment in assignments:
        principal = assignment["principal"]
        if principal not in (None, "", email, "serviceAccount:" + email):
            continue
        if (assignment["state"] == "ACTIVE"
                and assignment["reservation_status"] == "collected"
                and assignment["edition"] in ("ENTERPRISE", "ENTERPRISE_PLUS")):
            return True
    return False


def select(model, candidates, caller):
    if caller is None:
        return {}
    out = {}
    for tid, target in candidates.items():
        if not tid.startswith("gcp_verified_authority:bigquery_continuous_query:"):
            continue
        project = target.attrs.get("project") or target.scope
        email = target.attrs.get("email")
        sa = model.sas.get("serviceAccount:" + str(email or ""))
        if not isinstance(project, str) or sa is None or sa.attrs.get("disabled"):
            continue
        sa_resource = sa.attrs.get("resource")
        if not _has(model, caller, "iam.serviceAccounts.actAs", sa_resource):
            continue
        if not _known(model, caller, "iam.serviceAccounts.actAs", sa_resource):
            out[tid] = ("unknown", "continuous_query_actas_condition_unresolved")
            continue
        if _known(model, caller, "iam.serviceAccounts.getAccessToken", sa_resource):
            continue
        if _has(model, caller, "iam.serviceAccounts.getAccessToken", sa_resource):
            out[tid] = ("unknown", "continuous_query_existing_token_access_unresolved")
            continue
        if not _has(model, caller, "bigquery.jobs.create", project):
            continue
        if not _known(model, caller, "bigquery.jobs.create", project):
            out[tid] = ("unknown", "continuous_query_job_permission_unresolved")
            continue
        if not _permission_inventory_complete(model, project):
            out[tid] = ("unknown", "continuous_query_iam_inventory_incomplete")
            continue

        unresolved = model.continuous_assignment_status.get(project) not in ("collected", "empty")
        unresolved |= any(
            status not in ("collected", "empty")
            for kind in ("bigquery_dataset", "bigquery_table")
            for status in model.resource_inventory_status.get(kind, {}).values())
        destinations = []
        for table, item in model.bigquery_tables.items():
            if not table.startswith(project + "/datasets/"):
                continue
            dataset = table.rsplit("/tables/", 1)[0]
            metadata = model.bigquery_datasets.get(dataset) or {}
            location = metadata.get("location")
            if not isinstance(location, str) or not location:
                unresolved = True
                continue
            if not _eligible_assignment(model, project, location, email):
                if model.continuous_assignment_status.get(project) != "empty":
                    unresolved = True
                continue
            if (model.resource_policy_status.get("bigquery_dataset", {}).get(dataset) != "collected"
                    or model.resource_policy_status.get("bigquery_table", {}).get(table) != "collected"
                    or model.bigquery_row_policy_status.get(table) != "collected"
                    or model.bigquery_row_policies.get(table)):
                unresolved = True
                continue
            signature = _plain_schema(model, table)
            if signature is None:
                unresolved = True
                continue
            if not _known(model, sa, "bigquery.tables.updateData", table):
                if _has(model, sa, "bigquery.tables.updateData", table):
                    unresolved = True
                continue
            caller_write = _has(model, caller, "bigquery.tables.updateData", table)
            if caller_write and not _known(model, caller, "bigquery.tables.updateData", table):
                unresolved = True
            caller_read = _known(model, caller, "bigquery.tables.getData", table)
            destinations.append((table, location, signature, not caller_write, caller_read))

        for source, item in model.bigquery_tables.items():
            source_dataset = source.rsplit("/tables/", 1)[0]
            source_project = "/".join(source.split("/")[:2])
            metadata = model.bigquery_datasets.get(source_dataset) or {}
            signature = _plain_schema(model, source)
            if signature is None and any(
                    location.lower() == str(metadata.get("location", "")).lower()
                    for _, location, _, _, _ in destinations):
                unresolved = True
                continue
            routes = [(dest, new_write, caller_read) for dest, location, dest_signature,
                      new_write, caller_read in destinations
                      if location.lower() == str(metadata.get("location", "")).lower()
                      and signature == dest_signature and source != dest]
            if not routes:
                continue
            if (not _permission_inventory_complete(model, source_project)
                    or not _source_group_membership_complete(model, caller, source_project)
                    or model.resource_policy_status.get("bigquery_dataset", {}).get(source_dataset) != "collected"
                    or model.resource_policy_status.get("bigquery_table", {}).get(source) != "collected"
                    or model.bigquery_row_policy_status.get(source) != "collected"
                    or model.bigquery_row_policies.get(source)):
                unresolved = True
                continue
            if not _known(model, sa, "bigquery.tables.getData", source):
                if _has(model, sa, "bigquery.tables.getData", source):
                    unresolved = True
                continue
            caller_source_read = _has(model, caller, "bigquery.tables.getData", source)
            if caller_source_read and not _known(model, caller, "bigquery.tables.getData", source):
                unresolved = True
            if any(new_write for _, new_write, _ in routes):
                out[tid] = ("conditional", "continuous_query_exact_table_write_gain")
                break
            if not caller_source_read and any(caller_read for _, _, caller_read in routes):
                out[tid] = ("conditional", "continuous_query_exact_table_read_gain")
                break
        if tid not in out and unresolved:
            out[tid] = ("unknown", "continuous_query_reservation_or_table_evidence_incomplete")
    return out
