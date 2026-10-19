"""Signed narrow BigQuery public READER predicate over cached FULL ACL facts."""
from __future__ import annotations

from . import register, result, unknown
from .facts import Unavailable, full_representation, get, list_of_objects, omitted
from .fixtures import CASES


CHECK_ID = "gcp_pci_bigquery_dataset_a4e25dbf9640"


@register(CHECK_ID, "gcp", "exposure", "bigquery_dataset",
          "BigQuery dataset does not grant allUsers READER access",
          "medium", "AC-3",
          "Remove a reviewed allUsers READER dataset access entry and grant access only to approved principals.")
def no_anonymous_reader(item, index):
    name = get(item, "name", str)
    if not full_representation(item):
        raise Unavailable("BigQuery dataset ACL was not collected with FULL view")
    # A FULL datasets.get omits an empty access list. Other omitted or denied
    # fields are interpreted only after full-representation proof.
    access = omitted(item, "access", [], list)
    matches = []
    for row in list_of_objects(access):
        principal = row.get("specialGroup")
        member = row.get("iamMember")
        if principal is not None and not isinstance(principal, str):
            raise Unavailable("malformed dataset specialGroup")
        if member is not None and not isinstance(member, str):
            raise Unavailable("malformed dataset iamMember")
        if principal is not None and member is not None:
            raise Unavailable("conflicting dataset ACL principal selectors")
        # Native allUsers is a generic IAM member, not one of the documented
        # special groups. Retain specialGroup compatibility for old snapshots.
        principal = member if member is not None else principal
        if "role" not in row:
            # Authorized views, datasets, and routines have no ACL role.
            if principal is not None:
                return unknown("dataset specialGroup entry has no role", dataset=name)
            if any(field in row for field in ("view", "dataset", "routine")):
                continue
            raise Unavailable("unrecognized dataset ACL entry without role")
        role = get(row, "role", str)
        if role not in {"READER", "WRITER", "OWNER"} and not role.startswith("roles/"):
            return unknown("unrecognized BigQuery dataset ACL role", dataset=name, role=role)
        if principal == "allUsers" and role == "READER":
            matches.append({"special_group": "allUsers", "role": "READER"})
    return result(bool(matches), dataset=name, all_users_reader_entries=matches,
                  semantics="Exact signed allUsers READER pair; broader public ACLs are evaluated separately")


_dataset = {"name": "projects/pci-inert/datasets/sample",
    "_provenance": {"representation": "full"}}
CASES[CHECK_ID] = {"pass": {**_dataset, "access": [
        {"specialGroup": "allUsers", "role": "WRITER"}]},
    "fail": {**_dataset, "access": [
        {"specialGroup": "allUsers", "role": "READER"}]},
    "unknown": {**_dataset, "_coverage": {"access": {"status": "denied"}}}}
