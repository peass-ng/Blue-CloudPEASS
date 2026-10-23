"""Reviewed Azure control-plane pivots into exact adjacent-plane principals.

An ARM permission, a returned secret, or a successful command is not enough to
name a new principal. The optional evidence collection must prove one exact
subject and a newly authorized action after the credential or grant was used.
"""
from __future__ import annotations

import hashlib
import re
from datetime import datetime
from urllib.parse import urlsplit

from . import Node, inventory_status, items

COLLECTION = "azure_external_principal_evidence"
CONTRACT = {
    "azure-avs-list-vcenter-cloudadmin-external-principal":
        ("microsoft.avs/privateclouds/listadmincredentials/action", "vmware_vcenter", "credential"),
    "azure-avs-list-nsxt-admin-external-principal":
        ("microsoft.avs/privateclouds/listadmincredentials/action", "vmware_nsx", "credential"),
    "azure-avs-run-command-vcenter-grant-external-principal":
        ("microsoft.avs/privateclouds/scriptexecutions/write", "vmware_vcenter", "identity_grant"),
    "azure-apim-developer-portal-sso-external-principal":
        ("microsoft.apimanagement/service/users/generatessourl/action", "apim_developer_portal", "credential"),
    "azure-apim-developer-portal-shared-token-external-principal":
        ("microsoft.apimanagement/service/users/token/action", "apim_developer_portal", "credential"),
    "azure-datafactory-github-oauth-external-principal":
        ("microsoft.datafactory/factories/getgithubaccesstoken/action", "github_repository", "credential"),
    "azure-eventgrid-mqtt-client-grant-external-principal":
        ("microsoft.eventgrid/namespaces/permissionbindings/write", "eventgrid_mqtt", "identity_grant"),
    "azure-arc-resource-bridge-credential-export":
        (("microsoft.resourceconnector/appliances/listkeys/action",
          "microsoft.resourceconnector/appliances/listclusterusercredential/action"),
         "arc_bridge_appliance", "credential"),
}


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


def _valid(record, scope, snapshot):
    if not isinstance(record, dict) or not scope.startswith("/subscriptions/"):
        return False
    contract = CONTRACT.get(record.get("TechniqueId"))
    allowed_actions = (contract[0] if isinstance(contract[0], tuple) else (contract[0],)) if contract else ()
    if (contract is None or record.get("AccessPermission", "").casefold() not in allowed_actions
            or (record.get("TargetPlane"), record.get("AccessArtifactKind")) != contract[1:]):
        return False
    fields = ("TechniqueId", "SourceId", "ActionResource", "AccessPermission",
              "TargetPlane", "TargetServiceResource", "TargetPrincipalId",
              "AccessArtifactRef", "GainedPermission", "EvidenceRef",
              "TargetServiceBindingEvidenceRef", "TargetSubjectBindingEvidenceRef",
              "PriorTestedPermission", "AfterTestedPermission",
              "PriorTestedResource", "AfterTestedResource")
    if any(not _exact(record.get(field)) for field in fields):
        return False
    if record.get("TargetScope", "").casefold() != scope.casefold():
        return False
    action_resource = record["ActionResource"].casefold()
    if action_resource != scope.casefold() and not action_resource.startswith(scope.casefold() + "/"):
        return False
    if record["TechniqueId"] == "azure-arc-resource-bridge-credential-export":
        if not re.fullmatch(r"/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.resourceconnector/appliances/[^/]+",
                            action_resource):
            return False
    if record["TechniqueId"] == "azure-datafactory-github-oauth-external-principal":
        if not re.fullmatch(
            r"/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.datafactory/factories/[^/]+",
            action_resource,
        ):
            return False
    target_resource = record["TargetServiceResource"]
    try:
        url = urlsplit(target_resource)
        external_ok = (url.scheme == "https" and bool(url.hostname) and bool(url.path)
                       and not url.username and not url.password and not url.query and not url.fragment)
    except ValueError:
        external_ok = False
    if not (external_ok or target_resource.casefold().startswith(scope.casefold() + "/")):
        return False
    if record["TechniqueId"] == "azure-datafactory-github-oauth-external-principal":
        repo_path = url.path.strip("/").split("/") if external_ok else []
        enterprise = url.hostname != "github.com" if external_ok else False
        try:
            github_port_ok = external_ok and url.port in (None, 443)
        except ValueError:
            github_port_ok = False
        if (not external_ok or len(repo_path) != 2 or not all(repo_path)
                or not github_port_ok
                or record.get("GitHubHost", "").casefold() != url.hostname.casefold()
                or record.get("GitHubRepositoryOwner") != repo_path[0]
                or record.get("GitHubRepositoryName") != repo_path[1]
                or not all(_exact(record.get(key)) for key in (
                    "GitHubAuthorizationCodeEvidenceRef", "GitHubTokenResponseEvidenceRef",
                    "GitHubAuthenticatedSubjectEvidenceRef", "GitHubRepositoryActionEvidenceRef"))
                or not all(record.get(key) is True for key in (
                    "GitHubAuthorizationCodeSupplied", "GitHubTokenFromActionResponseVerified",
                    "GitHubTokenUsedForAuthenticationVerified", "GitHubRepositoryActionAuthorizedVerified"))
                or (enterprise and (record.get("GitHubEnterpriseHostVerified") is not True
                                    or not _exact(record.get("GitHubEnterpriseHostEvidenceRef"))))):
            return False
    if (record["PriorTestedPermission"] != record["GainedPermission"]
            or record["AfterTestedPermission"] != record["GainedPermission"]
            or record["PriorTestedResource"] != target_resource
            or record["AfterTestedResource"] != target_resource
            or record.get("ObservedPrincipalId") != record["TargetPrincipalId"]):
        return False
    if record.get("AccessArtifactKind") not in ("credential", "identity_grant"):
        return False
    if record["TechniqueId"] == "azure-avs-list-vcenter-cloudadmin-external-principal":
        vcenter_action = record.get("VcenterGainedAction")
        vcenter_privilege = isinstance(vcenter_action, str) and re.fullmatch(
            r"[A-Za-z][A-Za-z0-9]*(?:\.[A-Za-z][A-Za-z0-9]*)+", vcenter_action)
        vcenter_ui = (isinstance(vcenter_action, str)
                      and vcenter_action.startswith("vCenter UI: ") and len(vcenter_action) > 16)
        if (not (vcenter_privilege or vcenter_ui)
                or record.get("ReturnedVcenterUsername") != record["TargetPrincipalId"]
                or record.get("VcenterPasswordReturnedVerified") is not True
                or record.get("VcenterActionAuthorizedVerified") is not True
                or vcenter_action != record["GainedPermission"]
                or not all(_exact(record.get(key)) for key in (
                    "CredentialResponseEvidenceRef", "VcenterActionEvidenceRef"))):
            return False
    if record["TechniqueId"] == "azure-avs-list-nsxt-admin-external-principal":
        nsx_action = record.get("NsxtGainedAction")
        nsx_api = isinstance(nsx_action, str) and re.fullmatch(
            r"(?:GET|POST|PUT|PATCH|DELETE) /(?:policy/)?api/v1/[^\s]+", nsx_action)
        nsx_ui = isinstance(nsx_action, str) and nsx_action.startswith("NSX UI: ") and len(nsx_action) > 12
        if (not (nsx_api or nsx_ui)
                or record.get("ReturnedNsxtUsername") != record["TargetPrincipalId"]
                or record.get("NsxtPasswordReturnedVerified") is not True
                or record.get("NsxtActionAuthorizedVerified") is not True
                or record.get("NsxtGainedAction") != record["GainedPermission"]
                or not all(_exact(record.get(key)) for key in (
                    "CredentialResponseEvidenceRef", "NsxtActionEvidenceRef"))):
            return False
    if record["TechniqueId"] == "azure-avs-run-command-vcenter-grant-external-principal":
        package = str(record.get("ExecutedPackageId") or "").casefold()
        cmdlet = str(record.get("ExecutedCmdletId") or "").casefold()
        execution = str(record.get("ScriptExecutionResourceId") or "").casefold()
        expected_package = re.fullmatch(
            re.escape(action_resource) + r"/scriptpackages/microsoft\.avs\.identity@[^/]+", package)
        expected_cmdlet = (package + "/scriptcmdlets/" + cmdlet.rsplit("/", 1)[-1]
                           if expected_package else "")
        known_grants = {"add-grouptocloudadmins", "new-ldapidentitysource",
                        "new-ldapsidentitysource"}
        if (not all(_exact(record.get(key)) for key in (
                "ExecutedPackageId", "ExecutedCmdletId", "GrantOperationEvidenceRef",
                "ScriptExecutionResourceId", "GrantedGroupName", "ExecutedGroupName",
                "GroupMembershipEvidenceRef", "SourceLoginEvidenceRef"))
                or not expected_package or cmdlet != expected_cmdlet
                or cmdlet.rsplit("/", 1)[-1] not in known_grants
                or not re.fullmatch(re.escape(action_resource) + r"/scriptexecutions/[^/]+", execution)
                or record["GrantedGroupName"] != record["ExecutedGroupName"]
                or record.get("AuthenticatedPrincipalId") != record["TargetPrincipalId"]
                or record.get("SourceControlsTargetLogin") is not True
                or record.get("TargetInGrantedGroupVerified") is not True
                or record.get("GrantOperationSucceeded") is not True):
            return False
    if record["TechniqueId"] == "azure-eventgrid-mqtt-client-grant-external-principal":
        namespace = action_resource
        topic_space = record["TargetServiceResource"].casefold()
        topic_prefix = namespace + "/topicspaces/"
        topic_name = topic_space[len(topic_prefix):] if topic_space.startswith(topic_prefix) else ""
        client_id = str(record.get("MqttClientId") or "")
        group_id = str(record.get("MqttClientGroupId") or "")
        binding_id = str(record.get("PermissionBindingId") or "")
        if (not all(_exact(record.get(key)) for key in (
                "MqttClientId", "MqttClientGroupId", "PermissionBindingId",
                "OwnedCredentialEvidenceRef", "GrantOperationEvidenceRef",
                "MqttClientResourceId", "PermissionBindingResourceId",
                "PermissionBindingClientGroupName", "PermissionBindingTopicSpaceName",
                "PermissionBindingPermission", "ClientGroupQueryEvidenceRef"))
                or not re.fullmatch(
                    r"/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.eventgrid/namespaces/[^/]+",
                    namespace)
                or not topic_name or "/" in topic_name
                or not re.fullmatch(r"[-a-zA-Z0-9:._]{1,128}", client_id)
                or not (group_id == "$all" or re.fullmatch(r"[a-zA-Z0-9-]{3,50}", group_id))
                or not re.fullmatch(r"[a-zA-Z0-9-]{3,50}", binding_id)
                or not re.fullmatch(r"[a-zA-Z0-9-]{3,50}", topic_name)
                or record["MqttClientResourceId"].casefold() != namespace + "/clients/" + client_id.casefold()
                or record["PermissionBindingResourceId"].casefold() != namespace + "/permissionbindings/" + binding_id.casefold()
                or record["PermissionBindingClientGroupName"].casefold() != group_id.casefold()
                or record["PermissionBindingTopicSpaceName"].casefold() != topic_name
                or record["PermissionBindingPermission"].casefold() not in ("publisher", "subscriber")
                or record["PermissionBindingPermission"].casefold() != record["GainedPermission"].casefold()
                or record.get("MqttClientId") != record["TargetPrincipalId"]
                or not (record.get("ClientCreated") is True or record.get("ClientPreexistingOwned") is True)
                or not (record.get("PermissionBindingCreated") is True
                        or record.get("PermissionBindingUpdated") is True)
                or not all(record.get(key) is True for key in (
                    "ClientGroupBound", "ClientGroupQueryMatchedClient",
                    "CredentialOwnedBySource", "GrantOperationSucceeded"))):
            return False
    try:
        captured = _instant(snapshot.get("created_at"))
        observed = _instant(record.get("EvidenceObservedAt"))
        expiry = _instant(record.get("EvidenceExpiresAt"))
        prior = _instant(record.get("PriorAccessCheckedAt"))
        action = _instant(record.get("ActionObservedAt"))
        after = _instant(record.get("AfterAccessCheckedAt"))
        fresh = (prior < action <= after <= observed <= captured < expiry
                 and (captured - prior).total_seconds() <= 900)
    except (TypeError, ValueError, OverflowError):
        fresh = False
    return (fresh and record.get("Status") == "verified"
            and all(record.get(key) is True for key in (
                "ActionSucceeded", "PriorSourceAccessDenied", "AccessArtifactUsable",
                "AfterAuthenticationSucceeded", "AfterTargetPermissionAllowed",
                "TargetServiceBindingVerified", "TargetSubjectBindingVerified")))


def _node_id(record):
    fields = ("TechniqueId", "SourceId", "TargetPlane", "TargetServiceResource", "TargetPrincipalId")
    digest = hashlib.sha256("\x00".join(record[field] for field in fields).encode()).hexdigest()[:20]
    return f"azure_external_principal:{record['TargetPlane']}:{digest}"


def load(model):
    """A unique record in a complete subscription collection creates a target."""
    status = inventory_status(model.snapshot, COLLECTION)
    grouped, poisoned = {}, set()
    for collection_scope, record in items(model.snapshot, COLLECTION):
        scope = str(collection_scope).casefold()
        if not isinstance(record, dict):
            continue
        technique, source = record.get("TechniqueId"), record.get("SourceId")
        if not _exact(technique) or not _exact(source):
            continue
        owner = (technique, source, scope)
        if not all(_exact(record.get(key)) for key in (
                "ActionResource", "AccessPermission", "TargetPlane", "TargetServiceResource",
                "TargetPrincipalId")):
            poisoned.add(owner)
            continue
        key = (technique, source, scope, record["ActionResource"],
               record["AccessPermission"], record["TargetPlane"], record["TargetServiceResource"],
               record["TargetPrincipalId"])
        grouped.setdefault(key, []).append((collection_scope, record))
    nodes, records = {}, {}
    for (technique, source, scope, _, _, _, _, _), matches in grouped.items():
        if (technique, source, scope) in poisoned:
            continue
        if len(matches) != 1 or status.get(matches[0][0]) != "collected":
            continue
        record = matches[0][1]
        if not _valid(record, scope, model.snapshot):
            poisoned.add((technique, source, scope))
            continue
        ident = _node_id(record)
        if record["ActionResource"].casefold() != scope.casefold():
            model.parents.setdefault(record["ActionResource"].casefold(), scope.casefold())
        nodes[ident] = Node(ident, "azure_external_principal", "azure", scope,
                            f"{record['TargetPrincipalId']} on {record['TargetServiceResource']}",
                            attrs={"scope": scope, "resource": record["ActionResource"],
                                   "external_plane": record["TargetPlane"],
                                   "external_principal": record["TargetPrincipalId"],
                                   "external_resource": record["TargetServiceResource"]})
        records[ident] = record
    if poisoned:
        for ident, record in list(records.items()):
            if (record["TechniqueId"], record["SourceId"], record["TargetScope"].casefold()) in poisoned:
                nodes.pop(ident)
                records.pop(ident)
    return nodes, records


def select(model, candidates, source):
    if source is None:
        return {}
    entry = model.current_entry or {}
    if (entry.get("target") or {}).get("outcome") not in ("credentials", "identity"):
        return {}

    def actions(value):
        if isinstance(value, dict):
            if isinstance(value.get("action"), str):
                yield value["action"].casefold()
            for nested in value.values():
                yield from actions(nested)
        elif isinstance(value, list):
            for nested in value:
                yield from actions(nested)

    required = set(actions(entry.get("requires") or {}))
    out = {}
    for ident, node in candidates.items():
        record = model.external_principal_records.get(ident)
        if (record is None or record["TechniqueId"] != entry.get("id")
                or record["SourceId"] != source.id
                or record["AccessPermission"].casefold() not in required
                or node.attrs.get("resource") != record["ActionResource"]):
            continue
        authority_resource = (record["ScriptExecutionResourceId"]
                              if record["TechniqueId"] == "azure-avs-run-command-vcenter-grant-external-principal"
                              else record["ActionResource"])
        authority = model.check(source, {"action": record["AccessPermission"]}, authority_resource)
        if authority is not None and authority.confidence != "unknown":
            out[ident] = ("conditional", "reviewed_external_principal_gain")
    return out
