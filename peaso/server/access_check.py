"""Bounded, read-only connector access checks used before saving a connector."""
from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import json
import os
import re


def _issue(items, severity, scope, message):
    items.append({"severity": severity, "scope": scope, "message": message})


def _expiry(value):
    if not value:
        return None
    try:
        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(value, timezone.utc)
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed.astimezone(timezone.utc) if parsed.tzinfo else None
    except (ValueError, TypeError, OverflowError):
        return None


def _jwt_exp(token):
    try:
        payload = token.split(".")[1]
        return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))).get("exp")
    except (IndexError, ValueError, TypeError):
        return None


def _certificate_exp(value):
    try:
        from cryptography import x509
        raw = value.encode() if isinstance(value, str) else value
        if b"-----BEGIN CERTIFICATE-----" not in raw:
            if isinstance(value, str) and os.path.isfile(value) and os.path.getsize(value) <= 1_000_000:
                with open(value, "rb") as stream:
                    raw = stream.read()
            else:
                raw = base64.b64decode(raw, validate=True)
        match = re.search(rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", raw, re.DOTALL)
        return x509.load_pem_x509_certificate(match.group()).not_valid_after_utc if match else None
    except (ValueError, TypeError, AttributeError):
        return None


def _check_lifetime(auth, declared, issues):
    values = []
    if auth.get("aws_session_token"):
        values.append(("AWS session", declared))
    if auth.get("token") and not auth.get("aws_session_token"):
        values.append(("Access token", _jwt_exp(auth["token"]) or declared))
    for field in ("arm_token", "graph_token", "vault_token", "storage_token", "logs_token", "federated_token", "subject_token"):
        if auth.get(field):
            values.append((field.replace("_", " ").capitalize(), _jwt_exp(auth[field]) or declared))
    if auth.get("kubeconfig_data"):
        try:
            from peaso.collectors.k8s import validate_inline_kubeconfig
            configured = validate_inline_kubeconfig(auth["kubeconfig_data"], auth.get("context"))
            if configured.get("token"):
                values.append(("Kubeconfig token", _jwt_exp(configured["token"]) or declared))
        except Exception:
            pass
    for field in ("certificate_data", "client_certificate", "client_cert_data", "certificate_path", "client_cert"):
        if auth.get(field):
            expires = _certificate_exp(auth[field])
            if expires:
                values.append(("Client certificate", expires))
    for label, value in values:
        expires = _expiry(value)
        if expires is None:
            _issue(issues, "critical", label, "Expiration could not be verified. Enter its UTC expiration time.")
        elif expires < datetime.now(timezone.utc) + timedelta(hours=1):
            _issue(issues, "critical", label, "Credential expires in less than one hour. Supply a longer-lived credential.")


def _aws(auth, scopes, options, issues, principals):
    from peaso.collectors.aws import _session
    from botocore.config import Config
    region = (options.get("regions") or ["us-east-1"])[0]
    hosted = (auth.get("method") in {"assume_role", "task_role"}
              and str(auth.get("external_id", "")).startswith(("hacktricks-cspm-", "peaso-"))
              and not auth.get("aws_access_key_id")
              and bool(auth.get("assume_roles") or auth.get("role_arn")))
    config = Config(connect_timeout=5, read_timeout=10, retries={"max_attempts": 1})
    if hosted:
        import boto3
        from .validation import COLLECTOR_ROLE_ARN, PLATFORM_ACCOUNT_IDS
        source_session, _ = _session({"method": "default"}, region)
        collector = source_session.client("sts", config=config).assume_role(
            RoleArn=COLLECTOR_ROLE_ARN, RoleSessionName="hacktricks-cspm-access-check", DurationSeconds=3600)["Credentials"]
        session = boto3.Session(aws_access_key_id=collector["AccessKeyId"],
                                aws_secret_access_key=collector["SecretAccessKey"],
                                aws_session_token=collector["SessionToken"], region_name=region)
    else:
        source = {**auth, "method": "access_keys" if auth.get("aws_access_key_id") else auth.get("method", "default")}
        if source["method"] == "assume_role":
            source["method"] = "profile" if auth.get("profile") else "default"
        session, _ = _session(source, region)
    def assume(base, role_arn, external):
        params = {"RoleArn": role_arn, "RoleSessionName": "hacktricks-cspm-access-check", "DurationSeconds": 3600}
        if external:
            params["ExternalId"] = external
        result = base.client("sts", config=config).assume_role(**params)["Credentials"]
        import boto3
        return boto3.Session(aws_access_key_id=result["AccessKeyId"], aws_secret_access_key=result["SecretAccessKey"],
                             aws_session_token=result["SessionToken"], region_name=region)

    if not hosted:
        for step in [*(auth.get("role_chain") or []), *([{"role_arn": auth["role_arn"]}] if auth.get("role_arn") else [])]:
            entry = {"role_arn": step} if isinstance(step, str) else step
            try:
                session = assume(session, entry["role_arn"], entry.get("external_id") or auth.get("external_id"))
            except Exception:
                _issue(issues, "critical", entry.get("role_arn", "role chain"), "Could not assume the configured source role chain.")
                return
    targets = list(auth.get("assume_roles") or [])
    if hosted and auth.get("role_arn"):
        targets.append({"role_arn": auth["role_arn"]})
    if not hosted and options.get("include_source_account", True):
        targets = [{"source": True}] + targets
    if not targets:
        _issue(issues, "critical", "accounts", "No source account or target role is selected for scanning.")
        return
    selected_accounts = {s.split("/")[0] for s in scopes if re.match(r"^[0-9]{12}(?:/|$)", s)}
    verified_accounts = set()
    for target in targets:
        role_arn = target.get("role_arn") if isinstance(target, dict) else target
        if hosted and role_arn and role_arn.split(":")[4] in PLATFORM_ACCOUNT_IDS:
            _issue(issues, "critical", role_arn, "Platform-owned AWS accounts cannot be role targets.")
            continue
        if role_arn and selected_accounts and role_arn.split(":")[4] not in selected_accounts:
            continue
        scope = role_arn or "source account"
        try:
            active = session
            if role_arn:
                external = (target.get("external_id") if isinstance(target, dict) else None) or auth.get("external_id")
                if hosted:
                    try:
                        session.client("sts", config=config).assume_role(RoleArn=role_arn, RoleSessionName="hacktricks-cspm-trust-check", DurationSeconds=3600)
                    except Exception:
                        pass
                    else:
                        _issue(issues, "critical", scope, "Target role can be assumed without this connector's External ID; require sts:ExternalId in the trust policy.")
                active = assume(session, role_arn, external)
            identity = active.client("sts", config=config).get_caller_identity()
            if hosted and identity["Account"] in PLATFORM_ACCOUNT_IDS:
                _issue(issues, "critical", scope, "Platform-owned AWS accounts cannot be scanned.")
                continue
            if not role_arn and selected_accounts and identity["Account"] not in selected_accounts:
                continue
            verified_accounts.add(identity["Account"])
            principals.append({"scope": scope, "principal": identity["Arn"]})
        except Exception:
            _issue(issues, "critical", scope, "Could not authenticate or assume this target role with the configured trust and External ID.")
            continue
        try:
            active.client("iam", config=config).get_account_authorization_details(Filter=["Role"], MaxItems=1)
        except Exception:
            _issue(issues, "critical", scope, "IAM role inventory is denied (iam:GetAccountAuthorizationDetails). Grant the scanning role the documented read policies.")
        try:
            active.client("ec2", region_name=region, config=config).describe_instances(MaxResults=5)
        except Exception:
            _issue(issues, "critical", scope, "Compute inventory is denied (ec2:DescribeInstances). Grant the scanning role the documented read policies.")
        try:
            active.client("s3", config=config).list_buckets()
        except Exception:
            _issue(issues, "advisory", scope, "S3 bucket inventory is unavailable (s3:ListAllMyBuckets).")
        try:
            active.client("accessanalyzer", region_name=region, config=config).list_analyzers(maxResults=1)
        except Exception:
            _issue(issues, "advisory", scope, "IAM Access Analyzer inventory is unavailable (access-analyzer:ListAnalyzers). Grant read access if you use analyzer findings.")
    for missing in sorted(selected_accounts - verified_accounts):
        _issue(issues, "critical", missing, "No configured identity or target role could access this selected AWS account.")


def _gcp(auth, scopes, options, issues, principals, settings):
    import requests
    from peaso.collectors.gcp import Credentials
    from peaso.gcp_platform import PLATFORM_PROJECT, approved_project, load_service_account
    if auth.get("method") == "platform-service-account":
        auth = {"method": "service-account", "sa_json": load_service_account(settings.gcp_platform_sa_secret_arn)}
    service_account = auth.get("sa_json")
    if isinstance(service_account, str):
        try:
            service_account = json.loads(service_account)
        except ValueError:
            service_account = None
    principal = service_account.get("client_email") if isinstance(service_account, dict) else auth.get("target_principal") or auth.get("impersonate_service_account") or "authenticated GCP identity"
    credentials = Credentials(auth, timeout=10)
    try:
        headers = credentials.headers()
        selected = [s.removeprefix("projects/") for s in scopes if s != "*"]
        if options.get("all_projects") or "*" in scopes:
            page_token = None
            for _ in range(10):
                response = requests.get("https://cloudresourcemanager.googleapis.com/v3/projects:search", headers=headers,
                                        params={"pageSize": 100, **({"pageToken": page_token} if page_token else {})}, timeout=10)
                response.raise_for_status()
                page = response.json()
                selected.extend(item["projectId"] for item in page.get("projects", [])
                                if item.get("projectId") and item["projectId"] != PLATFORM_PROJECT)
                page_token = page.get("nextPageToken")
                if not page_token:
                    break
            if page_token:
                _issue(issues, "critical", "projects", "Too many accessible projects to verify in one check; select project IDs explicitly.")
        selected = list(dict.fromkeys(selected))
        if not selected:
            _issue(issues, "critical", "projects", "No accessible customer project was found.")
        for project in selected[:100]:
            if project == PLATFORM_PROJECT:
                _issue(issues, "critical", project, "Choose a different project to scan.")
                continue
            try:
                response = requests.get(f"https://cloudresourcemanager.googleapis.com/v3/projects/{project}", headers=headers, timeout=10)
                response.raise_for_status()
                item = response.json()
                if auth.get("project_proof_label") and not approved_project(item, auth["project_proof_label"]):
                    _issue(issues, "critical", project, "Project is missing this connector's approval label.")
                    continue
                principals.append({"scope": project, "principal": principal})
                perms = ["resourcemanager.projects.get", "cloudasset.assets.searchAllResources",
                         "iam.roles.list", "serviceusage.services.use", "logging.logEntries.list",
                         "logging.privateLogEntries.list", "securitycenter.findings.list",
                         "recommender.iamPolicyRecommendations.list"]
                response = requests.post(f"https://cloudresourcemanager.googleapis.com/v3/projects/{project}:testIamPermissions", headers=headers, json={"permissions": perms}, timeout=10)
                response.raise_for_status()
                granted = set(response.json().get("permissions", []))
                for permission in perms:
                    if permission not in granted:
                        _issue(issues, "critical" if permission in perms[:2] else "advisory", project, f"Missing {permission} on this project.")
            except Exception:
                _issue(issues, "critical", project, "Could not read this project or verify its IAM permissions.")
        if len(selected) > 100:
            _issue(issues, "critical", "projects", "Access check supports at most 100 projects at a time; narrow the scope.")
    finally:
        credentials.close()


def _azure(auth, scopes, issues, principals):
    from peaso.collectors.azure import AzureTransport, GRAPH, _claims
    transport = AzureTransport(auth)
    try:
        selected = scopes
        if not selected:
            response = transport.request("https://management.azure.com/subscriptions?api-version=2022-12-01")
            selected = [item["subscriptionId"] for item in response.get("value", []) if item.get("subscriptionId")]
        if not selected:
            _issue(issues, "critical", "subscriptions", "No accessible Azure subscription was found.")
        for value in selected[:100]:
            subscription = value.removeprefix("/subscriptions/")
            if not re.fullmatch(r"[0-9a-fA-F-]{36}", subscription):
                _issue(issues, "critical", value, "Enter a valid subscription ID.")
                continue
            try:
                transport.request(f"https://management.azure.com/subscriptions/{subscription}?api-version=2022-12-01")
                principals.append({"scope": subscription, "principal": auth.get("client_id") or "authenticated Azure identity"})
            except Exception:
                _issue(issues, "critical", subscription, "Cannot read this subscription (Microsoft.Resources/subscriptions/read).")
                continue
            for resource, label in (("resources", "resource inventory"), ("providers/Microsoft.Security/pricings", "Security Reader inventory")):
                try:
                    transport.request(f"https://management.azure.com/subscriptions/{subscription}/{resource}?api-version=" + ("2021-04-01" if resource == "resources" else "2024-01-01"))
                except Exception:
                    _issue(issues, "advisory", subscription, f"Cannot read {label}; check Reader and Security Reader assignments.")
        try:
            graph_token = transport.token(GRAPH)
            claims = _claims(graph_token)
            if auth.get("method") in {"client-secret", "client-cert", "workload-identity"}:
                required = {"Directory.Read.All", "Policy.Read.All", "AuditLog.Read.All", "Reports.Read.All",
                            "RoleManagement.Read.Directory", "Organization.Read.All"}
                for role in sorted(required - set(claims.get("roles", []))):
                    _issue(issues, "advisory", "Microsoft Graph", f"Missing {role} application permission or admin consent.")
            transport.request("https://graph.microsoft.com/v1.0/organization?$top=1", audience=GRAPH)
        except Exception:
            _issue(issues, "advisory", "Microsoft Graph", "Directory inventory is unavailable. Grant the documented Graph permissions and admin consent if directory checks are needed.")
    finally:
        if hasattr(transport, "close"):
            transport.close()


def _k8s(auth, issues, principals):
    from peaso.collectors.k8s import _new_api
    api = _new_api(auth)
    client = api.api_client
    client.rest_client.pool_manager.allow_self_subject_access_review = True
    try:
        for group, resource, severity in (("", "namespaces", "critical"), ("", "pods", "critical"),
                                          ("apps", "deployments", "critical"),
                                          ("rbac.authorization.k8s.io", "roles", "critical"),
                                          ("rbac.authorization.k8s.io", "rolebindings", "critical"),
                                          ("rbac.authorization.k8s.io", "clusterroles", "critical"),
                                          ("rbac.authorization.k8s.io", "clusterrolebindings", "critical"),
                                          ("", "secrets", "advisory")):
            review = {"apiVersion": "authorization.k8s.io/v1", "kind": "SelfSubjectAccessReview", "spec": {"resourceAttributes": {"group": group, "resource": resource, "verb": "list"}}}
            response = client.call_api("/apis/authorization.k8s.io/v1/selfsubjectaccessreviews", "POST", body=review, auth_settings=["BearerToken"], _preload_content=False, _return_http_data_only=True, _request_timeout=15)
            try:
                result = json.loads(response.data or response.read())
            finally:
                response.close()
                response.release_conn()
            allowed = result.get("status", {}).get("allowed", False)
            if not principals:
                principals.append({"scope": auth.get("cluster_id") or "cluster", "principal": "authenticated Kubernetes identity"})
            if not allowed:
                _issue(issues, severity, resource, f"Cannot list {resource}; grant the documented ClusterRole binding.")
    finally:
        if hasattr(api, "close"):
            api.close()


def check_access(provider, auth, scopes, options, settings, *, credential_expires_at=None):
    issues, principals = [], []
    _check_lifetime(auth, credential_expires_at, issues)
    if not any(item["severity"] == "critical" for item in issues):
        try:
            {"aws": _aws, "gcp": _gcp, "azure": _azure, "k8s": _k8s}[provider](
                *((auth, scopes, options, issues, principals) if provider == "aws" else
                  (auth, scopes, options, issues, principals, settings) if provider == "gcp" else
                  (auth, scopes, issues, principals) if provider == "azure" else
                  (auth, issues, principals)))
        except Exception as exc:
            status = getattr(exc, "status", None)
            suffix = f" (HTTP {status})" if isinstance(status, int) and 100 <= status <= 599 else ""
            _issue(issues, "critical", provider, "Could not authenticate or complete the access check" + suffix + ". Verify the credential, endpoint and target scope.")
    status = "blocked" if any(item["severity"] == "critical" for item in issues) else "warning" if issues else "pass"
    return {"status": status, "issues": issues, "principals": principals}
