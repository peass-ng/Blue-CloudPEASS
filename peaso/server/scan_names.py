"""Human scan names derived only from the connector input saved with the job."""
from datetime import datetime, timezone
import json
import re


def _short(value, fallback):
    if not isinstance(value, str):
        return fallback
    value = re.sub(r"[^\w.-]+", "-", value.strip()).strip("-._")
    return value[:48] or fallback


def _object(value):
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (ValueError, TypeError):
            return {}
    return value if isinstance(value, dict) else {}


def identity_hint(provider, private, scopes=()):
    """Return identity names and scope hints, never credential values."""
    auth = _object(_object(private).get("auth"))
    principal, accounts, default_scope = None, [], None
    if provider == "aws":
        selected = {account for scope in scopes if isinstance(scope, str)
                    for account in re.findall(r"(?<!\d)\d{12}(?!\d)", scope)}
        roles = auth.get("assume_roles") or ([auth["role_arn"]] if auth.get("role_arn") else auth.get("role_chain", [])[-1:])
        names = []
        for role in roles if isinstance(roles, list) else []:
            arn = role.get("role_arn") if isinstance(role, dict) else role
            match = re.fullmatch(r"arn:[\w-]+:iam::(\d{12}):role/(.+)", arn) if isinstance(arn, str) else None
            if match and (not selected or match[1] in selected):
                accounts.append(match[1])
                names.append(match[2].rsplit("/", 1)[-1])
        names = list(dict.fromkeys(names))
        principal = names[0] if len(names) == 1 else "multiple-roles" if names else None
        # Imported scans may use a default connector while the snapshot records
        # the actual caller. Prefer that recorded identity, never access keys.
        snapshot = _object(_object(_object(private).get("options")).get("snapshot"))
        callers = _object(snapshot.get("metadata")).get("caller_identities", [])
        recorded_names, recorded_accounts = [], []
        for caller in callers if isinstance(callers, list) else []:
            caller = _object(caller)
            arn, account = caller.get("Arn"), caller.get("Account")
            if not isinstance(arn, str) or not isinstance(account, str) or not re.fullmatch(r"\d{12}", account) or selected and account not in selected:
                continue
            match = re.fullmatch(r"arn:[\w-]+:(?:iam|sts)::" + account + r":(assumed-role|role|user)/(.+)", arn)
            name = (match[2].split("/", 1)[0] if match[1] == "assumed-role" else match[2].rsplit("/", 1)[-1]) if match else "root" if re.fullmatch(r"arn:[\w-]+:iam::" + account + ":root", arn) else None
            if name:
                recorded_names.append(name)
                recorded_accounts.append(account)
        recorded_names = list(dict.fromkeys(recorded_names))
        if recorded_names:
            principal = recorded_names[0] if len(recorded_names) == 1 else "multiple-identities"
            accounts = recorded_accounts
    elif provider == "gcp":
        service_account = _object(auth.get("sa_json"))
        email = service_account.get("client_email")
        if auth.get("method") == "platform-service-account":
            from peaso.gcp_platform import PLATFORM_EMAIL
            email = PLATFORM_EMAIL
        principal = email.split("@", 1)[0] if isinstance(email, str) else None
        default_scope = service_account.get("project_id")
    elif provider == "azure":
        client = auth.get("client_id")
        principal = client[:8] if isinstance(client, str) else None
    elif provider == "k8s":
        config = auth.get("kubeconfig_data")
        if isinstance(config, str):
            import yaml
            try:
                config = yaml.safe_load(config)
            except yaml.YAMLError:
                config = None
        config = config if isinstance(config, dict) else {}
        selected = auth.get("context") or config.get("current-context")
        for item in config.get("contexts", []) if isinstance(config.get("contexts", []), list) else []:
            if isinstance(item, dict) and item.get("name") == selected:
                context = _object(item.get("context"))
                principal, default_scope = context.get("user"), context.get("cluster")
                break
        default_scope = auth.get("cluster_id") or default_scope
    return principal, accounts, default_scope


def display_name(job, connector, hint):
    provider = connector.get("provider", "cloud")
    principal, accounts, default_scope = hint
    scopes = connector.get("scopes", [])
    scopes = scopes if isinstance(scopes, list) else []
    if provider == "aws":
        supplied = [match[0] for scope in scopes if isinstance(scope, str)
                    for match in [re.findall(r"(?<!\d)\d{12}(?!\d)", scope)] if match]
        scopes = list(dict.fromkeys(supplied or accounts))
    elif provider == "gcp":
        scopes = list(dict.fromkeys(s.removeprefix("projects/").split("/", 1)[0] for s in scopes if isinstance(s, str)))
    elif provider == "azure":
        scopes = list(dict.fromkeys(s.removeprefix("/subscriptions/").split("/", 1)[0][:8] for s in scopes if isinstance(s, str)))
    elif provider == "k8s" and default_scope:
        scopes = [default_scope]
    scopes = [s for s in scopes if s and s != "*"]
    scope_kind = {"aws": "accounts", "gcp": "projects", "azure": "subscriptions", "k8s": "clusters"}.get(provider, "scopes")
    scope = scopes[0] if len(scopes) == 1 else f"{len(scopes)}-{scope_kind}" if scopes else default_scope or "all-scopes"
    principal = principal or connector.get("name") or "default-identity"
    try:
        created = datetime.fromisoformat(job["created_at"].replace("Z", "+00:00"))
        date = (created if created.tzinfo else created.replace(tzinfo=timezone.utc)).astimezone(timezone.utc).strftime("%d.%m.%y")
    except (KeyError, TypeError, ValueError, AttributeError):
        date = "undated"
    return f"{_short(provider, 'cloud')}-{_short(principal, 'identity')}-{_short(scope, 'scope')}-{date}"
