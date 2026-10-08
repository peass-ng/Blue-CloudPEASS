"""Run reviewed applicability SQL against synthetic resources in the real engine.

Run inside the hardening image with the repository mounted at /repo:
  python /repo/tests/integration/verify_query_context.py
No cloud credentials, APIs, or persistent infrastructure are used.
"""

import json
from pathlib import Path
import re
import runpy
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "docker"))
from query_context import prepare_query_context, _cli_value


def value(value):
    if value is None:
        return "null"
    if isinstance(value, bool):
        return str(value).lower()
    if isinstance(value, (dict, list)):
        return "'" + json.dumps(value).replace("'", "''") + "'::jsonb"
    return "'" + str(value).replace("'", "''") + "'"


def table(name, columns, records):
    data = ",".join("(" + ",".join(value(item) for item in row) + ")" for row in records)
    return name + "(" + ",".join(columns) + ") as (values " + data + ")"


def query_sql(directory, name):
    for path in directory.rglob("*.pp"):
        text = path.read_text()
        match = re.search(r'^query "' + name + r'"\s*\{.*?\bsql\s*=\s*<<-?(\w+)\s*\n(.*?)^\s*\1\s*$', text, re.M | re.S)
        if match:
            return re.sub(r"\$\{[^\n]+\}", "", match[2]).strip().rstrip(";")
    raise AssertionError("Missing fixture query: " + name)


def with_tables(sql, tables):
    prefix = ", ".join(tables)
    if sql.lstrip().startswith("with "):
        return "with " + prefix + ", " + sql.lstrip()[5:]
    return "with " + prefix + " " + sql


def fixtures(root):
    aws, azure, gcp = root / "aws-compliance", root / "azure-compliance", root / "gcp-compliance"
    result = []
    def add(name, directory, sql_name, tables, expected):
        result.append((name, with_tables(query_sql(directory, sql_name), tables), expected))
    add("managed_network_acl", aws, "vpc_network_acl_unused", [table("aws_vpc_network_acl", ["network_acl_id", "associations", "is_default", "title"], [("default", [], True, "default"), ("customer", [], False, "customer")])], {"bluepeass_default_network_acl": {"default": True, "customer": False}})
    add("requester_managed_eni", aws, "ec2_network_interface_unused", [table("aws_ec2_network_interface", ["network_interface_id", "status", "attached_instance_id", "requester_managed", "title"], [("managed", "available", None, True, "managed"), ("customer", "available", None, False, "customer")])], {"bluepeass_requester_managed": {"managed": True, "customer": False}})
    distributions = [("oac", "oac", [{"DomainName": "bucket.s3.amazonaws.com", "OriginAccessControlId": "oac-id", "S3OriginConfig": {"OriginAccessIdentity": ""}}], {}, []), ("open", "open", [{"DomainName": "bucket.s3.amazonaws.com", "S3OriginConfig": {"OriginAccessIdentity": ""}}], {}, ["custom.example.test"]), ("sdk_default", "sdk_default", [], {}, {"Quantity": 0}), ("sdk_alias", "sdk_alias", [], {}, {"Quantity": 1, "Items": ["custom.example.test"]})]
    cf = table("aws_cloudfront_distribution", ["arn", "title", "origins", "viewer_certificate", "aliases"], distributions)
    add("oac_alternative", aws, "cloudfront_distribution_origin_access_identity_enabled", [cf], {"bluepeass_origin_access_control": {"oac": True, "open": False}})
    add("default_domain", aws, "cloudfront_distribution_use_custom_ssl_certificate", [cf], {"bluepeass_custom_domain_count": {"oac": 0, "open": 1, "sdk_default": 0, "sdk_alias": 1}})
    queues = table("aws_sqs_queue", ["queue_arn", "title", "redrive_policy"], [("source", "source", {"deadLetterTargetArn": "dlq"}), ("dlq", "dlq", None), ("customer", "customer", None)])
    add("dead_letter_target", aws, "sqs_queue_dead_letter_queue_configured", [queues], {"bluepeass_dead_letter_queue": {"source": False, "dlq": True, "customer": False}})
    subs = table("azure_subscription", ["subscription_id"], [("one",), ("two",), ("missing",)])
    contacts = table("azure_security_center_contact", ["name", "email", "subscription_id"], [("default", "one@example.test", "one"), ("default", "two@example.test", "two")])
    add("all_subscription_contacts", azure, "securitycenter_email_configured", [subs, contacts], {"status": {"one": "ok", "two": "ok", "missing": "alarm"}})
    sql = table("gcp_sql_database_instance", ["self_link", "title", "ip_configuration"], [("encrypted", "encrypted", {"sslMode": "ENCRYPTED_ONLY"}), ("client_cert", "client_cert", {"sslMode": "TRUSTED_CLIENT_CERTIFICATE_REQUIRED"}), ("legacy", "legacy", {"requireSsl": True}), ("unsafe", "unsafe", {"sslMode": "ALLOW_UNENCRYPTED_AND_ENCRYPTED"})])
    add("ssl_modes", gcp, "sql_instance_require_ssl_enabled", [sql], {"status": {"encrypted": "ok", "client_cert": "ok", "legacy": "ok", "unsafe": "alarm"}})
    firewall = table("gcp_compute_firewall", ["name", "self_link", "title", "direction", "action", "source_ranges", "allowed", "disabled"], [("disabled", "disabled", "disabled", "INGRESS", "Allow", ["0.0.0.0/0"], [{"IPProtocol": "tcp", "ports": ["3389"]}], True), ("enabled", "enabled", "enabled", "INGRESS", "Allow", ["0.0.0.0/0"], [{"IPProtocol": "tcp", "ports": ["3389"]}], False)])
    add("disabled_firewall_evidence", gcp, "compute_firewall_rule_rdp_access_restricted", [firewall], {"status": {"disabled": "alarm", "enabled": "alarm"}, "bluepeass_firewall_disabled": {"disabled": True, "enabled": False}})
    accounts = table("azure_storage_account", ["id", "name", "subscription_id", "encryption_key_source"], [("customer_key", "customer_key", "one", "Microsoft.Keyvault"), ("platform_key", "platform_key", "one", "Microsoft.Storage")])
    add("customer_encryption_alternative", azure, "storage_account_encryption_at_rest_using_mmk", [accounts, subs], {"bluepeass_key_source": {"customer_key": "Microsoft.Keyvault", "platform_key": "Microsoft.Storage"}})
    tenant = table("azure_tenant", ["tenant_id", "subscription_id", "_ctx"], [("tenant", "one", {})])
    policies = table("azuread_authorization_policy", ["id", "display_name", "tenant_id", "default_user_role_permissions"], [("deny_all", "deny_all", "tenant", {"permissionGrantPoliciesAssigned": []}), ("verified", "verified", "tenant", {"permissionGrantPoliciesAssigned": ["ManagePermissionGrantsForSelf.microsoft-user-default-low"]}), ("unsafe", "unsafe", "tenant", {"permissionGrantPoliciesAssigned": ["ManagePermissionGrantsForSelf.microsoft-user-default-legacy"]})])
    add("stricter_consent_alternative", azure, "ad_authorization_policy_user_consent_verified_publishers_selected_permissions", [tenant, policies], {"status": {"deny_all": "ok", "verified": "ok", "unsafe": "alarm"}})
    # Real SQL parsing of command/args, last flag wins, comma-separated plugins,
    # explicit false values, and certificate filenames independent of extension.
    commands = table("cases", ["resource", "c"], [("default", {"command": ["kube-apiserver"]}), ("list", {"command": ["kube-apiserver", "--enable-admission-plugins=NodeRestriction,NamespaceLifecycle"]}), ("args", {"command": ["kube-apiserver"], "args": ["--root-ca-file", "/ca.crt", "--service-account-lookup=false"]}), ("repeat", {"args": ["--service-account-lookup=false", "--service-account-lookup=true"]})])
    result.append(("cli_parser", "with " + commands + " select resource, " + _cli_value("c", "service-account-lookup") + " as lookup, " + _cli_value("c", "root-ca-file") + " as certificate, " + _cli_value("c", "enable-admission-plugins") + " as plugins from cases", {"lookup": {"default": None, "list": None, "args": "false", "repeat": "true"}, "certificate": {"args": "/ca.crt"}, "plugins": {"list": "NodeRestriction,NamespaceLifecycle"}}))
    return result


def main():
    with tempfile.TemporaryDirectory(prefix="bluepeass-query-tests-") as work:
        root = Path(work)
        for provider, mod in [("aws", "aws-compliance"), ("azure", "azure-compliance"), ("gcp", "gcp-compliance")]:
            shutil.copytree("/opt/bluepeass/mods/" + mod, root / mod)
            prepare_query_context(root / mod, provider)
        tests = fixtures(root)
        original = subprocess.run
        def execute(command, **kwargs):
            completed = original(command, **kwargs)
            if "query" in command and any("schema_name" in argument for argument in command):
                install = command[command.index("--install-dir") + 1]
                for name, sql, expected in tests:
                    result = original(["steampipe", "--install-dir", install, "query", sql, "--output", "json"], capture_output=True, text=True, timeout=30)
                    assert result.returncode == 0, (name, result.stderr)
                    rows = json.loads(result.stdout)["rows"]
                    for field, values in expected.items():
                        actual = {str(row["resource"]): row.get(field) for row in rows}
                        assert all(actual.get(resource) == setting for resource, setting in values.items()), (name, field, actual, values)
                    print(name + ": passed", flush=True)
            return completed
        subprocess.run = execute
        sys.argv = ["worker", "--self-test", "--input-dir", str(root), "--output-dir", str(root / "output"), "--timeout", "120"]
        runpy.run_path("/opt/bluepeass/hardening_worker.py", run_name="__main__")


if __name__ == "__main__":
    main()
