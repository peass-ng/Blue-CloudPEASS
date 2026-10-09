"""Add explicit applicability evidence and repair reviewed pinned query defects.

These edits operate only on the private runtime copy. Extra SELECT columns are
Powerpipe dimensions, allowing the report blacklist to match evidence rather
than guessing from display names or free-text reasons.
"""

from pathlib import Path
import json
import re


def _projection(sql, expressions):
    marker = re.search(r"^\s*(?:--)?\$\{(?:replace\()?local\.(?:tag_dimensions|common_dimensions)", sql, re.M)
    if marker is None:
        raise ValueError("Reviewed query has no dimension projection marker")
    columns = "".join(f"\n      , {expression} as {name}" for name, expression in expressions.items())
    return sql[:marker.start()] + columns + "\n" + sql[marker.start():]


def _rewrite_query(text, name, transform, kind="query"):
    pattern = re.compile(r'(^' + kind + r'\s+"' + re.escape(name) + r'"\s*\{.*?)(?=^(?:query|control|benchmark)\s+"|\Z)', re.M | re.S)
    count = 0
    def block(match):
        nonlocal count
        body = match[1]
        sql_pattern = re.compile(r'(\bsql\s*=\s*<<-?(\w+)[^\n]*\n)(.*?)(^\s*\2\s*$)', re.M | re.S)
        def rewrite(sql):
            try:
                return sql[1] + transform(sql[3]) + sql[4]
            except (ValueError, KeyError) as exc:
                raise ValueError(name + ": " + str(exc)) from exc
        result, changed = sql_pattern.subn(rewrite, body, count=1)
        if changed != 1:
            raise ValueError("Reviewed query has no unique SQL body: " + name)
        count += 1
        return result
    return pattern.sub(block, text), count


def _cli_value(container, flag):
    arguments = f"coalesce({container} -> 'command', '[]'::jsonb) || coalesce({container} -> 'args', '[]'::jsonb)"
    return "(select case when a.value like '--" + flag + "=%' then substring(a.value from " + str(len(flag) + 4) + ") when b.value is not null and b.value not like '--%' then b.value else 'true' end from jsonb_array_elements_text(" + arguments + ") with ordinality a(value, ordinal) left join jsonb_array_elements_text(" + arguments + ") with ordinality b(value, ordinal) on b.ordinal = a.ordinal + 1 where a.value = '--" + flag + "' or a.value like '--" + flag + "=%' order by a.ordinal desc limit 1)"


def _cli_evidence(sql, suffix):
    alias = re.search(r"\b([a-z]+\.value)\s*->\s*'command'", sql)
    container = alias[1] if alias else "c"
    if suffix in {"namespace_lifecycle_enabled", "service_account_enabled", "node_restriction_enabled"}:
        plugin = {"namespace_lifecycle_enabled": "NamespaceLifecycle", "service_account_enabled": "ServiceAccount", "node_restriction_enabled": "NodeRestriction"}[suffix]
        disabled = f"'{plugin}' = any(string_to_array(coalesce({_cli_value(container, 'disable-admission-plugins')}, ''), ','))"
        enabled = "true" if suffix != "node_restriction_enabled" else f"'{plugin}' = any(string_to_array(coalesce({_cli_value(container, 'enable-admission-plugins')}, ''), ','))"
        expression = f"({enabled} and not ({disabled}))"
    elif suffix == "service_account_lookup_enabled":
        expression = "coalesce(" + _cli_value(container, "service-account-lookup") + ", 'true') = 'true'"
    else:
        flag = {"kube_controller_manager_root_ca_file_configured": "root-ca-file", "kube_controller_manager_service_account_private_key_file_configured": "service-account-private-key-file", "service_account_key_file_appropriate": "service-account-key-file"}[suffix]
        expression = "coalesce(" + _cli_value(container, flag) + ", '') not in ('', 'true')"
    return _projection(sql, {"bluepeass_cli_setting_secure": expression})


def _inspector2_sql(sql):
    """Retain the pinned control's dimensions while replacing its retired API."""
    dimensions = re.search(r'(\s*\$\{local\.tag_dimensions_sql\}\s*\$\{replace\(local\.common_dimensions_qualifier_sql[^\n]+\})', sql)
    if 'aws_inspector_finding' not in sql or dimensions is None:
        raise ValueError('Pinned Inspector Classic query changed')
    return """    with high_findings as (
      select f.finding_account_id, f.region, r ->> 'Id' as instance_id,
        count(distinct f.arn) as finding_count
      from aws_inspector2_finding as f, jsonb_array_elements(f.resources) as r
      where f.status = 'ACTIVE' and f.severity in ('HIGH', 'CRITICAL')
        and r ->> 'Type' = 'AWS_EC2_INSTANCE'
      group by f.finding_account_id, f.region, r ->> 'Id'
    ), scanned_instances as (
      select distinct source_account_id, region, resource_id
      from aws_inspector2_coverage
      where resource_type = 'AWS_EC2_INSTANCE' and scan_type = 'PACKAGE'
        and scan_status_code = 'ACTIVE' and last_scanned_at is not null
    )
    select i.arn as resource,
      case when f.finding_count > 0 then 'alarm'
           when c.resource_id is null then 'info'
           else 'ok' end as status,
      case when f.finding_count > 0 then i.title || ' has ' || f.finding_count || ' active high/critical Inspector findings.'
           when c.resource_id is null then i.title || ' has no completed active Inspector package scan; vulnerability status needs review.'
           else i.title || ' has no active high/critical Inspector findings.' end as reason
""" + dimensions[1] + """
    from aws_ec2_instance as i
      left join high_findings as f on f.instance_id = i.instance_id
        and f.finding_account_id = i.account_id and f.region = i.region
      left join scanned_instances as c on c.resource_id = i.instance_id
        and c.source_account_id = i.account_id and c.region = i.region;
"""


def _scope_image_controls(text, project):
    # A literal source_project predicate is pushed into the plugin's image
    # project discovery. A source_project=project column comparison is not.
    # Audit every custom image in this target, without enumerating the public
    # OS catalog belonging to Google's other projects.
    prefix = "with bluepeass_target_images as (select * from gcp_compute_image where source_project = '" + str(project).replace("'", "''") + "'), "
    replacement = json.dumps(prefix).replace('${', '$${').replace('%{', '%%{')
    applied = []
    for name in ['compute_image_policy_prohibit_public_access', 'compute_image_policy_shared_access']:
        pattern = re.compile(r'(^control "' + name + r'"\s*\{.*?)(?=^(?:control|query|benchmark) |\Z)', re.M | re.S)
        def rewrite(match):
            body, count = re.subn(r'"__TABLE_NAME__", "gcp_compute_image"', '"__TABLE_NAME__", "bluepeass_target_images"', match[1], count=1)
            if count != 1:
                raise ValueError('Pinned image policy query changed: ' + name)
            body, count = re.subn(r'local\.iam_policy_(?:public|shared_access)_sql', lambda m: 'replace(' + m[0] + ', "with ", ' + replacement + ')', body, count=1)
            if count != 1:
                raise ValueError('Pinned image policy SQL template changed: ' + name)
            applied.append(name)
            return body
        text = pattern.sub(rewrite, text)
    return text, applied


def prepare_query_context(directory, provider, project=None):
    transformations = {}
    def evidence(name, **expressions):
        transformations[name] = lambda sql, expressions=expressions: _projection(sql, expressions)

    if provider == "aws" and Path(directory).name == "aws-compliance":
        transformations["ec2_instance_no_high_level_finding_in_inspector_scan"] = _inspector2_sql
        evidence("vpc_security_group_unused", bluepeass_security_group_name="s.group_name")
        evidence("vpc_security_group_associated_to_eni", bluepeass_security_group_name="group_name")
        evidence("vpc_network_acl_unused", bluepeass_default_network_acl="is_default")
        evidence("ec2_network_interface_unused", bluepeass_requester_managed="requester_managed")
        evidence("cloudfront_distribution_origin_access_identity_enabled", bluepeass_origin_access_control="nullif(o ->> 'OriginAccessControlId', '') is not null")
        evidence("cloudfront_distribution_use_custom_ssl_certificate", bluepeass_custom_domain_count="case when jsonb_typeof(aliases) = 'array' then jsonb_array_length(aliases) when jsonb_typeof(aliases) = 'object' and jsonb_typeof(aliases -> 'Items') = 'array' then jsonb_array_length(aliases -> 'Items') when jsonb_typeof(aliases) = 'object' then (aliases ->> 'Quantity')::integer else null end")
        evidence("secretsmanager_secret_automatic_rotation_lambda_enabled", bluepeass_owning_service="owning_service")
        def queue(sql):
            sql = "    with referenced_dead_letter_queues as (select distinct redrive_policy ->> 'deadLetterTargetArn' as arn from aws_sqs_queue where redrive_policy is not null)\n" + sql
            return _projection(sql, {"bluepeass_dead_letter_queue": "queue_arn in (select arn from referenced_dead_letter_queues)"})
        transformations["sqs_queue_dead_letter_queue_configured"] = queue
    elif provider == "azure" and Path(directory).name == "azure-compliance":
        evidence("storage_account_encryption_at_rest_using_mmk", bluepeass_key_source="sa.encryption_key_source")
        # An aggregate grouped by subscription must not discard all but one
        # subscription's configured contacts before the outer join.
        for name in ["securitycenter_additional_email_configured", "securitycenter_email_configured"]:
            def contacts(sql):
                result, count = re.subn(r"\n\s*limit 1\s*\n", "\n", sql, count=1)
                if count != 1:
                    raise ValueError("Pinned contact aggregation changed")
                return result
            transformations[name] = contacts
        def consent(sql):
            condition = "(p.default_user_role_permissions -> 'permissionGrantPoliciesAssigned')::jsonb = '[]'::jsonb"
            sql = sql.replace("case\n", "case\n        when " + condition + " then 'ok'\n", 1)
            start = sql.index("end as status")
            sql = sql[:start] + sql[start:].replace("case\n", "case\n        when " + condition + " then p.display_name || ' user consent disabled.'\n", 1)
            return sql
        transformations["ad_authorization_policy_user_consent_verified_publishers_selected_permissions"] = consent
    elif provider == "gcp" and Path(directory).name == "gcp-compliance":
        def ssl(sql):
            condition = "ip_configuration ->> 'sslMode' = 'ENCRYPTED_ONLY'"
            if sql.count(condition) != 2:
                raise ValueError("Pinned Cloud SQL SSL condition changed")
            return sql.replace(condition, "(ip_configuration ->> 'sslMode' in ('ENCRYPTED_ONLY', 'TRUSTED_CLIENT_CERTIFICATE_REQUIRED') or (ip_configuration ->> 'requireSsl')::boolean is true)")
        transformations["sql_instance_require_ssl_enabled"] = ssl
    elif provider == "kubernetes":
        evidence("config_map_default_namespace_used", bluepeass_resource_name="name")
        evidence("service_default_namespace_used", bluepeass_resource_name="name")
        evidence("deployment_replica_minimum_3", bluepeass_desired_replicas="replicas")
        for kind in ["cronjob", "daemonset", "deployment", "job", "pod", "pod_template", "replicaset", "replication_controller", "statefulset"]:
            if kind == "pod":
                parent = "security_context"
            elif kind == "cronjob":
                parent = "job_template -> 'spec' -> 'template' -> 'spec' -> 'securityContext'"
            else:
                parent = "template -> 'spec' -> 'securityContext'"
            nonroot = "case when c -> 'securityContext' ->> 'runAsUser' is not null then (c -> 'securityContext' ->> 'runAsUser')::bigint > 0 when (" + parent + ") ->> 'runAsUser' is not null then ((" + parent + ") ->> 'runAsUser')::bigint > 0 else coalesce((c -> 'securityContext' ->> 'runAsNonRoot')::boolean, ((" + parent + ") ->> 'runAsNonRoot')::boolean, false) end"
            evidence(kind + "_non_root_container", bluepeass_non_root_configured=nonroot)
            evidence(kind + "_container_image_pull_policy_always", bluepeass_image_digest_pinned="(c ->> 'image') ~ '@sha256:[a-fA-F0-9]{64}$'")
            if kind == "pod":
                containers = "coalesce(containers, '[]'::jsonb) || coalesce(init_containers, '[]'::jsonb)"
            elif kind == "cronjob":
                containers = "coalesce(job_template -> 'spec' -> 'template' -> 'spec' -> 'containers', '[]'::jsonb) || coalesce(job_template -> 'spec' -> 'template' -> 'spec' -> 'initContainers', '[]'::jsonb)"
            else:
                containers = "coalesce(template -> 'spec' -> 'containers', '[]'::jsonb) || coalesce(template -> 'spec' -> 'initContainers', '[]'::jsonb)"
            seccomp = "jsonb_array_length(" + containers + ") > 0 and not exists (select 1 from jsonb_array_elements(" + containers + ") item where coalesce(item -> 'securityContext' -> 'seccompProfile' ->> 'type', (" + parent + ") -> 'seccompProfile' ->> 'type', 'Unconfined') not in ('RuntimeDefault', 'Localhost'))"
            evidence(kind + "_default_seccomp_profile_enabled", bluepeass_seccomp_configured=seccomp)
            for suffix in ["namespace_lifecycle_enabled", "service_account_enabled", "node_restriction_enabled", "service_account_lookup_enabled", "kube_controller_manager_root_ca_file_configured", "kube_controller_manager_service_account_private_key_file_configured", "service_account_key_file_appropriate"]:
                transformations[kind + "_container_argument_" + suffix] = lambda sql, suffix=suffix: _cli_evidence(sql, suffix)

    remaining, applied = set(transformations), []
    for path in Path(directory).rglob("*.pp"):
        text = path.read_text()
        modified = text
        if provider == "gcp" and Path(directory).name == "gcp-perimeter" and project is not None:
            modified, scoped = _scope_image_controls(modified, project)
            applied.extend(scoped)
        if provider == "gcp":
            kind = "control" if Path(directory).name == "gcp-perimeter" else "query"
            for match in list(re.finditer(r'^' + kind + r'\s+"([^"]+)"\s*\{', text, re.M)):
                name = match[1]
                if not (name.startswith("compute_firewall_") or name.startswith("restrict_firewall_") or name.startswith("vpc_firewall_")):
                    continue
                def firewall(sql):
                    tables = re.findall(r"\bfrom\s+([a-z_]+)(?:\s+as\s+([a-z]+))?", sql, re.I)
                    if not tables or tables[-1][0] != "gcp_compute_firewall":
                        raise ValueError("Reviewed firewall query no longer selects firewall resources")
                    alias = tables[-1][1]
                    return _projection(sql, {"bluepeass_firewall_disabled": (alias + "." if alias else "") + "disabled"})
                modified, count = _rewrite_query(modified, name, firewall, kind=kind)
                if count != 1:
                    raise ValueError("Pinned firewall applicability query changed: " + name)
                applied.append(name)
        for name in sorted(remaining.copy()):
            if 'query "' + name + '"' not in modified:
                continue
            modified, count = _rewrite_query(modified, name, transformations[name])
            if count != 1:
                raise ValueError("Reviewed query is not unique: " + name)
            remaining.remove(name)
            applied.append(name)
        if modified != text:
            path.write_text(modified)
    # Pod has a runAsUser check rather than a family-consistent non-root name;
    # variants not present in the pinned workload catalog are not invented.
    optional = {"pod_template_non_root_container", "pod_template_container_image_pull_policy_always", "pod_template_default_seccomp_profile_enabled"}
    if remaining - optional:
        raise ValueError("Pinned applicability queries changed: " + ", ".join(sorted(remaining - optional)))
    if provider == 'gcp' and Path(directory).name == 'gcp-perimeter' and project is not None:
        missing = {'compute_image_policy_prohibit_public_access', 'compute_image_policy_shared_access'} - set(applied)
        if missing:
            raise ValueError('Pinned image policy controls changed: ' + ', '.join(sorted(missing)))
    return applied
