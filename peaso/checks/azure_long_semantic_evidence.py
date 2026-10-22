"""Observed Azure success facts retained by the native evaluators."""


def evidence_summary(finding):
    if not isinstance(finding, dict) or finding.get('provider') != 'azure' or finding.get('status') not in ('PASS', 'FAIL'):
        return None
    cid, e = finding.get('check_id'), finding.get('evidence')
    if not isinstance(e, dict):
        return None
    if finding['status'] == 'FAIL':
        if cid == 'azure_api_management_3_5_1_1_345bdac' and 'FAIL' in e.get('effective_path_states', []):
            return ('A required API path lacks an approved encrypted cache setting.\n'
                    'Its cached response may have less protection than intended.\n'
                    'That could expose data returned to users.')
        if cid == 'azure_devops_project_1_2_8_6_fb0e5a8':
            rows = e.get('observed_fail_facts')
            if isinstance(rows, list) and any(isinstance(row, dict)
                    and isinstance(row.get('repository_id'), str) and row.get('clone_url_has_credentials') is True
                    for row in rows):
                return ('A DevOps repository clone URL contains embedded credentials.\n'
                        'Someone who gets the URL may also get a sign-in secret.\n'
                        'That could expose the project code.')
        if cid == 'azure_devops_project_6_5_5_2_2908a87':
            rows = e.get('observed_fail_facts')
            if isinstance(rows, list) and any(isinstance(row, dict)
                    and type(row.get('deployment_job_count')) is int
                    and type(row.get('approved_job_limit')) is int
                    and row['deployment_job_count'] > row['approved_job_limit'] for row in rows):
                return ('A deployment stage allows more jobs than its approved limit.\n'
                        'More deployments may run at the same time than intended.\n'
                        'That could increase unwanted changes to services people use.')
        if cid == 'azure_ml_workspace_1_2_8_36_33f50db':
            rows = e.get('other_subnet_bindings')
            if isinstance(rows, list) and rows and all(isinstance(row, dict)
                    and isinstance(row.get('compute_id'), str) for row in rows):
                return ('An ML compute instance lacks an approved subnet binding.\n'
                        'It may use a different network path than intended.\n'
                        'That could expose the instance to unwanted requests.')
        if cid == 'azure_ml_workspace_1_2_8_37_973721f':
            ids = e.get('direct_egress_compute_ids')
            if isinstance(ids, list) and ids and all(isinstance(value, str) and value for value in ids):
                return ('An ML compute instance has a direct internet egress path.\n'
                        'It may send requests outside the approved network route.\n'
                        'That could expose data handled by the instance.')
        if cid == 'azure_storage_account_monitor_alert_create_update_sqlserver_fr_7a7ddfa':
            violations = e.get('violations')
            if isinstance(violations, list) and violations and all(isinstance(row, dict)
                    and isinstance(row.get('metricName'), str) for row in violations):
                return (f'The required {violations[0]["metricName"]} metric lacks an enabled alert.\n'
                        'A change in that metric may go unnoticed.\n'
                        'That could delay the team’s response to a service problem.')
        return None
    if cid == 'azure_aks_cluster_aks_cluster_rbac_enabled_db12524':
        rows, pods = e.get('nonroot_container_uids'), e.get('linux_pods')
        if (type(pods) is int and pods > 0 and isinstance(rows, list) and rows
                and all(isinstance(row, dict) and isinstance(row.get('container'), str)
                        and row['container'] and type(row.get('uid')) is int and row['uid'] > 0 for row in rows)):
            return (f'Linux container {rows[0]["container"]} declares user ID {rows[0]["uid"]}.\n'
                    'It is set to run without root user privileges.\n'
                    'That may limit what someone controlling it can change.')
    if cid == 'azure_api_management_3_5_1_1_345bdac':
        states, count = e.get('effective_path_states'), e.get('effective_path_count')
        if (isinstance(states, list) and states and all(state == 'PASS' for state in states)
                and type(count) is int and count == len(states)
                and type(e.get('required_operation_count')) is int and e['required_operation_count'] > 0):
            return ('Every recorded required API path uses an approved encrypted cache.\n'
                    'Cached responses may stay protected by its recorded settings.\n'
                    'That could help protect data returned to users.')
    if cid == 'azure_application_gateway_1_2_5_8_33a9d21':
        listeners, domains = e.get('approved_https_listener_ids'), e.get('approved_front_door_domain_ids')
        if (isinstance(listeners, list) and listeners and all(isinstance(v, str) and v for v in listeners)
                and type(e.get('https_listener_count')) is int and len(listeners) == e['https_listener_count']
                and isinstance(domains, list) and all(isinstance(v, str) and v for v in domains)
                and type(e.get('front_door_domain_count')) is int and len(domains) == e['front_door_domain_count']
                and e.get('approved_minimum_protocol') in ('TLSv1_2', 'TLSv1_3')):
            return (f'The HTTPS listeners use approved TLS settings at or above {e["approved_minimum_protocol"]}.\n'
                    'Those settings may protect traffic to the gateway.\n'
                    'That could help keep users’ data private in transit.')
    if cid == 'azure_application_gateway_app_client_certificates_on_fcca0b8':
        listeners, count = e.get('validated_key_vault_listener_ids'), e.get('listener_count')
        if (isinstance(listeners, list) and listeners and all(isinstance(v, str) and v for v in listeners)
                and type(count) is int and count == len(listeners)):
            return ('The HTTPS listeners have validated Key Vault certificate bindings.\n'
                    'Their server certificates may support trusted connections.\n'
                    'That could help users connect to the intended gateway.')
    if cid in ('azure_cosmos_account_10_2_1_1_13_5c115b0', 'azure_cosmos_account_10_2_1_1_23_e04a63d'):
        facts, count = e.get('observed_pass_facts'), e.get('assessed_count')
        if (type(count) is int and count > 0 and isinstance(facts, list) and len(facts) == count
                and all(isinstance(row, dict) and isinstance(row.get('resource_id'), str)
                        and isinstance(row.get('qualifying_diagnostic_ids'), list)
                        and row['qualifying_diagnostic_ids']
                        and all(isinstance(v, str) and v for v in row['qualifying_diagnostic_ids'])
                        and isinstance(row.get('required_categories'), list)
                        and row['required_categories'] for row in facts)):
            kind = 'Mongo request' if cid.endswith('13_5c115b0') else 'data-plane request'
            return (f'The Cosmos account has a diagnostic setting for {kind} logs.\n'
                    'Those logs may help trace use of its data.\n'
                    'The team could review unusual requests affecting users.')
    if cid in ('azure_devops_project_1_2_8_6_fb0e5a8', 'azure_devops_project_6_5_5_2_2908a87'):
        facts, count = e.get('observed_pass_facts'), e.get('assessed_count')
        if type(count) is int and count > 0 and isinstance(facts, list) and len(facts) == count:
            if cid.endswith('6_fb0e5a8') and all(
                    isinstance(row, dict) and type(row.get('repository_count')) is int
                    and row['repository_count'] >= 0 and row.get('clone_urls_with_credentials') == 0 for row in facts):
                if any(row['repository_count'] > 0 for row in facts):
                    return ('The recorded DevOps repository clone URLs contain no embedded credentials.\n'
                            'A copied URL may be less likely to reveal a sign-in secret.\n'
                            'That could help keep project code private.')
            if cid.endswith('2_2908a87') and all(
                    isinstance(row, dict) and type(row.get('pipeline_count')) is int
                    and row['pipeline_count'] >= 0 and type(row.get('checked_deployment_stages')) is int
                    and row['checked_deployment_stages'] >= 0 and row.get('stages_over_limit') == 0 for row in facts):
                if any(row['checked_deployment_stages'] > 0 for row in facts):
                    return ('The recorded deployment stages stay within their approved job limits.\n'
                            'A pipeline may run fewer deployments at once.\n'
                            'That could reduce unwanted changes to services people use.')
    if cid in ('azure_c5_ops_20_01b', 'azure_c5_ops_25_02b'):
        facts, count = e.get('observed_pass_facts'), e.get('assessed_count')
        if type(count) is int and count > 0 and isinstance(facts, list) and len(facts) == count:
            if cid.endswith('20_01b') and all(isinstance(row, dict)
                    and type(row.get('reviewed_incident_count')) is int and row['reviewed_incident_count'] >= 0
                    and (row.get('process_steps_verified') is True or row.get('continuous_coverage') is True)
                    for row in facts):
                return ('The Sentinel workspace has verified incident handling or continuous coverage.\n'
                        'Security events may receive a recorded response.\n'
                        'That could help protect people when an incident occurs.')
            if cid.endswith('25_02b') and all(isinstance(row, dict)
                    and (row.get('assessment_state') == 'NotApplicable'
                         or row.get('assessment_state') in ('Healthy', 'Unhealthy')
                         and row.get('criteria_matched') is True) for row in facts):
                return ('The applicable security assessments match the approved severity criteria.\n'
                        'Their ratings may help the team order needed work.\n'
                        'That could help people address serious data risks sooner.')
    if cid == 'azure_firewall_policy_sqlserver_unrestricted_inbound_access_c12f86d':
        facts, count = e.get('observed_pass_facts'), e.get('evaluated_count')
        if (type(count) is int and count > 0 and isinstance(facts, list) and len(facts) == count
                and all(isinstance(row, dict) and isinstance(row.get('server_id'), str)
                        and row['server_id'] and row.get('unrestricted_rules') == [] for row in facts)):
            return ('The reviewed database servers have no unrestricted firewall rules.\n'
                    'Their recorded rules do not allow every public IP address.\n'
                    'That may limit who can send requests to the databases.')
    if cid == 'azure_vm_1_4_5_1_d40be43':
        facts, count = e.get('observed_pass_facts'), e.get('evaluated_count')
        if (type(count) is int and count > 0 and isinstance(facts, list) and len(facts) == count
                and all(isinstance(row, dict)
                        and ((isinstance(row.get('vm_id'), str) and row.get('public_ip_ids') == [])
                             or (isinstance(row.get('vm_scale_set_id'), str)
                                 and row.get('public_ip_templates') == [])) for row in facts)):
            if all('vm_id' in row for row in facts):
                subject = 'VM network interfaces'
            elif all('vm_scale_set_id' in row for row in facts):
                subject = 'VM scale set templates'
            else:
                subject = 'VM interfaces and scale set templates'
            return (f'The reviewed {subject} have no public IP assignment.\n'
                    'Their recorded settings avoid a direct public address.\n'
                    'That may reduce unwanted requests to these workloads.')
    if cid == 'azure_ml_workspace_1_2_8_36_33f50db':
        bindings, count = e.get('approved_subnet_bindings'), e.get('compute_instance_count')
        if (type(count) is int and count > 0 and isinstance(bindings, list) and len(bindings) == count
                and all(isinstance(row, dict) and isinstance(row.get('compute_id'), str)
                        and row['compute_id'] and isinstance(row.get('subnet_id'), str)
                        and row['subnet_id'] for row in bindings)):
            return ('The ML compute instances use approved virtual network subnets.\n'
                    'Their recorded network placement follows the chosen subnet list.\n'
                    'That may reduce unwanted routes to the compute instances.')
    if cid == 'azure_ml_workspace_1_2_8_37_973721f':
        ids, count = e.get('blocked_egress_compute_ids'), e.get('compute_count')
        if (type(count) is int and count > 0 and isinstance(ids, list) and len(ids) == count
                and all(isinstance(value, str) and value for value in ids)):
            return ('The ML compute instances have no direct internet egress path.\n'
                    'Their recorded outbound attempts were blocked.\n'
                    'That may limit unwanted connections from those instances.')
    if cid == 'azure_storage_account_monitor_alert_create_update_sqlserver_fr_7a7ddfa':
        rows, count = e.get('matched_metrics'), e.get('required_metric_count')
        if (type(count) is int and count > 0 and isinstance(rows, list) and len(rows) == count
                and all(isinstance(row, dict) and isinstance(row.get('resource_id'), str)
                        and isinstance(row.get('metric_name'), str)
                        and isinstance(row.get('enabled_alert_ids'), list)
                        and row['enabled_alert_ids'] for row in rows)):
            return ('The required storage metrics have enabled alerts.\n'
                    'Those alerts may flag changes to the recorded resources.\n'
                    'That could help the team respond to unwanted changes.')
    if cid == 'azure_diagnostic_setting_11_5_2_3_7959930':
        rows, count = e.get('matched_settings'), e.get('expected_setting_count')
        if (type(count) is int and count > 0 and isinstance(rows, list)
                and {row.get('expected_setting') for row in rows if isinstance(row, dict)} == set(range(count))
                and all(isinstance(row, dict) and isinstance(row.get('enabled_alert_id'), str)
                        and row['enabled_alert_id'] and isinstance(row.get('routed_action_group_ids'), list)
                        and row['routed_action_group_ids'] for row in rows)):
            return ('The expected metric alerts are enabled and routed to action groups.\n'
                    'The recorded groups may receive the matching metric events.\n'
                    'That could help the team respond to service changes.')
    if cid in ('azure_storage_account_sqlserver_auditing_enabled_e4e4b28',
               'azure_synapse_workspace_10_2_1_1_28_47f4840'):
        ids, count = e.get('approved_pool_ids'), e.get('pool_count')
        if (type(count) is int and count > 0 and isinstance(ids, list) and len(ids) == count
                and all(isinstance(value, str) and value for value in ids)):
            if cid == 'azure_storage_account_sqlserver_auditing_enabled_e4e4b28':
                return ('The dedicated SQL pool audit policies are enabled for the required storage account.\n'
                        'Their recorded settings may store SQL audit events there.\n'
                        'That could help the team review changes to data.')
            return ('The Synapse workspace key and SQL pool audit policies match the required settings.\n'
                    'Their recorded settings may protect and record data use.\n'
                    'That could help the team review unwanted changes.')
    return None
