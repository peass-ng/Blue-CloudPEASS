# Schema extensions requested by catalog authors (evaluator must implement in registry)

## Azure RBAC (catalog/azure/authorization|automation|virtual_machines|app_services ...)
- placeholder `{target.host_resource}`: ARM id of resource the managed identity is attached to
- `{pivot}` + `pivot_resource_type`: all requirements using {pivot} must be covered on the same resource of that type (may be newly created)
- selector `managed_identity_type: user_assigned|system_assigned`
- selector `custom_role_assigned_to_source`: scopes where custom roles assigned to source apply
- selector `credential_stored_in_scope`: principals whose secrets live in that resource (always conditional)
- selector `azure_host_linked_to_pivot: automation_hybrid_worker|...`
- `attached_to_service` values may be full ARM resource types (Microsoft.Web/sites/slots)
- requirement `data_action: true`: must be granted via DataActions
- blockers: azure_deny_assignment, role_assignment_condition_is_allowlist, scm_and_ftp_basic_auth_disabled

## Entra ID (catalog/azure/entraid_*.yaml)
- target kind `entra_group` (membership -> its Entra roles if role-assignable, RBAC, app roles)
- requirement keys: `graph_app_permission: <name>`; `entra_owner_of: <id>` + `object_type: application|servicePrincipal|group`; `entra_pim_eligible_role: <id>`; `entra_tenant_setting: guest_invites_allowed_for_source`; `scope:` on entra_permission/entra_role ("/", "/administrativeUnits/<id>", "/<objectId>")
- placeholder `{target.application_id}`; `{target.scope}` = Entra directory scope
- selectors: entra_reset_matrix_column (password_admin|helpdesk_admin|authentication_admin|user_admin|privileged_auth_admin|non_admin_only, per MS "who can reset passwords" table + role-assignable-group and restricted-AU exclusions); entra_role_assignment_scope_covers_target; entra_target_not_in_restricted_au; entra_sp_has_tenant_application; entra_app_sign_in_audience; entra_sp_type_in; entra_source_is_owner_of_application|service_principal|group; entra_custom_role_assigned_to_source; entra_pim_eligible_for_source; entra_agent_blueprint_principal_or_child_identity; entra_user_upn_on_federatable_custom_domain; entra_group_role_assignable; entra_group_membership_type; entra_group_type_covered_by_permission; entra_dynamic_rule_attributes_writable_by_source; entra_dynamic_rule_satisfiable_by_invited_guest (parse membershipRule); entra_role_assignable: any
- blockers: restricted_management_au, role_assignable_group_member_or_owner, sp_lock_configuration_credentials, service_principal_conditional_access_block, pim_approval_required_by_other_principal, target_upn_on_initial_onmicrosoft_domain
- severity: raise when an Entra "non-admin" target holds Azure RBAC Owner
