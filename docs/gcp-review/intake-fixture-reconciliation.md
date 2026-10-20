# Intake fixture reconciliation — 2026-10-19

Updated only the six assigned test files. Boolean validation remains strict: five invalid opt-ins now require constructor `ValueError` before credential/session access. The registered Artifact File named-gate fixture now includes an exact scoped File selection with SHA256 and format.

Directory responses now use real CRM v3 project and organization fields to prove the selected customer before full-projection Directory reads. The pagination test asserts the six exact requests and resulting binding chain. The native service fixture uses the same project/organization/customer contract plus GKE native location and selfLink fields.

The service failure came from requesting newly supported content-only inventories in a metadata-success fixture. Its metadata inventory assertion and blanket rejection of malformed/unknown collections remain intact; 13 content-only kinds are checked separately for default exclusion and explicit disabled behavior. All registered consumers for those disabled kinds must return UNKNOWN. Five selected-source adapters currently return empty envelopes without selection, which is explicitly asserted and never treated as a clean secret observation.

The disabled workflow path exposed a synthetic transport attribute error. The coordinator fixed the production early admission gate and gated GKE authority validation on both opt-ins; this worker changed no production and did not expand the fake transport to hide that bug.

Direct Python invocation passed 57 helper cases using inert response resolvers and temporary MonkeyPatch contexts, including five constructor rejections, ten valid gate cases, 26 registered named cases, and sixteen metadata/default/disabled cases. These calls did not run pytest, touch shared restoration inputs, contact clouds, or execute detectors. Pytest session behavior and import-order effects remain pending the coordinator’s single combined targeted retest.

Pending pytest selections:

- `tests/test_gcp_additional_literal_secret_review_20261019.py::test_disabled_extra_inventories_make_zero_calls`
- `tests/test_gcp_additional_literal_secret_review_20261019.py::test_non_boolean_optin_rejected_before_credentials_or_http`
- `tests/test_gcp_log_secret_review_20261019.py::test_opt_in_and_named_binding_required_before_auth_or_http`
- `tests/test_gcp_log_secret_review_20261019.py::test_non_boolean_optin_rejected_before_credentials_or_http`
- `tests/test_gcp_selected_object_secret_review_20261019.py::test_default_no_optin_or_named_kind_performs_zero_additional_calls`
- `tests/test_gcp_selected_object_secret_review_20261019.py::test_non_boolean_optin_rejected_before_credentials_or_http`
- `tests/test_gcp_secret_integration_acceptance_review.py::test_registered_named_check_alone_admits_only_its_kind`
- `tests/test_peaso_checks_gcp_ports_collection.py::test_workspace_directory_reads_only_explicit_metadata_and_paginates_with_selected_identity`
- `tests/test_peaso_collectors_gcp.py::test_native_service_coverage_and_configuration_fixture`
- `tests/test_peaso_collectors_gcp.py::test_content_only_inventories_are_excluded_by_default`
- `tests/test_peaso_collectors_gcp.py::test_explicit_disabled_content_inventory_cannot_claim_collected_or_clean`
