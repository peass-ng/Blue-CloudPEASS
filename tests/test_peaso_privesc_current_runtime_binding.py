"""Current reports resolve, while earlier strict cards retain their exact catalog."""

from peaso.privesc import versioned_catalog as catalog
from peaso.privesc.finding_explanation import evidence_summary
from tests.test_peaso_privesc_finding_explanations_review import admin_projected


def test_current_catalog_binding_resolves_new_technique():
    binding = catalog.current_binding()
    entries, status = catalog.lookup_entries(["aws-flink-studio-presigned-url"], binding)
    assert status == "exact_strict_privesc"
    assert set(entries) == {"aws-flink-studio-presigned-url"}


def test_cloudfront_creation_binding_retains_previous_update_only_catalog():
    ident = "aws-cloudfront-lambda-edge-passrole"
    current, status = catalog.lookup_entries([ident], catalog.current_binding())
    assert status == "exact_strict_privesc"
    assert "new or existing distribution" in current[ident]["title"]
    previous_binding = {"schema": catalog.BINDING_SCHEMA,
                        "manifest_sha256": catalog.CLOUDFRONT_CREATE_683_PREVIOUS_MANIFEST,
                        "effective_tree_sha256": catalog.CLOUDFRONT_CREATE_683_PREVIOUS_TREE,
                        "source_revision": catalog.V4_REVISION}
    previous, status = catalog.lookup_entries([ident], previous_binding)
    assert status == "exact_previous_current"
    assert previous[ident]["title"] == "Associate a new Lambda@Edge function with a passed role to a distribution"
    assert len(catalog._verified_cloudfront_create_683_previous()) == 683


def test_intermediate_strict_binding_uses_retained_660_entry_catalog():
    binding = {"schema": catalog.BINDING_SCHEMA,
               "manifest_sha256": catalog.INTERMEDIATE_CURRENT_MANIFEST,
               "effective_tree_sha256": catalog.INTERMEDIATE_CURRENT_TREE,
               "source_revision": catalog.V4_REVISION}
    entries, status = catalog.lookup_entries(
        ["aws-emr-addjobflowsteps", "aws-flink-studio-presigned-url"], binding)
    assert status == "exact_previous_current"
    assert set(entries) == {"aws-emr-addjobflowsteps"}
    assert len(catalog._verified_intermediate_current()) == 660


def test_previous_strict_binding_uses_retained_633_entry_catalog():
    binding = {"schema": catalog.BINDING_SCHEMA,
               "manifest_sha256": catalog.PREVIOUS_CURRENT_MANIFEST,
               "effective_tree_sha256": catalog.PREVIOUS_CURRENT_TREE,
               "source_revision": catalog.V4_REVISION}
    entries, status = catalog.lookup_entries(
        ["aws-emr-passrole-runjobflow", "aws-emr-addjobflowsteps"], binding)
    assert status == "exact_previous_current"
    assert set(entries) == {"aws-emr-passrole-runjobflow"}
    assert len(catalog._verified_previous_current()) == 633


def test_azure_and_kubernetes_finding_explanations_load():
    for provider in ("azure", "k8s"):
        for confidence in ("derived", "conditional", "unknown"):
            text = evidence_summary(admin_projected(provider, confidence))
            assert text and len(text.splitlines()) == 3
