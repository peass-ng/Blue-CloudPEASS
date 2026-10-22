"""Discontinued FinSpace route stays available only to historical bindings."""

from peaso.privesc import versioned_catalog as catalog


def test_finspace_sunset_removes_active_route_but_preserves_prior_binding():
    ident = "aws-finspace-passrole-createkxcluster"
    current, current_status = catalog.lookup_entries([ident], catalog.current_binding())
    assert current_status == "exact_strict_privesc"
    assert current == {}

    prior_binding = {
        "schema": catalog.BINDING_SCHEMA,
        "manifest_sha256": catalog.FINSPACE_SUNSET_690_PREVIOUS_MANIFEST,
        "effective_tree_sha256": catalog.FINSPACE_SUNSET_690_PREVIOUS_TREE,
        "source_revision": catalog.V4_REVISION,
    }
    previous, previous_status = catalog.lookup_entries([ident], prior_binding)
    assert previous_status == "exact_previous_current"
    assert set(previous) == {ident}
    assert len(catalog._verified_finspace_sunset_690_previous()) == 690
