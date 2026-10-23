"""A per-member Config Management feature is collected under its exact membership."""

from types import SimpleNamespace

from test_gcp_config_delivery_location import catalog


def test_lists_each_membership_and_keeps_only_config_management():
    module = catalog()
    project = "projects/demo-project1"
    first = project + "/locations/global/memberships/one"
    second = project + "/locations/us-central1/memberships/two"
    calls = []

    def pages(url, scope, **kwargs):
        calls.append((url, scope, kwargs))
        if url.endswith("/locations/-/memberships"):
            yield [{"name": first}, {"name": second}], "memberships"
        elif url.endswith(first + "/features"):
            yield [{"name": first + "/features/configmanagement", "lifecycleState": {"state": "ACTIVE"}},
                   {"name": first + "/features/servicemesh"}], "first-features"
        elif url.endswith(second + "/features"):
            yield [], "second-features"
        else:
            raise AssertionError(url)

    rows = list(module.membership_features(SimpleNamespace(pages=pages), project))
    assert [row for page, _ in rows for row in page] == [
        {"name": first + "/features/configmanagement", "lifecycleState": {"state": "ACTIVE"}}]
    assert [receipt for _, receipt in rows] == ["memberships", "first-features", "second-features"]
    assert calls[0][0] == "https://gkehub.googleapis.com/v1/" + project + "/locations/-/memberships"
    assert calls[1][0] == "https://gkehub.googleapis.com/v2/" + first + "/features"


def test_rejects_feature_outside_queried_membership():
    module = catalog()
    project = "projects/demo-project1"
    member = project + "/locations/global/memberships/one"

    def pages(url, scope, **kwargs):
        if url.endswith("/locations/-/memberships"):
            yield [{"name": member}], "memberships"
        else:
            yield [{"name": project + "/locations/global/memberships/other/features/configmanagement"}], "features"

    try:
        list(module.membership_features(SimpleNamespace(pages=pages), project))
    except module.ReadError:
        return
    raise AssertionError("a feature from another membership was accepted")


def test_numeric_project_name_requires_collected_alias_binding():
    module = catalog()
    project = "projects/demo-project1"
    member = "projects/123456789/locations/global/memberships/one"

    def pages(url, scope, **kwargs):
        if url.endswith("/locations/-/memberships"):
            yield [{"name": member}], "memberships"
        else:
            yield [{"name": member + "/features/configmanagement"}], "features"

    binding = lambda scope, require_alias: {
        "project_id": "demo-project1", "project_number": "123456789",
        "source_requests": ["project-identity"]}
    collector = SimpleNamespace(pages=pages, _data_project_binding=binding)
    rows = list(module.membership_features(collector, project))
    assert [receipt for _, receipt in rows] == ["memberships", "project-identity", "features"]
    assert [row["name"] for page, _ in rows for row in page] == [
        member + "/features/configmanagement"]
