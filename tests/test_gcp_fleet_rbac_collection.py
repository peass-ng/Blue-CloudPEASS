"""Fleet RBAC inventory keeps exact membership and scope identities."""

from types import SimpleNamespace

from test_gcp_config_delivery_location import catalog

PROJECT = "projects/demo-project1"
MEMBER = PROJECT + "/locations/global/memberships/team-a"
SCOPE = PROJECT + "/locations/global/scopes/prod"


def test_member_binding_collection_uses_exact_membership_parent():
    module = catalog()
    plan = module.PRIVATE_SERVICES["fleet_member_rbac_binding"]
    urls = []

    def pages(url, scope, **kwargs):
        urls.append(url)
        if url.endswith("/memberships"):
            yield [{"name": MEMBER}], "members"
        else:
            assert url.endswith(MEMBER + "/rbacrolebindings")
            yield [{"name": MEMBER + "/rbacrolebindings/admin", "user": "operator@example.com",
                    "role": {"customRole": "platform-admin"}, "state": {"code": "READY"}}], "bindings"

    rows = list(module.inventory_pages(SimpleNamespace(pages=pages), PROJECT, plan,
                                      PROJECT + "/locations/global", "https://gkehub.googleapis.com/v1"))
    assert len(urls) == 2
    assert [row["name"] for page, _ in rows for row in page] == [
        MEMBER + "/rbacrolebindings/admin"]


def test_scope_membership_collection_binds_only_listed_members():
    module = catalog()
    urls = []

    def pages(url, scope, **kwargs):
        urls.append(url)
        if url.endswith("/scopes"):
            yield [{"name": SCOPE}], "scopes"
        elif url.endswith(SCOPE + ":listMemberships"):
            yield [{"name": MEMBER}], "members"
        else:
            raise AssertionError(url)

    rows = list(module.scope_members(SimpleNamespace(pages=pages), PROJECT))
    assert [row for page, _ in rows for row in page] == [{"scope": SCOPE, "membership": MEMBER}]
    assert urls == ["https://gkehub.googleapis.com/v1/" + PROJECT + "/locations/global/scopes",
                    "https://gkehub.googleapis.com/v1/" + SCOPE + ":listMemberships"]


def test_scope_member_outside_project_is_rejected():
    module = catalog()

    def pages(url, scope, **kwargs):
        if url.endswith("/scopes"):
            yield [{"name": SCOPE}], "scopes"
        else:
            yield [{"name": "projects/other/locations/global/memberships/team-a"}], "members"

    collector = SimpleNamespace(pages=pages, _data_project_binding=lambda *a, **k: {
        "project_id": "demo-project1", "project_number": "123456789", "source_requests": []})
    try:
        list(module.scope_members(collector, PROJECT))
    except module.ReadError:
        return
    raise AssertionError("a scope member from another project was accepted")
