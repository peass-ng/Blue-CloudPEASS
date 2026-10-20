"""Offline native SQL Admin examples; runnable directly without pytest's runner."""
from copy import deepcopy


from peaso.checks import CHECKS
from peaso.checks.gcp_sql_transport_native import CHECK_IDS, sql_transport


def instance(config, version="POSTGRES_16"):
    return {"kind": "sql#instance", "name": "transport-db", "project": "p-one",
            "databaseVersion": version, "settings": {"ipConfiguration": config}}


def verdict(row, expected):
    before = deepcopy(row)
    status, evidence = sql_transport(row, {})
    assert status == expected, (row, status, evidence)
    assert row == before
    return evidence


def test_all_documented_engine_mode_pairs():
    for version in ("MYSQL_8_0", "POSTGRES_16", "SQLSERVER_2019_STANDARD"):
        for mode, expected in (("ENCRYPTED_ONLY", "PASS"),
                               ("ALLOW_UNENCRYPTED_AND_ENCRYPTED", "FAIL")):
            for config in ({"sslMode": mode}, {"sslMode": mode, "requireSsl":
                    mode == "ENCRYPTED_ONLY" and version.startswith("SQLSERVER_")}):
                verdict(instance(config, version), expected)
    for version in ("MYSQL_8_0", "POSTGRES_16"):
        for config in ({"sslMode": "TRUSTED_CLIENT_CERTIFICATE_REQUIRED"},
                       {"sslMode": "TRUSTED_CLIENT_CERTIFICATE_REQUIRED", "requireSsl": True}):
            verdict(instance(config, version), "PASS")


def test_legacy_boolean_is_not_client_certificate_requirement():
    for version in ("MYSQL_8_0", "POSTGRES_16", "SQLSERVER_2019_STANDARD"):
        for legacy, expected in ((True, "PASS"), (False, "FAIL")):
            for config in ({"requireSsl": legacy},
                           {"sslMode": "SSL_MODE_UNSPECIFIED", "requireSsl": legacy}):
                evidence = verdict(instance(config, version), expected)
                assert evidence["deciding_field"] == "settings.ipConfiguration.requireSsl"
    # ENCRYPTED_ONLY + requireSsl=false is documented for MySQL/PostgreSQL.
    assert verdict(instance({"sslMode": "ENCRYPTED_ONLY", "requireSsl": False}),
                   "PASS")["deciding_field"] == "settings.ipConfiguration.sslMode"


def test_unsupported_and_conflicting_declarations_are_unknown():
    verdict(instance({"sslMode": "TRUSTED_CLIENT_CERTIFICATE_REQUIRED"},
                     "SQLSERVER_2019_STANDARD"), "UNKNOWN")
    row = instance({"sslMode": "TRUSTED_CLIENT_CERTIFICATE_REQUIRED"})
    del row["databaseVersion"]
    verdict(row, "UNKNOWN")
    for version, config in (
        ("POSTGRES_16", {"sslMode": "ENCRYPTED_ONLY", "requireSsl": True}),
        ("SQLSERVER_2019_STANDARD", {"sslMode": "ENCRYPTED_ONLY", "requireSsl": False}),
        ("MYSQL_8_0", {"sslMode": "TRUSTED_CLIENT_CERTIFICATE_REQUIRED", "requireSsl": False}),
        ("POSTGRES_16", {"sslMode": "ALLOW_UNENCRYPTED_AND_ENCRYPTED", "requireSsl": True}),
        ("FUTURE_ENGINE_1", {"sslMode": "ENCRYPTED_ONLY"}),
    ):
        verdict(instance(config, version), "UNKNOWN")


def test_missing_malformed_denied_and_unknown_values():
    for config in ({}, {"sslMode": "SSL_MODE_UNSPECIFIED"},
                   {"sslMode": "FUTURE_MODE", "requireSsl": True},
                   {"sslMode": None}, {"sslMode": 1}, {"requireSsl": "false"},
                   {"requireSsl": 0}, {"requireSsl": None},
                   {"sslMode": "ENCRYPTED_ONLY", "requireSsl": "true"},
                   {"sslMode": "ENCRYPTED_ONLY", "_coverage": {"sslMode": {"status": "denied"}}}):
        verdict(instance(config), "UNKNOWN")
    for row in ({}, {"settings": {}}, {"settings": {"ipConfiguration": None}}, None,
                {"settings": {"ipConfiguration": {}}, "collection_status": "partial"}):
        verdict(row, "UNKNOWN")
    row = instance({"sslMode": "ENCRYPTED_ONLY"})
    row["_coverage"] = {"settings": {"status": "denied"}}
    verdict(row, "UNKNOWN")


def test_generic_explicit_modes_need_no_fabricated_engine():
    for mode, expected in (("ENCRYPTED_ONLY", "PASS"),
                           ("ALLOW_UNENCRYPTED_AND_ENCRYPTED", "FAIL")):
        row = instance({"sslMode": mode})
        del row["databaseVersion"]
        verdict(row, expected)


def test_native_collector_projection_and_engine_evaluation():
    from peaso.engine import evaluate_snapshot
    from tests.test_peaso_collectors_gcp import collection, snapshot

    examples = [
        (instance({"sslMode": "ENCRYPTED_ONLY", "requireSsl": False}), "PASS"),
        (instance({"sslMode": "ALLOW_UNENCRYPTED_AND_ENCRYPTED", "requireSsl": False}), "FAIL"),
        (instance({"sslMode": "TRUSTED_CLIENT_CERTIFICATE_REQUIRED", "requireSsl": True}), "PASS"),
        (instance({"sslMode": "TRUSTED_CLIENT_CERTIFICATE_REQUIRED"}, "SQLSERVER_2019_STANDARD"), "UNKNOWN"),
        (instance({}), "UNKNOWN"),
        (instance({"requireSsl": True}), "PASS"),
    ]
    for row, expected in examples:
        def resolve(request):
            if request["url"].endswith("/instances"):
                return {"kind": "sql#instancesList", "items": [deepcopy(row)]}
            assert request["url"].endswith("/transport-db/users")
            return {"kind": "sql#usersList", "items": []}
        captured, transport = snapshot(["sql_instance"], resolve)
        projected = collection(captured, "sql_instance")["items"][0]
        assert projected["settings"] == row["settings"]
        assert projected["databaseVersion"] == row["databaseVersion"]
        findings = evaluate_snapshot(captured, checks=list(CHECK_IDS))["findings"]
        assert len(findings) == 2
        assert {finding["status"] for finding in findings} == {expected}
        assert len(transport.requests) == 2
        assert {request["method"] for request in transport.requests} == {"GET"}


if __name__ == "__main__":
    tests = [value for name, value in list(globals().items()) if name.startswith("test_")]
    for test in tests:
        test()
    print(f"{len(tests)} direct SQL transport tests passed")
