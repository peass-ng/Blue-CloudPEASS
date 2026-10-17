"""Cluster-scoped MSK upgrade facts must not use a global version maximum."""
import copy

import pytest

from peaso.checks import CHECKS
from peaso.checks import claude_aws_b_messaging as messaging
from peaso.checks.claude_aws_b_common import indexes, inventory
from peaso.collectors import aws_facts_cb_ca as facts


CHECK = next(check for check in CHECKS if check.id == "aws.cb.kafka.latest_version")
ARN = messaging.MSK_ARN


def cluster(version="3.7.x", instance="kafka.m5.large"):
    item = messaging._msk(CurrentBrokerSoftwareInfo={"KafkaVersion": version})
    if instance is not None:
        item["Provisioned"]["BrokerNodeGroupInfo"] = {"InstanceType": instance}
    return item


def evidence(current="3.7.x", targets=(), *, versions=None, response_status="collected"):
    versions = versions or [("3.7.x", "ACTIVE"), ("3.9.x", "ACTIVE"), ("4.2.x", "ACTIVE")]
    return indexes(
        inventory("kafka_version", [{"Version": version, "Status": state} for version, state in versions]),
        inventory("msk_compatible_version", [{"ClusterArn": ARN, "CompatibleVersions": {
            "collection_status": response_status,
            **({"items": [{"SourceVersion": current, "TargetVersions": list(targets)}]} if response_status == "collected" else {}),
        }}]),
    )


def evaluate(item, index):
    before = copy.deepcopy((item, index))
    outcome = CHECK.evaluate(item, index)
    assert (item, index) == before
    return outcome


def test_standard_current_passes_despite_express_only_global_maximum():
    status, detail = evaluate(cluster(), evidence())
    assert status == "PASS"
    assert detail["broker_type"] == "STANDARD"
    assert detail["compatible_active_targets"] == []
    assert "cluster-specific" in detail["assessment"]


def test_standard_and_express_fail_only_for_their_returned_active_targets():
    standard, standard_detail = evaluate(cluster(), evidence(targets=["3.9.x"]))
    express, express_detail = evaluate(cluster("3.9.x", "express.m7g.large"), evidence("3.9.x", ["4.2.x"]))
    assert standard == express == "FAIL"
    assert standard_detail["compatible_active_targets"] == ["3.9.x"]
    assert express_detail["broker_type"] == "EXPRESS"
    assert express_detail["compatible_active_targets"] == ["4.2.x"]


def test_unordered_global_version_list_does_not_change_outcome():
    index = evidence(targets=["3.9.x"])
    index["kafka_version"].reverse()
    assert evaluate(cluster(), index)[0] == "FAIL"


def test_newer_uses_numeric_components_not_lexical_order():
    index = evidence(current="3.9.x", targets=["3.10.x"], versions=[("3.7.x", "ACTIVE"),
                                                                    ("3.9.x", "ACTIVE"), ("3.10.x", "ACTIVE")])
    status, detail = evaluate(cluster("3.9.x"), index)
    assert status == "FAIL"
    assert detail["compatible_active_targets"] == ["3.10.x"]


@pytest.mark.parametrize("target", ["3.7.x", "3.9.x.kraft", "3.9.1", "release-4"])
def test_older_or_incomparable_active_target_cannot_prove_newer_update(target):
    index = evidence(current="3.9.x", targets=[target], versions=[("3.7.x", "ACTIVE"), ("3.9.x", "ACTIVE"),
                                                                ("3.9.x.kraft", "ACTIVE"), ("3.9.1", "ACTIVE"),
                                                                ("release-4", "ACTIVE")])
    assert evaluate(cluster("3.9.x"), index)[0] == "UNKNOWN"


def test_inconsistent_older_target_does_not_hide_behind_newer_target():
    index = evidence(current="3.9.x", targets=["3.10.x", "3.7.x"], versions=[("3.7.x", "ACTIVE"),
                                                                                  ("3.9.x", "ACTIVE"), ("3.10.x", "ACTIVE")])
    assert evaluate(cluster("3.9.x"), index)[0] == "UNKNOWN"


def test_deprecated_current_fails_without_guessing_a_target():
    index = evidence(response_status="denied", versions=[("3.7.x", "DEPRECATED"), ("4.2.x", "ACTIVE")])
    status, detail = evaluate(cluster(instance=None), index)
    assert status == "FAIL"
    assert detail["version_status"] == "DEPRECATED"
    assert "latest" not in str(detail).lower()


@pytest.mark.parametrize("item,index", [
    (cluster(instance=None), evidence()),
    (cluster(instance="mystery.large"), evidence()),
    (cluster(), evidence(response_status="denied")),
    (cluster(), evidence(current="2.8.1", targets=["3.9.x"])),
    (cluster(), evidence(targets=["5.0.x"])),
    (cluster(), evidence(versions=[("3.7.x", "UNKNOWN")])),
])
def test_missing_broker_upgrade_or_version_status_is_unknown(item, index):
    assert evaluate(item, index)[0] == "UNKNOWN"


def test_empty_compatible_targets_only_pass_with_complete_matching_source():
    index = evidence()
    assert evaluate(cluster(), index)[0] == "PASS"
    index["msk_compatible_version"][0]["data"]["CompatibleVersions"]["items"] = []
    assert evaluate(cluster(), index)[0] == "UNKNOWN"
    index = evidence()
    del index["msk_compatible_version"][0]["data"]["CompatibleVersions"]["items"][0]["TargetVersions"]
    assert evaluate(cluster(), index)[0] == "UNKNOWN"


def test_malformed_or_denied_collection_and_duplicate_cluster_rows_are_unknown():
    index = evidence()
    index["collections"]["msk_compatible_version"][0]["status"] = "denied"
    assert evaluate(cluster(), index)[0] == "UNKNOWN"
    index = evidence()
    index["msk_compatible_version"].append(copy.deepcopy(index["msk_compatible_version"][0]))
    assert evaluate(cluster(), index)[0] == "UNKNOWN"
    index = evidence()
    index["msk_compatible_version"][0]["data"]["CompatibleVersions"]["items"][0]["TargetVersions"] = [None]
    assert evaluate(cluster(), index)[0] == "UNKNOWN"


def test_serverless_is_outside_the_provisioned_version_predicate():
    assert evaluate(messaging.SERVERLESS, {})[0] == "NOT_APPLICABLE"


class FakeReads:
    def __init__(self, clusters, responses, status="collected"):
        self.clusters, self.responses, self.status = clusters, responses, status
        self.calls = []

    def pages(self, session, service, region, operation, expression):
        self.calls.append((operation, None))
        assert (service, operation, expression) == ("kafka", "list_clusters_v2", "ClusterInfoList")
        return facts._result(self.clusters, self.status)

    def detail(self, session, service, region, operation, **arguments):
        arn = arguments["ClusterArn"]
        self.calls.append((operation, arn))
        assert (service, operation) == ("kafka", "get_compatible_kafka_versions")
        return self.responses[arn]


def test_collector_reads_once_per_provisioned_arn_and_skips_serverless():
    second = ARN.replace("/1", "/2")
    reads = FakeReads(
        [{"ClusterArn": ARN, "ClusterType": "PROVISIONED"},
         {"ClusterArn": second, "ClusterType": "PROVISIONED"},
         {"ClusterArn": "serverless", "ClusterType": "SERVERLESS"}],
        {ARN: {"collection_status": "collected", "CompatibleKafkaVersions": [{"SourceVersion": "3.7.x", "TargetVersions": ["3.9.x"]}]},
         second: {"collection_status": "denied", "error": {"code": "AccessDeniedException"}}},
    )
    result = facts.FETCHERS["msk_compatible_version"](reads, object(), "us-east-1", "111111111111")
    assert result.status == "collected" and len(result.items) == 2
    assert reads.calls == [("list_clusters_v2", None), ("get_compatible_kafka_versions", ARN),
                           ("get_compatible_kafka_versions", second)]
    assert result.items[0]["CompatibleVersions"]["items"][0]["TargetVersions"] == ["3.9.x"]
    assert result.items[1]["CompatibleVersions"]["collection_status"] == "denied"
    assert ("kafka", "get_compatible_kafka_versions") in facts.READ_ACTIONS
    assert "msk_compatible_version" in CHECK.declared_dependencies


def test_collector_rejects_incomplete_list_or_malformed_compatibility():
    listed = [{"ClusterArn": ARN, "ClusterType": "PROVISIONED"}]
    denied = FakeReads(listed, {}, "denied")
    assert facts.FETCHERS["msk_compatible_version"](denied, object(), "us-east-1", "111111111111").status == "denied"
    assert denied.calls == [("list_clusters_v2", None)]
    malformed = FakeReads(listed, {ARN: {"collection_status": "collected", "CompatibleKafkaVersions": {}}})
    result = facts.FETCHERS["msk_compatible_version"](malformed, object(), "us-east-1", "111111111111")
    assert result.items[0]["CompatibleVersions"]["collection_status"] == "malformed"
