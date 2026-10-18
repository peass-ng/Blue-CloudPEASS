"""Pub/Sub Topic list completeness is per item, not a claim about the whole inventory."""
from peaso.checks.facts import full_representation
from peaso.collectors import gcp
from tests.test_peaso_collectors_gcp import collection, snapshot


def test_topics_list_marks_complete_topic_after_pagination_and_iam_hydration():
    urls = []

    def resolve(request):
        urls.append(request["url"])
        if request["url"].endswith(":getIamPolicy"):
            return {"bindings": []}
        assert request["url"] == "https://pubsub.googleapis.com/v1/projects/p-one/topics"
        if request["params"].get("pageToken") == "next":
            return {"topics": [{"name": "projects/p-one/topics/second",
                                "kmsKeyName": "projects/p-one/locations/global/keyRings/r/cryptoKeys/k"}]}
        return {"topics": [{"name": "projects/p-one/topics/default",
                            "_representation": "partial"}], "nextPageToken": "next"}

    result, transport = snapshot(["pubsub_topic"], resolve)
    topics = collection(result, "pubsub_topic")
    assert topics["status"] == "collected" and len(topics["items"]) == 2
    assert transport.calls == 4
    assert sum(url.endswith(":getIamPolicy") for url in urls) == 2
    by_name = {item["name"]: item for item in topics["items"]}
    default = by_name["projects/p-one/topics/default"]
    assert "kmsKeyName" not in default and full_representation(default)
    assert default["_coverage"]["iamPolicy"]["status"] == "collected"
    assert default["_provenance"]["representation"] == "full"
    assert "_representation" not in default


def test_denied_or_incomplete_topic_list_cannot_be_read_as_complete_inventory():
    def denied(request):
        raise gcp.ReadError("denied", "api_error", http_status=403)

    unavailable = collection(snapshot(["pubsub_topic"], denied)[0], "pubsub_topic")
    assert unavailable["status"] == "denied" and not unavailable["items"]

    def partial(request):
        if request["url"].endswith(":getIamPolicy"):
            return {"bindings": []}
        return {"topics": [{"name": "projects/p-one/topics/seen"}],
                "warning": {"code": "PARTIAL_RESULTS"}}

    incomplete = collection(snapshot(["pubsub_topic"], partial)[0], "pubsub_topic")
    assert incomplete["status"] != "collected"
    assert incomplete["coverage_status"] not in ("collected", "empty")
