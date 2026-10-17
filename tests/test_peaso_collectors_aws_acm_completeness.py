"""Offline ACM inventory fixtures for the explicit full-filter read contract."""

from types import SimpleNamespace
from datetime import datetime, timezone

import botocore.session
import pytest
import boto3
from botocore.stub import Stubber

from peaso.collectors import aws, aws_b_services as acm


def _shape(*, statuses=acm._ACM_STATUSES, origins=acm._ACM_ORIGINS,
           key_types=acm._ACM_KEY_TYPES):
    def enum(values):
        return SimpleNamespace(member=SimpleNamespace(metadata={"enum": values}))

    includes = SimpleNamespace(members={"keyTypes": enum(key_types)})
    members = {"CertificateStatuses": enum(statuses), "CertificateKeyPairOrigins": enum(origins),
               "Includes": includes}
    return SimpleNamespace(input_shape=SimpleNamespace(members=members))


class Requests:
    def __init__(self, model, read=None):
        self.model = model
        self.read = read or aws.ReadResult([{"CertificateArn": "arn:aws:acm:eu-west-1:123456789012:certificate/a",
                                             "CertificateKeyPairOrigin": "ACME"}])
        self.calls = []

    def client(self, session, service, region):
        assert service == "acm" and region == "eu-west-1"
        return SimpleNamespace(meta=SimpleNamespace(service_model=SimpleNamespace(
            operation_model=lambda operation: self.model)))

    def pages(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        return self.read


def test_registered_dispatch_keeps_read_guard_and_full_filters():
    assert "acm_certificate" in aws.AWS_TYPES
    assert aws.SPECS["acm_certificate"] == ("acm", "list_certificates", "CertificateSummaryList")
    assert aws.FETCHERS["acm_certificate"] is acm._acm_certificates
    assert ("acm", "list_certificates") in aws.READ_ACTIONS
    assert ("acm", "describe_certificate") in aws.READ_ACTIONS
    requests = Requests(_shape())
    result = aws.FETCHERS["acm_certificate"](requests, object(), "eu-west-1", "123456789012")
    assert result.status == "collected" and len(requests.calls) == 1
    args, kwargs = requests.calls[0]
    assert args[1:5] == ("acm", "eu-west-1", "list_certificates", "CertificateSummaryList")
    assert kwargs == {"CertificateStatuses": list(acm._ACM_STATUSES),
                      "CertificateKeyPairOrigins": list(acm._ACM_ORIGINS),
                      "Includes": {"keyTypes": list(acm._ACM_KEY_TYPES)}}
    with pytest.raises(aws.ReadFailure) as failure:
        aws.Requests({}).call(object(), "acm", "eu-west-1", "delete_certificate",
                              CertificateArn="arn:aws:acm:eu-west-1:123456789012:certificate/a")
    assert failure.value.code == "non_read_operation"


def test_old_sdk_model_never_silently_returns_partial_default_inventory():
    model = botocore.session.get_session().get_service_model("acm").operation_model("ListCertificates")
    if "CertificateKeyPairOrigins" in model.input_shape.members:
        # CI's reviewed SDK floor has the field; exercise the older model shape explicitly.
        members = dict(model.input_shape.members)
        del members["CertificateKeyPairOrigins"]
        model = SimpleNamespace(input_shape=SimpleNamespace(members=members))
    requests = Requests(model)
    result = acm._acm_certificates(requests, object(), "eu-west-1", "123456789012")
    assert (result.status, result.error) == ("not_collected", {"code": "acm_complete_filter_unsupported_sdk"})
    assert requests.calls == []


def test_unreviewed_filter_enum_fails_closed_before_provider_read():
    requests = Requests(_shape(origins=(*acm._ACM_ORIGINS, "FUTURE_ORIGIN")))
    result = acm._acm_certificates(requests, object(), "eu-west-1", "123456789012")
    assert (result.status, result.error) == ("not_collected", {"code": "acm_filter_enum_unreviewed"})
    assert requests.calls == []


def test_partial_paging_and_unknown_response_origin_stay_incomplete():
    row = {"CertificateArn": "arn:aws:acm:eu-west-1:123456789012:certificate/a",
           "CertificateKeyPairOrigin": "ACME"}
    partial = Requests(_shape(), aws.ReadResult([row], "partial", {"code": "page_limit"}))
    result = acm._acm_certificates(partial, object(), "eu-west-1", "123456789012")
    assert result.status == "partial" and result.error == {"code": "page_limit"}
    future = Requests(_shape(), aws.ReadResult([{**row, "CertificateKeyPairOrigin": "FUTURE"}]))
    result = acm._acm_certificates(future, object(), "eu-west-1", "123456789012")
    assert (result.status, result.error) == ("partial", {"code": "acm_unreviewed_origin_response"})


def test_existing_detail_enricher_runs_once_for_listed_certificate():
    arn = "arn:aws:acm:eu-west-1:123456789012:certificate/a"

    class DetailRequests:
        calls = []

        def detail(self, session, service, region, operation, **kwargs):
            self.calls.append((service, operation, kwargs))
            return {"collection_status": "collected", "Certificate": {"CertificateArn": arn,
                    "Status": "ISSUED", "NotAfter": "2026-12-01T00:00:00Z"}}

    requests = DetailRequests()
    result = aws.ENRICHERS["acm_certificate"](requests, object(), "eu-west-1", [{"CertificateArn": arn}])
    assert result[0]["Certificate"]["Certificate"]["Status"] == "ISSUED"
    assert requests.calls == [("acm", "describe_certificate", {"CertificateArn": arn})]


def _real_requests(monkeypatch, *, max_calls=3):
    session = boto3.Session(aws_access_key_id="inert", aws_secret_access_key="inert",
                            region_name="eu-west-1")
    client = session.client("acm", region_name="eu-west-1")
    monkeypatch.setattr(aws.Requests, "client", lambda self, _session, service, region: client)
    return session, client, aws.Requests({"max_calls": max_calls, "retry_attempts": 1})


def _filters():
    return {"CertificateStatuses": list(acm._ACM_STATUSES),
            "CertificateKeyPairOrigins": list(acm._ACM_ORIGINS),
            "Includes": {"keyTypes": list(acm._ACM_KEY_TYPES)}}


def test_real_botocore_two_pages_and_one_detail_under_read_budget(monkeypatch):
    session, client, requests = _real_requests(monkeypatch)
    model = client.meta.service_model.operation_model("ListCertificates")
    assert "CertificateKeyPairOrigins" in model.input_shape.members
    arn = "arn:aws:acm:eu-west-1:123456789012:certificate/11111111-1111-1111-1111-111111111111"
    summary = {"CertificateArn": arn, "DomainName": "example.invalid", "Status": "ISSUED",
               "CertificateKeyPairOrigin": "ACME"}
    with Stubber(client) as stub:
        stub.add_response("list_certificates", {"CertificateSummaryList": [summary], "NextToken": "page-2"}, _filters())
        stub.add_response("list_certificates", {"CertificateSummaryList": []},
                          {**_filters(), "NextToken": "page-2"})
        stub.add_response("describe_certificate", {"Certificate": {"CertificateArn": arn,
            "DomainName": "example.invalid", "Status": "ISSUED",
            "NotAfter": datetime(2026, 12, 1, tzinfo=timezone.utc)}}, {"CertificateArn": arn})
        read = aws.FETCHERS["acm_certificate"](requests, session, "eu-west-1", "123456789012")
        assert read.status == "collected" and read.items == [summary]
        enriched = aws.ENRICHERS["acm_certificate"](requests, session, "eu-west-1", read.items)
        assert enriched[0]["Certificate"]["Certificate"]["Status"] == "ISSUED"
        assert requests.calls == 3
        # The scan-local scheduler reuses the same complete paginated read.
        again = aws.FETCHERS["acm_certificate"](requests, session, "eu-west-1", "123456789012")
        assert again.status == "collected" and requests.calls == 3
        stub.assert_no_pending_responses()


@pytest.mark.parametrize("error_code", ["AccessDeniedException", "ValidationException"])
def test_real_botocore_denied_or_rejected_filter_never_becomes_empty(monkeypatch, error_code):
    session, client, requests = _real_requests(monkeypatch, max_calls=1)
    with Stubber(client) as stub:
        stub.add_client_error("list_certificates", error_code, expected_params=_filters())
        read = aws.FETCHERS["acm_certificate"](requests, session, "eu-west-1", "123456789012")
        assert read.status not in {"collected", "empty"}
        assert read.error and read.error["code"] == error_code
        stub.assert_no_pending_responses()
