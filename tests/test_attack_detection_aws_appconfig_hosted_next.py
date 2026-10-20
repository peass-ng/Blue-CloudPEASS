"""Synthetic derivatives of the owned AppConfig hosted configuration lab."""

from copy import deepcopy

from peaso.attack_detection import detect_aws_events
from peaso.attack_detection.rules import load_rules


ACCOUNT = "999999999999"
APP, PROFILE, ENV = "a12345", "p12345", "e12345"
CREATOR = f"arn:aws:sts::{ACCOUNT}:assumed-role/synthetic-version-writer/session"
DEPLOYER = f"arn:aws:iam::{ACCOUNT}:user/synthetic-deployer"
READER = f"arn:aws:sts::{ACCOUNT}:assumed-role/synthetic-reader/session"
CONTENT = "SYNTHETIC_HOSTED_CONTENT_NEVER_EMIT"
IDS = {"d7b325a5-49a6-430e-8ea8-8371468919fb",
       "7d3e2b61-b2e3-4212-ae6d-acc713529e55",
       "1e519668-048c-43ab-ae4c-3842d9d60f78",
       "09efd5cd-2e3a-43bb-8a80-43af2e8dbb2d"}


def selected():
    return [r for r in load_rules(product="aws") if r.id in IDS]


def event(name, minute, actor, request, response=None, read_only=False):
    return {"eventSource": "appconfig.amazonaws.com", "eventName": name,
            "eventCategory": "Management", "eventType": "AwsApiCall",
            "managementEvent": True, "readOnly": read_only,
            "recipientAccountId": ACCOUNT, "awsRegion": "us-east-1",
            "userIdentity": {"arn": actor, "accountId": ACCOUNT},
            "eventID": "synthetic-" + name + "-" + str(minute),
            "eventTime": f"2026-10-20T13:{minute:02d}:00Z",
            "requestParameters": request, "responseElements": response}


def events():
    create = event("CreateHostedConfigurationVersion", 10, CREATOR,
        {"applicationId": APP, "configurationProfileId": PROFILE,
         "contentType": "text/plain", "content": CONTENT},
        {"applicationId": APP, "configurationProfileId": PROFILE,
         "content": CONTENT, "versionNumber": 2})
    deploy = event("StartDeployment", 11, DEPLOYER,
        {"applicationId": APP, "configurationProfileId": PROFILE,
         "environmentId": ENV, "configurationVersion": "2"},
        {"applicationId": APP, "configurationProfileId": PROFILE,
         "environmentId": ENV, "configurationVersion": "2", "state": "COMPLETE"})
    old_read = event("GetHostedConfigurationVersion", 12, READER,
        {"applicationId": APP, "configurationProfileId": PROFILE,
         "versionNumber": 1}, None, read_only=True)
    return [create, deploy, old_read]


def data_events():
    arn = (f"arn:aws:appconfig:us-east-1:{ACCOUNT}:application/{APP}"
           f"/environment/{ENV}/configuration/{PROFILE}")
    resource = [{"accountId": ACCOUNT, "type": "AWS::AppConfig::Configuration", "ARN": arn}]
    start = {"eventSource": "appconfig.amazonaws.com",
             "eventName": "StartConfigurationSession", "eventCategory": "Data",
             "eventType": "AwsApiCall", "managementEvent": False, "readOnly": False,
             "recipientAccountId": ACCOUNT, "awsRegion": "us-east-1",
             "userIdentity": {"arn": READER, "accountId": ACCOUNT},
             "eventID": "synthetic-data-session", "eventTime": "2026-10-20T13:20:00Z",
             "resources": resource,
             "requestParameters": {"applicationIdentifier": APP,
                                   "environmentIdentifier": ENV,
                                   "configurationProfileIdentifier": PROFILE},
             "responseElements": None}
    get = deepcopy(start)
    get.update({"eventName": "GetLatestConfiguration", "readOnly": True,
                "eventID": "synthetic-data-get", "eventTime": "2026-10-20T13:21:00Z",
                "requestParameters": {"configurationToken": "HIDDEN_DUE_TO_SECURITY_REASONS"}})
    return [start, get]


def rollback_events():
    prior = event("StartDeployment", 14, DEPLOYER,
        {"applicationId": APP, "configurationProfileId": PROFILE,
         "environmentId": ENV, "configurationVersion": "2"},
        {"applicationId": APP, "configurationProfileId": PROFILE,
         "environmentId": ENV, "configurationVersion": "2", "state": "COMPLETE"})
    rollback = event("StartDeployment", 15, DEPLOYER,
        {"applicationId": APP, "configurationProfileId": PROFILE,
         "environmentId": ENV, "configurationVersion": "1"},
        {"applicationId": APP, "configurationProfileId": PROFILE,
         "environmentId": ENV, "configurationVersion": "1", "state": "COMPLETE"})
    return [prior, rollback]


def test_live_shape_cross_actor_deployment_and_prior_read():
    hits = detect_aws_events(events() + data_events(), selected())
    assert len(hits) == len({h.rule_id for h in hits}) == 3
    assert {h.rule_id for h in hits} == IDS - {"09efd5cd-2e3a-43bb-8a80-43af2e8dbb2d"}
    assert CONTENT not in repr(hits)
    assert "HIDDEN_DUE_TO_SECURITY_REASONS" not in repr(hits)


def test_management_correlations_standalone():
    hits = detect_aws_events(events(), selected())
    assert len(hits) == len({h.rule_id for h in hits}) == 2
    assert {h.rule_id for h in hits} == IDS - {"1e519668-048c-43ab-ae4c-3842d9d60f78",
                                               "09efd5cd-2e3a-43bb-8a80-43af2e8dbb2d"}
    assert CONTENT not in repr(hits)


def test_wrong_version_identity_and_response_do_not_join():
    baseline = events()
    changes = [
        (0, ("responseElements", "versionNumber"), 3, 1),
        (0, ("userIdentity", "arn"), DEPLOYER, 1),
        (0, ("errorCode",), "AccessDeniedException", 1),
        (1, ("requestParameters", "configurationProfileId"), "other", 0),
        (1, ("requestParameters", "configurationVersion"), "3", 0),
        (1, ("responseElements", "state"), "ROLLED_BACK", 0),
        (1, ("userIdentity", "arn"), READER, 1),
        (2, ("requestParameters", "versionNumber"), 2, 1),
        (2, ("readOnly",), False, 1),
    ]
    for index, path, value, count in changes:
        records = deepcopy(baseline)
        current = records[index]
        for key in path[:-1]:
            current = current[key]
        current[path[-1]] = value
        assert len(detect_aws_events(records, selected())) == count, (index, path)


def test_missing_history_cross_account_and_out_of_window():
    baseline = events()
    assert not detect_aws_events([baseline[2]], selected())
    records = deepcopy(baseline)
    records[0]["recipientAccountId"] = "888888888888"
    assert len(detect_aws_events(records, selected())) == 1
    records = deepcopy(baseline)
    records[2]["eventTime"] = "2026-10-22T13:12:00Z"
    assert len(detect_aws_events(records, selected())) == 1


def test_data_chain_requires_same_configuration_actor_and_window():
    baseline = data_events()
    assert len(detect_aws_events(baseline, selected())) == 1
    variants = [
        (0, ("requestParameters", "environmentIdentifier"), "other"),
        (0, ("eventCategory",), "Management"),
        (0, ("managementEvent",), True),
        (0, ("errorCode",), "AccessDeniedException"),
        (1, ("userIdentity", "arn"), DEPLOYER),
        (1, ("resources", 0, "ARN"),
             f"arn:aws:appconfig:us-east-1:{ACCOUNT}:application/{APP}/environment/{ENV}/configuration/other"),
        (1, ("requestParameters", "configurationToken"), ""),
        (1, ("readOnly",), False),
        (1, ("eventTime",), "2026-10-20T13:30:00Z"),
    ]
    for index, path, value in variants:
        changed = deepcopy(baseline)
        current = changed[index]
        for key in path[:-1]:
            current = current[key]
        current[path[-1]] = value
        assert not detect_aws_events(changed, selected()), (index, path)


def test_rollback_requires_completed_newer_version_same_environment():
    baseline = rollback_events()
    assert [h.rule_id for h in detect_aws_events(baseline, selected())] == [
        "09efd5cd-2e3a-43bb-8a80-43af2e8dbb2d"]
    for index, path, value in [
        (0, ("responseElements", "state"), "DEPLOYING"),
        (0, ("requestParameters", "environmentId"), "other"),
        (1, ("requestParameters", "configurationVersion"), "2"),
        (1, ("eventTime",), "2026-10-19T13:15:00Z"),
        (1, ("errorCode",), "AccessDeniedException"),
    ]:
        changed = deepcopy(baseline)
        current = changed[index]
        for key in path[:-1]:
            current = current[key]
        current[path[-1]] = value
        assert not detect_aws_events(changed, selected()), (index, path)
