"""Synthetic CloudTrail derivatives for EC2 Multi-Attach correlation."""

from copy import deepcopy

from peaso.attack_detection.aws_ebs_multiattach import correlate_aws_ebs_multiattach


ACCOUNT = "999999999999"
VOLUME = "vol-0123456789abcdef0"
FIRST = "i-0123456789abcdef0"
SECOND = "i-abcdef01234567890"


def event(name, instance, *, second=0):
    return {"eventSource": "ec2.amazonaws.com", "eventName": name,
            "eventCategory": "Management", "eventType": "AwsApiCall",
            "managementEvent": True, "readOnly": False,
            "recipientAccountId": ACCOUNT, "awsRegion": "us-east-2",
            "eventTime": f"2026-10-22T00:00:{second:02d}Z",
            "eventID": f"synthetic-{name}-{instance}-{second}",
            "userIdentity": {"type": "IAMUser", "arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic"},
            "requestParameters": {"volumeId": VOLUME, "instanceId": instance, "device": "/dev/sdf"},
            "responseElements": {"volumeId": VOLUME, "instanceId": instance,
                                 "status": "attaching" if name == "AttachVolume" else "detaching"}}


def test_two_accepted_attachments_to_distinct_instances():
    first, second = event("AttachVolume", FIRST), event("AttachVolume", SECOND, second=1)
    hits = correlate_aws_ebs_multiattach([second, first])
    assert len(hits) == 1
    assert hits[0]["target.id"] == VOLUME
    assert hits[0]["request.ebs_volume_attached_to_distinct_instances"] is True
    assert not correlate_aws_ebs_multiattach([first])
    assert not correlate_aws_ebs_multiattach([first, first])


def test_transfer_after_detach_is_not_reported():
    records = [event("AttachVolume", FIRST), event("DetachVolume", FIRST, second=1),
               event("AttachVolume", SECOND, second=2)]
    assert not correlate_aws_ebs_multiattach(records)


def test_target_account_region_outcome_and_response_must_match():
    first, second = event("AttachVolume", FIRST), event("AttachVolume", SECOND, second=1)
    for mutate in (
        lambda e: e.update(recipientAccountId="111111111111"),
        lambda e: e.update(awsRegion="us-west-2"),
        lambda e: e["requestParameters"].update(volumeId="vol-abcdef01234567890"),
        lambda e: e["responseElements"].update(instanceId=FIRST),
        lambda e: e.update(errorCode="VolumeInUse"),
        lambda e: e.update(readOnly=True),
    ):
        changed = deepcopy(second)
        mutate(changed)
        assert not correlate_aws_ebs_multiattach([first, changed])


def test_old_or_same_second_attachments_are_not_correlated():
    first, second = event("AttachVolume", FIRST), event("AttachVolume", SECOND, second=1)
    same = deepcopy(second)
    same["eventTime"] = first["eventTime"]
    assert not correlate_aws_ebs_multiattach([first, same])
    old = deepcopy(first)
    old["eventTime"] = "2026-10-21T23:00:00Z"
    assert not correlate_aws_ebs_multiattach([old, second])
