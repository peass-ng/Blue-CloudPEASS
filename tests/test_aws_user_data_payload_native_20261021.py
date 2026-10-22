"""Actual installed EC2 response projector; all payloads are inert fixtures."""
import base64
import gzip
import importlib.util
from pathlib import Path
import sys

import pytest

from tests.test_aws_user_data_payload_20261021 import multipart
from peaso.collectors import aws

project = aws._project_user_data_indicators
INSTANCE = 'i-0123456789abcdef0'


def response(raw):
    return {'InstanceId': INSTANCE, 'UserData': {'Value': base64.b64encode(raw).decode()}}


def test_plain_and_absent_native_responses_are_unchanged():
    for value in ({'InstanceId': INSTANCE}, response(b'#!/bin/sh\necho ordinary')):
        observed = project(value, INSTANCE)
        assert observed['InstanceId'] == INSTANCE
        assert observed['UserDataIndicators'] == {'KeywordMatch':False,'PasswordShapeMatch':False,'Present':'UserData' in value}
        assert observed['UserDataSecretIndicators']['HighConfidenceSecretPresent'] is False


@pytest.mark.parametrize('encoded', [False, True])
def test_gzip_mime_literal_reaches_existing_native_secret_indicator(encoded):
    text = b'password="SyntheticPassword907!"\n'
    payload = gzip.compress(text)
    if encoded:
        payload = multipart([b'Content-Type: application/gzip\r\nContent-Transfer-Encoding: base64\r\n\r\n'
                             + base64.b64encode(payload)])
    observed = project(response(payload), INSTANCE)
    assert observed['UserDataSecretIndicators']['HighConfidenceSecretPresent'] is True
    assert observed['UserDataSecretIndicators']['MatchedCategories'] == ['password_assignment']
    assert 'SyntheticPassword907!' not in repr(observed)


@pytest.mark.parametrize('wire', [b'\x1f\x8bmalformed', gzip.compress(b'x', mtime=0)[:-1],
    multipart([b'Content-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n\r\n@@@'])])
def test_bad_payload_uses_existing_readfailure_boundary(wire):
    with pytest.raises(aws.ReadFailure):
        project(response(wire), INSTANCE)


def test_foreign_instance_is_rejected_before_decoding():
    with pytest.raises(aws.ReadFailure):
        project(response(gzip.compress(b'ordinary')), 'i-fffffffffffffffff')


def test_actual_pinned_dual_engines_find_one_synthetic_mime_secret():
    token = 'ghp_' + '7mQ2zR9wL4cV8nK1sF6aH3jP5uD0xB2yE9rT'
    body = multipart([b'Content-Type: text/x-shellscript\r\nContent-Transfer-Encoding: base64\r\n\r\n'
        + base64.b64encode(('github_token=' + token).encode())])
    observed = project(response(gzip.compress(body)), INSTANCE, dual_scanner=True)
    scan = observed['UserDataSecretIndicators']['ContentScan']
    assert scan['complete'] is True
    assert len(scan['leaks']) == 1
    assert {entry['engine'] for entry in scan['leaks'][0]['detectors']} == {'kingfisher', 'trufflehog'}
    assert token not in repr(observed)
