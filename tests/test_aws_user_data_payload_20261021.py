import base64
import gzip
import importlib.util
from pathlib import Path

import pytest

PATH = Path(__file__).parents[1] / 'peaso/collectors/aws_user_data_payload_20261021.py'
spec = importlib.util.spec_from_file_location('userdata_decoding_proposal', PATH)
decoder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(decoder)


def multipart(parts):
    return (b'MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary="unit"\r\n\r\n'
        + b''.join(b'--unit\r\n' + part + b'\r\n' for part in parts) + b'--unit--\r\n')


@pytest.mark.parametrize('raw', [b'', b'#!/bin/sh\necho ordinary\n', b'#cloud-config\npackages: []\n',
                                  b'key=value\nContent-Type: within-script'])
def test_plain_text_is_preserved(raw):
    assert decoder.decoded_text(raw) == raw.decode()


def test_gzip_and_concatenated_members_decode_without_disk():
    assert decoder.decoded_text(gzip.compress(b'first')) == 'first'
    assert decoder.decoded_text(gzip.compress(b'first') + gzip.compress(b'second')) == 'firstsecond'


def test_compressed_content_can_exceed_native_wire_limit_with_bounded_expansion():
    raw = gzip.compress(b'x' * 20000)
    assert len(raw) < decoder.MAX_INPUT
    assert len(decoder.decoded_text(raw)) == 20000


def test_mime_all_encoded_parts_and_headers_reach_transient_text():
    body = multipart([
        b'Content-Type: text/x-shellscript\r\nContent-Transfer-Encoding: base64\r\n\r\n'
        + base64.b64encode(b'export TOKEN=synthetic-value'),
        b'Content-Type: text/cloud-config\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n'
        b'password=3Dsynthetic-value',
    ])
    result = decoder.decoded_text(body)
    assert 'export TOKEN=synthetic-value' in result
    assert 'password=synthetic-value' in result
    assert 'Content-Type: text/x-shellscript' in result


def test_gzip_wrapped_mime_and_gzip_attachment():
    part = (b'Content-Type: application/gzip\r\nContent-Transfer-Encoding: base64\r\n\r\n'
            + base64.b64encode(gzip.compress(b'PASSWORD=synthetic-value')))
    assert 'PASSWORD=synthetic-value' in decoder.decoded_text(gzip.compress(multipart([part])))


@pytest.mark.parametrize('raw', [gzip.compress(b'x', mtime=0)[:-1], gzip.compress(b'x', mtime=0) + b'tail',
    b'\x1f\x8bmalformed', b'\x00binary', b'\xff', b'x' * (decoder.MAX_INPUT + 1),
    gzip.compress(b'x' * (decoder.MAX_TEXT + 1), mtime=0),
    multipart([b'Content-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n\r\n@@@@']),
    multipart([b'Content-Type: text/plain\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n=GG']),
    multipart([b'Content-Type: text/plain; charset=utf-16\r\n\r\nx']),
    b'MIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=missing\n\nno-boundary',
    multipart([b'Content-Type: text/plain\r\nContent-Type: text/plain\r\n\r\nx']),
])
def test_unsupported_malformed_or_oversized_content_never_becomes_clean_text(raw):
    with pytest.raises((ValueError, UnicodeError)):
        decoder.decoded_text(raw)


def test_part_and_member_limits():
    with pytest.raises(ValueError, match='bound'):
        decoder.decoded_text(multipart([b'Content-Type: text/plain\r\n\r\nx'] * 40))
    with pytest.raises(ValueError, match='member bound'):
        decoder.decoded_text(gzip.compress(b'x') * 9)


def test_mime_first_header_malformed_header_block_is_rejected():
    with pytest.raises(ValueError):
        decoder.decoded_text(b"Content-Type: text/plain\ninvalid header\n\ntext")
