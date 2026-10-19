"""Private deny lists never enter source; release checks inspect compressed content."""
import gzip
import io
import json
import lzma
import zipfile

import pytest

from peaso.public_audit import check_sources


@pytest.mark.parametrize('kind', ['plain', 'gzip', 'xz', 'zip'])
def test_private_identifier_detected_inside_archives(kind, tmp_path):
    path = tmp_path / 'private-identifiers.json'
    path.write_text(json.dumps(['synthetic-private-resource']))
    data = b'{"value":"synthetic-private-resource"}'
    name = 'fixture.json'
    if kind == 'gzip':
        data, name = gzip.compress(data), name + '.gz'
    elif kind == 'xz':
        data, name = lzma.compress(data), name + '.xz'
    elif kind == 'zip':
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, 'w') as archive:
            archive.writestr('nested.json.gz', gzip.compress(data))
        data, name = stream.getvalue(), 'fixture.zip'
    with pytest.raises(ValueError) as caught:
        check_sources({name: data}, path)
    assert name in str(caught.value)
    assert 'synthetic-private-resource' not in str(caught.value)


def test_clean_source_and_bad_private_configuration(tmp_path):
    path = tmp_path / 'private-identifiers.json'
    path.write_text(json.dumps(['synthetic-private-resource']))
    assert check_sources({'public.py': b'print("hello")'}, path) == {'files_checked': 1, 'private_identifiers_found': 0}
    path.write_text('{}')
    with pytest.raises(ValueError):
        check_sources({}, path)
