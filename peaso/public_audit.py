"""Check release content against an operator-owned private identifier list."""
from __future__ import annotations

import gzip
import io
import json
import lzma
from pathlib import Path
import tarfile
import zipfile

MAX_EXPANDED_BYTES = 256 * 1024 * 1024


def identifiers(path):
    values = json.loads(Path(path).read_text())
    if not isinstance(values, list) or not values or any(not isinstance(v, str) or len(v) < 6 for v in values):
        raise ValueError('Private identifier file must contain nonempty strings of at least six characters')
    return tuple(v.encode() for v in values)


def contains_private(data, name, needles, *, depth=0):
    """Inspect bounded nested archives without extracting files or printing matches."""
    if len(data) > MAX_EXPANDED_BYTES or depth > 4:
        raise ValueError('Public audit expansion limit exceeded')
    if any(needle in data for needle in needles):
        return True
    def check(content, member):
        return contains_private(content, member, needles, depth=depth + 1)
    def bounded(stream):
        value = stream.read(MAX_EXPANDED_BYTES + 1)
        if len(value) > MAX_EXPANDED_BYTES:
            raise ValueError('Public audit expansion limit exceeded')
        return value
    if name.endswith(('.tar.gz', '.tgz')):
        with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
            expanded = 0
            for member in archive:
                expanded += member.size
                if expanded > MAX_EXPANDED_BYTES:
                    raise ValueError('Public audit expansion limit exceeded')
                if member.isfile() and check(bounded(archive.extractfile(member)), member.name):
                    return True
    elif name.endswith('.gz'):
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as stream:
            return check(bounded(stream), name[:-3])
    elif name.endswith('.xz'):
        with lzma.LZMAFile(io.BytesIO(data)) as stream:
            return check(bounded(stream), name[:-3])
    elif name.endswith('.zip'):
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            if sum(member.file_size for member in archive.infolist()) > MAX_EXPANDED_BYTES:
                raise ValueError('Public audit expansion limit exceeded')
            for member in archive.infolist():
                if not member.is_dir() and check(archive.read(member), member.filename):
                    return True
    return False


def check_sources(source, identifier_file):
    needles = identifiers(identifier_file)
    failed = [name for name, content in source.items() if contains_private(content, name, needles)]
    if failed:
        # Do not include matched values or archive member names in errors.
        raise ValueError('Private identifiers found in public source files: ' + ', '.join(sorted(failed)))
    return {'files_checked': len(source), 'private_identifiers_found': 0}
