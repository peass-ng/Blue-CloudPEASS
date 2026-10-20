"""Exact native Functions import successor over preserved predecessor bytes."""
import gzip
import hashlib
import json


def reviewed_delta(root, receipt):
    path = root / receipt['predecessors']['path']
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != receipt['predecessors']['sha256']:
        raise RuntimeError('Functions predecessor archive changed')
    archive = json.loads(gzip.decompress(raw))
    for name, row in archive['files'].items():
        old = bytes.fromhex(row['hex'])
        if hashlib.sha256(old).hexdigest() != row['sha256']:
            raise RuntimeError('Functions predecessor bytes changed')
        # Shared init has a separately reviewed additive epoch. Test/doc proofs
        # remain in the archive; runtime guards require only packaged sources.
        if name.startswith('peaso/') and name not in {
                'peaso/collectors/gcp.py', 'peaso/checks/__init__.py'}:
            if (root / name).read_bytes() != old:
                raise RuntimeError('Functions immutable predecessor changed: ' + name)
    name = 'peaso/collectors/gcp.py'
    current = (root / name).read_bytes()
    old = bytes.fromhex(archive['files'][name]['hex'])
    before = receipt['gcp_import_delta']['before'].encode()
    after = receipt['gcp_import_delta']['after'].encode()
    if (current.count(after) != 1 or old.count(before) != 1
            or current.replace(after, before, 1) != old):
        raise RuntimeError('Functions native hook changed outside the reviewed import')
    return archive
