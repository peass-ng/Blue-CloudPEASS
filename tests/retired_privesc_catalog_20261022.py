"""Exact retained bytes for the one intentionally removed public catalog file."""
import hashlib
import tarfile

REMOVED = 'peaso/privesc/catalog/aws/apigateway.yaml'
ARCHIVE = 'peaso/privesc/catalog_versions/prior-bulk-633-catalog.tar.gz'
ARCHIVE_SHA256 = 'fad4c89765aa466f27831b6992a7e79059c28a118ee3707496a0e944b6335826'
ORIGINAL_SHA256 = 'b9ead8ab961965b1f784f5a9a0d6795a616dc476a1732b4bde71a1e918319e57'


def original_bytes(root, name):
    assert name == REMOVED
    assert not (root / name).exists(), 'The retired generic API Gateway technique was restored'
    path = root / ARCHIVE
    assert hashlib.sha256(path.read_bytes()).hexdigest() == ARCHIVE_SHA256
    with tarfile.open(path, 'r:gz') as archive:
        member = archive.getmember('catalog/aws/apigateway.yaml')
        assert member.isfile() and member.size == 2974
        raw = archive.extractfile(member).read()
    assert hashlib.sha256(raw).hexdigest() == ORIGINAL_SHA256
    return raw
