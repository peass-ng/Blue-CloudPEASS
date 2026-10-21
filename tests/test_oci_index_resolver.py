"""Pure bounded graph properties without a registry, SDK, or detector."""
import json
import pytest
import test_ecr_public_image as prior

archive=prior.archive;index=prior.index
wire=prior.wire


def make_index(descriptors):
    raw=wire({'schemaVersion':2,'mediaType':index.OCI_INDEX,'manifests':descriptors})
    return raw,archive.sha(raw)


def descriptor(raw,digest=None,platform=None,media=None):
    return {'mediaType':media or archive.OCI,'size':len(raw),'digest':digest or archive.sha(raw),
            'platform':platform or {'os':'linux','architecture':'amd64'}}


def test_parent_child_hash_size_and_platform_are_exact():
    child=prior.image(False).manifest
    parent,digest=make_index([descriptor(child)])
    reads=[]
    def fetch(d,size,media):
        reads.append((d,size,media));return child
    resolved=list(index.children(parent,digest,fetch))
    assert [x['digest'] for x in resolved]==[archive.sha(child)]
    assert reads==[(archive.sha(child),len(child),archive.OCI)]
    with pytest.raises(ValueError,match='parent_manifest_digest_or_size'):
        list(index.children(parent,'sha256:'+'0'*64,fetch))
    with pytest.raises(ValueError,match='child_manifest_digest_or_size'):
        list(index.children(parent,digest,lambda *_:child[:-1]))
    with pytest.raises(ValueError,match='index_platform_selection_incomplete'):
        list(index.children(parent,digest,fetch,platform={'os':'linux','architecture':'arm64'}))


def test_unsupported_attestation_nested_duplicate_and_cancelled():
    child=prior.image(False).manifest
    unsupported,digest=make_index([descriptor(child,platform={'os':'unknown','architecture':'unknown'})])
    with pytest.raises(ValueError,match='unsupported_platform_descriptor'):
        list(index.children(unsupported,digest,lambda *_:child))
    duplicate,digest=make_index([descriptor(child),descriptor(child)])
    with pytest.raises(ValueError,match='duplicate_index_child'):
        list(index.children(duplicate,digest,lambda *_:child))
    nested,digest=make_index([descriptor(child,media=index.OCI_INDEX)])
    with pytest.raises(ValueError,match='unsupported_index_child'):
        list(index.children(nested,digest,lambda *_:child))
    parent,digest=make_index([descriptor(child)])
    def cancel():raise KeyboardInterrupt('cancelled')
    with pytest.raises(KeyboardInterrupt):
        list(index.children(parent,digest,lambda *_:child,check=cancel))


def test_docker_manifest_list_requires_docker_leaf_and_exact_media():
    child=prior.image(False).manifest.replace(archive.OCI.encode(),archive.DOCKER.encode())
    document=json.loads(child)
    assert document['mediaType']==archive.DOCKER
    parent=wire({'schemaVersion':2,'mediaType':index.DOCKER_LIST,
                 'manifests':[descriptor(child,media=archive.DOCKER)]})
    resolved=list(index.children(parent,archive.sha(parent),lambda *_:child))
    assert len(resolved)==1 and resolved[0]['mediaType']==archive.DOCKER
    wrong=wire({'schemaVersion':2,'mediaType':index.DOCKER_LIST,
                'manifests':[descriptor(child,media=archive.OCI)]})
    with pytest.raises(ValueError,match='unsupported_index_child'):
        list(index.children(wrong,archive.sha(wrong),lambda *_:child))
    mismatched=child.replace(archive.DOCKER.encode(),archive.OCI.encode())
    parent=wire({'schemaVersion':2,'mediaType':index.DOCKER_LIST,
                 'manifests':[descriptor(mismatched,media=archive.DOCKER)]})
    with pytest.raises(ValueError,match='unsupported_child_manifest'):
        list(index.children(parent,archive.sha(parent),lambda *_:mismatched))
