"""Literal immutable Artifact Registry image identities, including native GCR URLs.

No alias rewriting: a gcr.io URL must itself be returned by DockerImage.uri and
bound to its documented native repository before content inspection is possible.
"""
import re

GCR_REPOSITORIES = {
    'gcr.io': ('us', 'gcr.io'),
    'us.gcr.io': ('us', 'us.gcr.io'),
    'eu.gcr.io': ('europe', 'eu.gcr.io'),
    'asia.gcr.io': ('asia', 'asia.gcr.io'),
}


def parse(value):
    if not isinstance(value, str):
        raise ValueError('literal image URI required')
    bare = value.removeprefix('https://')
    pkg = re.fullmatch(r'([a-z0-9-]+)-docker\.pkg\.dev/([a-z0-9-]+)/([A-Za-z0-9._-]+)/([A-Za-z0-9._/-]+)@(sha256:[a-f0-9]{64})', bare)
    if pkg:
        location, project, repository, image, digest = pkg.groups()
    else:
        gcr = re.fullmatch(r'(gcr\.io|us\.gcr\.io|eu\.gcr\.io|asia\.gcr\.io)/([a-z0-9-]+)/([a-z0-9._/-]+)@(sha256:[a-f0-9]{64})', bare)
        if not gcr:
            raise ValueError('immutable supported native registry URI required')
        host, project, image, digest = gcr.groups()
        location, repository = GCR_REPOSITORIES[host]
    if repository in ('.', '..') or any(part in ('', '.', '..') for part in image.split('/')):
        raise ValueError('unsafe native repository or image path')
    return ('https://' + bare,
            f'projects/{project}/locations/{location}/repositories/{repository}',
            digest, image + '@' + digest)
