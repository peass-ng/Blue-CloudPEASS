"""Select one immutable ECR manifest from bounded, distinct tag aliases."""

MAX_ALIASES = 100


def select_digest_image(images, failures, account, repository, digest):
    """Reject every row unless all report the same requested manifest identity."""
    if failures != [] or type(images) is not list or not 1 <= len(images) <= MAX_ALIASES:
        raise ValueError('ambiguous ECR image response')
    first = images[0]
    if type(first) is not dict or type(first.get('imageManifest')) is not str \
            or type(first.get('imageManifestMediaType')) is not str:
        raise ValueError('invalid ECR image row')
    manifest = first['imageManifest']
    media = first['imageManifestMediaType']
    tags = set()
    for row in images:
        image_id = row.get('imageId') if type(row) is dict else None
        if (type(image_id) is not dict or row.get('registryId') != account
                or row.get('repositoryName') != repository
                or image_id.get('imageDigest') != digest
                or row.get('imageManifest') != manifest
                or row.get('imageManifestMediaType') != media):
            raise ValueError('ECR image alias identity mismatch')
        if len(images) > 1:
            tag = image_id.get('imageTag')
            if type(tag) is not str or not tag or tag in tags:
                raise ValueError('ambiguous ECR image tag aliases')
            tags.add(tag)
    return first
