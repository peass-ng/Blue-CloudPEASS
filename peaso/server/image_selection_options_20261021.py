"""Credential-free intake for independently selected image vulnerability scans."""
from peaso import aws_image_selection_20261021 as aws
from peaso import gcp_image_selection_20261021 as registry
from . import cloudrun_job_selection_static_20261021 as gcp
from . import acr_image_selection_static_20261021 as azure


def validate_image_options(provider, options, scopes):
    # Each supplied selector is independently validated, including disabled
    # selections. A Pod/public-registry selection must not require an unrelated
    # private ECR, ACR, or Cloud Run Job target.
    if aws.ENABLE in options and type(options[aws.ENABLE]) is not bool:
        raise ValueError('Image vulnerability scanning must be a boolean')
    explicit = set()
    for option, expected in (
            ('selected_aws_ecr_public_images', 'aws'),
            ('selected_gke_pod_images', 'gcp'),
            ('selected_azure_aks_pod_images', 'azure'),
            ('selected_k8s_registry_images', 'k8s')):
        if option not in options:
            continue
        if provider != expected:
            raise ValueError('Selected image provider does not match connector')
        if expected == 'aws':
            from peaso.aws_ecr_public_selection_20261021 import selected_targets
            selected_targets(options, scopes)
        elif expected == 'gcp':
            from peaso.gcp_gke_image_selection_20261021 import selected
            selected(options, scopes, [])
        else:
            from . import content_selection_preflight_20261021 as pure
            selector = pure.aks_image if expected == 'azure' else pure.registry
            selector.selected_targets(options, scopes, [])
        explicit.add(expected)
    flex = 'selected_appengine_flex_version_images' in options
    if flex:
        if provider != 'gcp':
            raise ValueError('Selected Flex version images require GCP')
        from peaso.gcp_appengine_flex_image_selection_20261021 import selected
        selected(options, scopes, [])
    if registry.OPTION in options:
        if provider != 'gcp':
            raise ValueError('Selected GCP registry images require GCP')
        registry.selections(options, scopes)
    if azure.OPTION in options:
        if provider != 'azure':
            raise ValueError('Selected Azure ACR images require Azure')
        azure.selected_targets(options, scopes)
    if aws.OPTION in options:
        if provider != 'aws':
            raise ValueError('Selected AWS images require AWS')
        aws.selections(options, scopes)
    if options.get(aws.ENABLE) is not True:
        return
    if provider == 'aws':
        if aws.OPTION in options or provider not in explicit:
            aws.selections(options, scopes)
    elif provider == 'gcp':
        if registry.OPTION in options:
            registry.selections(options, scopes)
            if gcp.OPTION in options:
                gcp.validate_image_options(provider, options, scopes)
        elif gcp.OPTION in options or not (flex or provider in explicit):
            gcp.validate_image_options(provider, options, scopes)
    elif provider == 'azure':
        if azure.OPTION in options or provider not in explicit:
            azure.selected_targets(options, scopes)
    elif provider == 'k8s' and provider in explicit:
        return
    else:
        raise ValueError('Image vulnerability scanning requires selected AWS, GCP or Azure images')
