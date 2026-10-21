"""Credential-free intake for independently selected image vulnerability scans."""
from peaso import aws_image_selection_20261021 as aws
from peaso import gcp_image_selection_20261021 as registry
from . import cloudrun_job_selection_static_20261021 as gcp
from . import acr_image_selection_static_20261021 as azure


def validate_image_options(provider, options, scopes):
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
    if aws.ENABLE not in options:
        return
    if type(options[aws.ENABLE]) is not bool:
        raise ValueError('Image vulnerability scanning must be a boolean')
    if provider == 'aws':
        aws.selections(options, scopes)
    elif provider == 'gcp':
        if registry.OPTION in options:
            registry.selections(options, scopes)
            if gcp.OPTION in options:
                gcp.validate_image_options(provider, options, scopes)
        else:
            gcp.validate_image_options(provider, options, scopes)
    elif provider == 'azure':
        azure.selected_targets(options, scopes)
    else:
        raise ValueError('Image vulnerability scanning requires selected AWS, GCP or Azure images')
