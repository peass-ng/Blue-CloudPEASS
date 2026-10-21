"""Credential-free intake for independently selected image CVE scans."""
from peaso import aws_image_selection_20261021 as aws
from . import cloudrun_job_selection_static_20261021 as gcp

def validate_image_options(provider, options, scopes):
    if aws.OPTION in options:
        if provider != "aws":
            raise ValueError("Selected AWS images require AWS")
        aws.selections(options, scopes)
    if aws.ENABLE not in options:
        return
    if type(options[aws.ENABLE]) is not bool:
        raise ValueError("Image vulnerability scanning must be a boolean")
    if provider == "aws":
        aws.selections(options, scopes)
    elif provider == "gcp":
        gcp.validate_image_options(provider, options, scopes)
    else:
        raise ValueError("Image vulnerability scanning supports selected AWS or GCP images")
