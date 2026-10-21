"""Install native unused-network findings beside unused identity hardening."""


def install(registry):
    from peaso.unused_network_aws import install as aws
    from peaso.unused_network_gcp import install as gcp
    from peaso.unused_network_azure_20261021 import install as azure
    from peaso.unused_network_k8s_20261021 import install as k8s
    for installer in (aws, gcp, azure, k8s):
        installer(registry)
