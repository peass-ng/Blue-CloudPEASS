"""claude2_azure partition natives (prefix ``azure.claude2.``): App Service, Entra ID, network, Defender, compute and data.

Importing this module registers every predicate of the partition; ``CHECK_IDS`` lists them in registration order.
"""
from __future__ import annotations
from . import claude2_azure_app, claude2_azure_identity, claude2_azure_network, claude2_azure_defender  # noqa: F401
from .claude2_azure_common import CHECK_IDS, PREFIX

GROUPS = {"app": claude2_azure_app.APP_IDS, "identity": claude2_azure_identity.IDENTITY_IDS,
          "network": claude2_azure_network.NETWORK_IDS, "defender": claude2_azure_defender.DEFENDER_IDS}

__all__ = ["CHECK_IDS", "PREFIX", "GROUPS"]
