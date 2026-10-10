"""Claude-ported Azure predicates (partition claude_azure), split by service group.

Loaded by one registry import in peaso/checks/__init__.py. Review dispositions live in
peaso/rulepacks/reviewed_claude_azure.json and reviewed_claude_azure_manual.json.
"""
from . import claude_azure_common  # noqa: F401
from . import claude_azure_compute, claude_azure_identity, claude_azure_network, claude_azure_data  # noqa: F401
from .claude_azure_common import CHECK_IDS  # noqa: F401
