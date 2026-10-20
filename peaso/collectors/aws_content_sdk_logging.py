"""Call-scoped SDK content/auth log suppression for explicit content readers.

Standard-library-only helper. It neither imports SDKs/configuration nor changes
logger levels. Other threads continue logging; every installed filter is removed.
"""
from contextlib import contextmanager
import logging
import threading


@contextmanager
def private_sdk_logs():
    """Suppress native SDK auth/content logging on this call's thread only."""
    owner = threading.get_ident()
    class Private(logging.Filter):
        def filter(self, record):
            return threading.get_ident() != owner
    guard = Private()
    # SDK endpoint/auth/parser emitters are stable native modules. Include
    # existing descendants and output handlers for descendants loaded lazily.
    prefixes = ('botocore', 'boto3', 'urllib3', 's3transfer')
    seeds = ('botocore.auth', 'botocore.endpoint', 'botocore.parsers', 'botocore.hooks',
        'botocore.client', 'botocore.utils', 'botocore.credentials', 'botocore.httpsession',
        'botocore.regions', 'botocore.retryhandler', 'urllib3.connectionpool')
    for name in seeds:logging.getLogger(name)
    loggers = [logging.getLogger(name) for name in list(logging.root.manager.loggerDict)
        if name.split('.')[0] in prefixes]
    handlers = set(logging.getLogger().handlers)
    for logger in loggers:handlers.update(logger.handlers)
    class Output(logging.Filter):
        def filter(self, record):
            return threading.get_ident() != owner or record.name.split('.')[0] not in prefixes
    output = Output()
    for logger in loggers:logger.addFilter(guard)
    for handler in handlers:handler.addFilter(output)
    try:
        yield
    finally:
        for logger in loggers:logger.removeFilter(guard)
        for handler in handlers:handler.removeFilter(output)

