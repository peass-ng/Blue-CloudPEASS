"""Fail closed before shell-enabled agents reach the platform worker.

The deployment owns the isolation implementation (container/VM/sandbox service).
A temporary cwd, environment allowlist, or a model's instructions are not an OS
security boundary. No HTTP input may configure this launcher.
"""
import os
from pathlib import Path
import stat


def remote():
    return os.getenv('PEASO_AI_RUNTIME', '') == 'fargate'


def launcher():
    value = os.getenv('PEASO_AI_ISOLATION_LAUNCHER', '')
    if not value or not Path(value).is_absolute():
        raise RuntimeError('ai_isolation_unavailable')
    path = Path(value).resolve(strict=True)
    metadata = path.stat()
    if (not stat.S_ISREG(metadata.st_mode) or not os.access(path, os.X_OK)
            or metadata.st_uid not in (0, os.geteuid()) or metadata.st_mode & 0o022):
        raise RuntimeError('ai_isolation_unavailable')
    return str(path)


def available():
    try:
        if remote():
            from .fargate import configuration
            configuration()
            return True
        launcher()
        return True
    except (OSError, RuntimeError, ValueError):
        return False


def wrap_command(argv, workspace):
    """Launcher must isolate the supplied workspace before executing argv.

    Contract: LAUNCHER --workspace DIRECTORY -- EXECUTABLE ARG...
    The directory is the only scan-specific readable/writable mount. The
    launcher must provide a private PID namespace, no inherited descriptors or
    platform identity, and network policy blocking platform metadata/internal
    services while permitting the explicitly assigned cloud endpoints.
    """
    return [launcher(), '--workspace', str(workspace), '--', *argv]
