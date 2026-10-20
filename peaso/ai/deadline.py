"""Carry a bounded invocation budget into the inner agent wrapper."""
import math
import os

ENVIRONMENT_KEY = 'PEASO_AI_AGENT_TIMEOUT_SECONDS'


def timeout_seconds(value):
    try:
        seconds = float(value)
    except (TypeError, ValueError):
        raise ValueError('invalid_ai_agent_timeout') from None
    if isinstance(value, bool) or not math.isfinite(seconds) or not 0 < seconds <= 1800:
        raise ValueError('invalid_ai_agent_timeout')
    return math.ceil(seconds)


def configure_runner(config, remaining=None):
    if remaining is None:
        remaining = os.getenv(ENVIRONMENT_KEY)
    if remaining is not None:
        # Round upward so Chack cannot impose an earlier, minute-based cutoff.
        # The caller's absolute deadline still stops the entire process tree.
        config.agent.max_runtime_minutes = math.ceil(timeout_seconds(remaining) / 60)
