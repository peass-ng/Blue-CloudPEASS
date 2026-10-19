"""Bounded ISO duration parsing for collected Azure policy metadata only."""
import re

from .facts import Unavailable


def duration_parts(value):
    if not isinstance(value, str) or len(value) > 128:
        raise Unavailable("malformed policy duration")
    match = re.fullmatch(
        r"P(?:(\d+)Y)?(?:(\d+)M)?(?:(\d+)W)?(?:(\d+)D)?"
        r"(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?", value)
    if not match or not any(part is not None for part in match.groups()) or value.endswith("T"):
        raise Unavailable("malformed policy duration")
    parts = tuple(int(part or 0) for part in match.groups())
    if parts[2] and any(parts[i] for i in (0, 1, 3, 4, 5, 6)):
        raise Unavailable("mixed week policy duration")
    return parts


def positive_duration(value):
    return any(duration_parts(value))


def rotation_interval_supported(value):
    # Azure Key Vault requires at least seven days after creation. A month or
    # year is always longer than this bound; no fixed calendar conversion needed.
    years, months, weeks, days, hours, minutes, seconds = duration_parts(value)
    return bool(years or months or (weeks * 7 + days) * 86400 + hours * 3600 + minutes * 60 + seconds >= 7 * 86400)
