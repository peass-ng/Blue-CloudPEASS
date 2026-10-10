"""Compact reproducible registry fixtures; never used to evaluate real snapshots."""
CASES = {}


def nest(path, value):
    result = value
    for part in reversed(path.split(".")):
        result = {part: result}
    return result
