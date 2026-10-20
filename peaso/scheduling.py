"""Shared calendar recurrence for SQLite workers and the AWS scheduler."""
from calendar import monthrange
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo


def next_run(data, after):
    """Return the first occurrence strictly after an epoch timestamp.

    Rules form a union: simultaneous rules produce one scan. Missed runs are
    coalesced into the due scan; the next run stays on its wall-clock calendar.
    Short months use their last day. DST gaps move forward by the clock gap;
    ambiguous times use the first occurrence and never run twice.
    """
    rules = data.get('rules')
    if not rules:
        return after + data.get('interval_hours', 168) * 3600
    zone = ZoneInfo(data.get('timezone', 'UTC'))
    today = datetime.fromtimestamp(after, zone).date()
    candidates = []
    for rule in rules:
        hour, minute = map(int, rule['time'].split(':'))
        # Every valid monthly rule fires within the next32 days, weekly within8.
        for offset in range(33):
            day = today + timedelta(days=offset)
            if rule['frequency'] == 'weekly' and day.weekday() not in rule['weekdays']:
                continue
            if rule['frequency'] == 'monthly' and day.day != min(rule['day_of_month'], monthrange(day.year, day.month)[1]):
                continue
            candidate = datetime(day.year, day.month, day.day, hour, minute, tzinfo=zone, fold=0)
            stamp = candidate.astimezone(timezone.utc).timestamp()
            if stamp > after:
                candidates.append(stamp)
                break
    if not candidates:
        raise ValueError('Schedule has no upcoming occurrence')
    return min(candidates)
