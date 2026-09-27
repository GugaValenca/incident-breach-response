"""
Deadline arithmetic: turning "72 hours", "3 business days" or "30
calendar days" plus a start timestamp into a due date, and a due date
plus "now" into a countdown.

Pure functions only — no models, no database — so the counting rules are
unit-tested directly (see `incidents/tests.py`).

Counting conventions used here (implementation choices, NOT statements of
law — each is surfaced in the UI next to any deadline it affects):

- Hours: an exact offset from the start timestamp (GDPR Art. 33(1)'s
  "not later than 72 hours after having become aware").
- Calendar days: the due date is the *end* of the Nth calendar day after
  the start date (the start day itself is not counted).
- Business days: same, skipping Saturdays and Sundays.

# TODO: VERIFY business-day counting convention against ANPD guidance.
# Resolução CD/ANPD nº 15/2024 (Arts. 6 and 9) sets "três dias úteis"
# counted from the controller's knowledge, but its text (checked
# 2026-09-26) does not say whether the start day is excluded, which
# public holidays apply (national only, or state/municipal too) or which
# time zone the day ends in. This module skips weekends only, excludes
# the start day, and ends days at 23:59:59 in the start timestamp's time
# zone (UTC in this app). Brazilian public holidays are NOT modeled, so a
# computed LGPD due date can be earlier than the real one — never later.
"""

from dataclasses import dataclass
from datetime import date, datetime, time, timedelta

HOURS = "hours"
CALENDAR_DAYS = "calendar_days"
BUSINESS_DAYS = "business_days"

BUSINESS_DAY_CAVEAT = (
    "Business days are counted Monday-Friday, excluding the day of discovery. "
    "Brazilian public holidays are not modeled (TODO: VERIFY counting convention)."
)


def _end_of_day(day: date, like: datetime) -> datetime:
    return datetime.combine(day, time(23, 59, 59), tzinfo=like.tzinfo)


def add_business_days(start: date, days: int) -> date:
    """The date `days` weekdays after `start` (the start date itself is
    never counted, even if it's a weekday)."""
    current = start
    remaining = days
    while remaining > 0:
        current += timedelta(days=1)
        if current.weekday() < 5:  # Mon=0 … Fri=4
            remaining -= 1
    return current


def compute_due(start: datetime, unit: str, value: int) -> datetime:
    """Due timestamp for a deadline of `value` `unit`s running from `start`."""
    if unit == HOURS:
        return start + timedelta(hours=value)
    if unit == CALENDAR_DAYS:
        return _end_of_day(start.date() + timedelta(days=value), start)
    if unit == BUSINESS_DAYS:
        return _end_of_day(add_business_days(start.date(), value), start)
    raise ValueError(f"Unknown deadline unit: {unit!r}")


@dataclass(frozen=True)
class Countdown:
    remaining: timedelta

    @property
    def is_overdue(self) -> bool:
        return self.remaining < timedelta(0)

    @property
    def label(self) -> str:
        """Compact human label, e.g. "2d 4h left" or "overdue by 3d 1h"."""
        magnitude = abs(self.remaining)
        days = magnitude.days
        hours = magnitude.seconds // 3600
        minutes = (magnitude.seconds % 3600) // 60
        if days:
            amount = f"{days}d {hours}h"
        elif hours:
            amount = f"{hours}h {minutes}m"
        else:
            amount = f"{minutes}m"
        return f"overdue by {amount}" if self.is_overdue else f"{amount} left"


def countdown(due: datetime, now: datetime) -> Countdown:
    return Countdown(remaining=due - now)
