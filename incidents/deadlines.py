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

Business-day counting for LGPD deadlines — a documented interpretation
(sources checked 2026-09-26):

- Resolução CD/ANPD nº 15/2024 (Arts. 6 and 9) sets "três dias úteis"
  counted from the controller's knowledge that the incident affected
  personal data, but says nothing about how to count them. Neither does
  the ANPD's incident-communication page (gov.br/anpd).
- The closest rules are Resolução CD/ANPD nº 1/2021, Art. 8 (the ANPD's
  inspection regulation: deadlines in business days, start day excluded,
  end day included, extended when the ANPD's headquarters has no working
  hours on the last day) and Lei 9.784/1999, Art. 66 (federal
  administrative procedure, same start/end rule). Art. 8 governs the
  deadlines of Res. 1/2021 itself, so it applies here by analogy, not by
  its own terms; the analogy is supported by the ANPD processing an
  incident communication as an administrative case (supplements are filed
  "no mesmo processo").
- Where the analogous rules are explicit, this module follows them: the
  start day is excluded. On every point they leave open for this purpose,
  it takes the conservative reading: public holidays are not skipped, and
  each day ends at 23:59:59 in the start timestamp's time zone (UTC —
  20:59 in Brasília). The due date shown can therefore be earlier than the
  one the analogy gives, never later. For a compliance tool, erring early
  is the acceptable error. The one assumption that cuts the other way is
  the start-day exclusion itself: read as counting the day of knowledge,
  the deadline would end one business day earlier than shown.
"""

from dataclasses import dataclass
from datetime import date, datetime, time, timedelta

HOURS = "hours"
CALENDAR_DAYS = "calendar_days"
BUSINESS_DAYS = "business_days"

BUSINESS_DAY_CAVEAT = (
    "LGPD business days are counted Monday-Friday, excluding the day of discovery and "
    "ending at 23:59 UTC. Resolução CD/ANPD nº 15/2024 doesn't say how to count them; "
    "this is a conservative reading by analogy with Res. CD/ANPD nº 1/2021 (Art. 8) and "
    "Lei 9.784/1999 (Art. 66), which exclude the start day. Public holidays aren't skipped, "
    "so the date shown is never later than that reading gives."
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
