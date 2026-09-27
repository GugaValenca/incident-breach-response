"""
Which legal requirements apply to an incident, and by when.

How the pieces fit:

- `LegalRequirement` rows (seeded, source-verified) hold *what* each
  framework requires: recipient, deadline, citation.
- This module holds *when* each requirement applies: one small predicate
  per requirement `code`, registered in `APPLICABILITY_RULES`. Each
  predicate reads only an `IncidentFacts` snapshot and returns whether the
  requirement applies plus the human-readable reasons why (or why not),
  so the detail page and PDF can show the reasoning, not just a verdict.
- `evaluate_obligations` combines the two with the incident's
  `NotificationRecord`s and the current time into countdowns.

Every predicate is a simplification of the legal test it encodes, and
says so in its docstring. The judgment calls a statute leaves to the
controller (is there a "risk"? a "high risk"? is this "large scale"?)
are recorded on the Incident by the response team, never inferred here.

DISCLAIMER: demonstration tool; not legal advice.
"""

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING

from .deadlines import Countdown, compute_due, countdown

if TYPE_CHECKING:
    from .models import LegalRequirement

BR = "BR"
EU = "EU"
CA = "US-CA"

UNLIKELY = "unlikely"
HIGH = "high"

# Cal. Civ. Code § 1798.82(f): AG sample copy when a single breach requires
# notifying "more than 500 California residents" (verified 2026-09-26).
CA_AG_THRESHOLD = 500


@dataclass(frozen=True)
class IncidentFacts:
    """Everything the applicability rules are allowed to look at."""

    individuals_by_jurisdiction: dict[str, int] = field(default_factory=dict)
    has_special_category: bool = False
    has_financial: bool = False
    has_authentication: bool = False
    has_ca_breach_element: bool = False
    has_ccpa_150_element: bool = False
    risk_to_individuals: str = "risk"
    data_encrypted: bool = False
    encryption_key_compromised: bool = False
    involves_vulnerable_individuals: bool = False
    involves_confidential_data: bool = False
    is_large_scale: bool = False
    controller_is_small_agent: bool = False

    def count(self, jurisdiction: str) -> int:
        return self.individuals_by_jurisdiction.get(jurisdiction, 0)

    @property
    def encryption_protects_data(self) -> bool:
        return self.data_encrypted and not self.encryption_key_compromised


def facts_from_incident(incident) -> IncidentFacts:
    """Snapshot a saved Incident. Callers should prefetch
    `affected_data_categories` and `jurisdiction_impacts`."""
    categories = list(incident.affected_data_categories.all())
    by_jurisdiction: dict[str, int] = {}
    for impact in incident.jurisdiction_impacts.all():
        by_jurisdiction[impact.jurisdiction] = (
            by_jurisdiction.get(impact.jurisdiction, 0) + impact.individuals
        )
    return IncidentFacts(
        individuals_by_jurisdiction=by_jurisdiction,
        has_special_category=any(c.is_special_category for c in categories),
        has_financial=any(c.is_financial for c in categories),
        has_authentication=any(c.is_authentication for c in categories),
        has_ca_breach_element=any(c.is_ca_breach_element for c in categories),
        has_ccpa_150_element=any(c.is_ccpa_150_element for c in categories),
        risk_to_individuals=incident.risk_to_individuals,
        data_encrypted=incident.data_encrypted,
        encryption_key_compromised=incident.encryption_key_compromised,
        involves_vulnerable_individuals=incident.involves_vulnerable_individuals,
        involves_confidential_data=incident.involves_confidential_data,
        is_large_scale=incident.is_large_scale,
        controller_is_small_agent=incident.controller_is_small_agent,
    )


@dataclass(frozen=True)
class Applicability:
    applies: bool
    reasons: tuple[str, ...]


def _applies(*reasons: str) -> Applicability:
    return Applicability(True, reasons)


def _not_applicable(*reasons: str) -> Applicability:
    return Applicability(False, reasons)


# --- LGPD ------------------------------------------------------------------


def rcis_criteria(facts: IncidentFacts) -> list[str]:
    """Which of the six ANPD RCIS Art. 5 criteria the incident meets."""
    criteria = []
    if facts.has_special_category:
        criteria.append("sensitive personal data (I)")
    if facts.involves_vulnerable_individuals:
        criteria.append("data of children, adolescents or elderly people (II)")
    if facts.has_financial:
        criteria.append("financial data (III)")
    if facts.has_authentication:
        criteria.append("system authentication data (IV)")
    if facts.involves_confidential_data:
        criteria.append("data under legal/judicial/professional secrecy (V)")
    if facts.is_large_scale:
        criteria.append("large-scale data (VI)")
    return criteria


def _lgpd_relevant_risk(facts: IncidentFacts) -> Applicability:
    """LGPD Art. 48 + ANPD RCIS Art. 5: communication is owed when an
    incident "may significantly affect" data subjects' interests and
    fundamental rights AND, cumulatively, meets at least one Art. 5
    criterion.

    Simplification: "may significantly affect" is read from the team's
    documented `risk_to_individuals` (anything above "unlikely").
    """
    if facts.count(BR) == 0:
        return _not_applicable("No affected individuals in Brazil.")
    if facts.risk_to_individuals == UNLIKELY:
        return _not_applicable(
            "Risk to individuals assessed as unlikely — not documented as able to "
            "significantly affect data subjects' interests and fundamental rights."
        )
    criteria = rcis_criteria(facts)
    if not criteria:
        return _not_applicable("None of the six RCIS Art. 5 criteria is met.")
    return _applies(
        f"{facts.count(BR):,} affected individuals in Brazil.",
        "Risk to individuals documented above 'unlikely'.",
        "RCIS Art. 5 criteria met: " + "; ".join(criteria) + ".",
    )


def _lgpd_record(facts: IncidentFacts) -> Applicability:
    """ANPD RCIS Art. 10: keep a record of every incident, including those
    not communicated, for at least five years."""
    if facts.count(BR) == 0:
        return _not_applicable("No affected individuals in Brazil.")
    return _applies("Applies to every incident, including those not communicated.")


# --- GDPR ------------------------------------------------------------------


def _gdpr_supervisory_authority(facts: IncidentFacts) -> Applicability:
    """GDPR Art. 33(1): notify unless the breach is "unlikely to result in
    a risk to the rights and freedoms of natural persons"."""
    if facts.count(EU) == 0:
        return _not_applicable("No affected individuals in the EU/EEA.")
    if facts.risk_to_individuals == UNLIKELY:
        return _not_applicable(
            "Risk to individuals documented as unlikely (Art. 33(1) exception)."
        )
    return _applies(
        f"{facts.count(EU):,} affected individuals in the EU/EEA.",
        "Breach not documented as unlikely to result in a risk.",
    )


def _gdpr_data_subjects(facts: IncidentFacts) -> Applicability:
    """GDPR Art. 34(1): communicate to data subjects when the breach is
    "likely to result in a high risk".

    Only the Art. 34(3)(a) exception (encryption) is evaluated; (b)
    subsequent measures and (c) disproportionate effort are judgment calls
    left to the team and noted on screen.
    """
    if facts.count(EU) == 0:
        return _not_applicable("No affected individuals in the EU/EEA.")
    if facts.risk_to_individuals != HIGH:
        return _not_applicable("Risk to individuals not documented as high.")
    if facts.encryption_protects_data:
        return _not_applicable(
            "Art. 34(3)(a) exception: data was encrypted and the key was not compromised."
        )
    return _applies(
        f"{facts.count(EU):,} affected individuals in the EU/EEA.",
        "Risk to individuals documented as high.",
        "Art. 34(3)(b) and (c) exceptions not evaluated — confirm with counsel.",
    )


def _gdpr_record(facts: IncidentFacts) -> Applicability:
    """GDPR Art. 33(5): document any personal data breach."""
    if facts.count(EU) == 0:
        return _not_applicable("No affected individuals in the EU/EEA.")
    return _applies("Applies to every personal data breach, notified or not.")


# --- California ------------------------------------------------------------


def _ca_breach_trigger(facts: IncidentFacts) -> Applicability:
    """Shared trigger for § 1798.82(a): California residents whose
    unencrypted personal information (as defined in (h)) was, or is
    reasonably believed to have been, acquired — or encrypted information
    together with its key. No risk-of-harm test applies.

    Simplification: "acquired by an unauthorized person" is assumed for
    every recorded incident; a team that concludes data was not acquired
    should not record the category as affected.
    """
    if facts.count(CA) == 0:
        return _not_applicable("No affected California residents.")
    if not facts.has_ca_breach_element:
        return _not_applicable("No affected data category meets the § 1798.82(h) definition.")
    if facts.encryption_protects_data:
        return _not_applicable("Data was encrypted and the key was not compromised.")
    return _applies(
        f"{facts.count(CA):,} affected California residents.",
        "Affected data meets the § 1798.82(h) definition of personal information.",
        "Data unencrypted, or the encryption key was also compromised.",
    )


def _ca_attorney_general(facts: IncidentFacts) -> Applicability:
    """§ 1798.82(f): sample copy to the AG when more than 500 California
    residents must be notified."""
    trigger = _ca_breach_trigger(facts)
    if not trigger.applies:
        return trigger
    if facts.count(CA) <= CA_AG_THRESHOLD:
        return _not_applicable(
            f"{facts.count(CA):,} California residents — not more than {CA_AG_THRESHOLD}."
        )
    return _applies(f"{facts.count(CA):,} California residents — more than {CA_AG_THRESHOLD}.")


def _ccpa_private_action(facts: IncidentFacts) -> Applicability:
    """§ 1798.150(a)(1): potential statutory-damages exposure for a breach of
    "nonencrypted and nonredacted personal information" as defined in
    § 1798.81.5(d)(1)(A), or of an email address with a password or security
    question and answer. Flagged, not determined: liability also requires a
    failure to maintain reasonable security, which this tool can't assess.

    Uses its own category flag (`is_ccpa_150_element`), because that
    definition is narrower than § 1798.82(h)'s: e.g. self-reported physical
    conditions can trigger a § 1798.82 notice without being "medical
    information" under § 1798.81.5(d)(2).

    Simplifications: exfiltration, theft or disclosure is assumed for every
    recorded incident (as for § 1798.82), and encrypted data whose key was
    also compromised is treated as exposed — the statute says only
    "nonencrypted", so for an exposure flag the cautious reading is to flag it.
    """
    if facts.count(CA) == 0:
        return _not_applicable("No affected California residents.")
    if not facts.has_ccpa_150_element:
        return _not_applicable(
            "No affected data category is personal information under § 1798.81.5(d)(1)(A) "
            "or an email address with a password."
        )
    if facts.encryption_protects_data:
        return _not_applicable("Data was encrypted and the key was not compromised.")
    return _applies(
        f"{facts.count(CA):,} affected California residents.",
        "Affected data is personal information under § 1798.81.5(d)(1)(A), or an email "
        "address with a password.",
        "Exposure only: liability also requires a failure to maintain reasonable security.",
    )


APPLICABILITY_RULES: dict[str, Callable[[IncidentFacts], Applicability]] = {
    "lgpd-anpd": _lgpd_relevant_risk,
    "lgpd-data-subjects": _lgpd_relevant_risk,
    "lgpd-incident-record": _lgpd_record,
    "gdpr-supervisory-authority": _gdpr_supervisory_authority,
    "gdpr-data-subjects": _gdpr_data_subjects,
    "gdpr-breach-record": _gdpr_record,
    "ca-residents": _ca_breach_trigger,
    "ca-attorney-general": _ca_attorney_general,
    "ccpa-private-action": _ccpa_private_action,
}


def check_applicability(code: str, facts: IncidentFacts) -> Applicability:
    rule = APPLICABILITY_RULES.get(code)
    if rule is None:
        return _not_applicable("No applicability rule is implemented for this requirement yet.")
    return rule(facts)


# --- Putting it together -----------------------------------------------------


class Status:
    NOT_APPLICABLE = "not_applicable"
    SENT = "sent"
    OVERDUE = "overdue"
    PENDING = "pending"
    NO_FIXED_DEADLINE = "no_fixed_deadline"
    ONGOING = "ongoing"  # record-keeping / exposure: nothing to "send"


STATUS_LABELS = {
    Status.NOT_APPLICABLE: "Not applicable",
    Status.SENT: "Sent",
    Status.OVERDUE: "Overdue",
    Status.PENDING: "Pending",
    Status.NO_FIXED_DEADLINE: "Pending — no fixed deadline",
    Status.ONGOING: "Applies",
}


@dataclass(frozen=True)
class Obligation:
    requirement: "LegalRequirement"
    applies: bool
    reasons: tuple[str, ...]
    deadline_value: int | None = None
    due_at: datetime | None = None
    due_is_projected: bool = False
    sent_at: datetime | None = None
    countdown: Countdown | None = None

    @property
    def status(self) -> str:
        if not self.applies:
            return Status.NOT_APPLICABLE
        if self.requirement.kind != "notification":
            return Status.ONGOING
        if self.sent_at is not None:
            return Status.SENT
        if self.due_at is None:
            return Status.NO_FIXED_DEADLINE
        if self.countdown is not None and self.countdown.is_overdue:
            return Status.OVERDUE
        return Status.PENDING

    @property
    def status_label(self) -> str:
        return STATUS_LABELS[self.status]

    @property
    def sent_late(self) -> bool:
        return (
            self.sent_at is not None and self.due_at is not None and self.sent_at > self.due_at
        )


def _effective_deadline_value(
    requirement, facts: IncidentFacts
) -> tuple[int | None, str | None]:
    """ANPD RCIS Arts. 6 §8 and 9 §6: LGPD communication deadlines count
    double for small-scale processing agents."""
    value = requirement.deadline_value
    if (
        value is not None
        and requirement.framework == "lgpd"
        and requirement.deadline_unit == "business_days"
        and facts.controller_is_small_agent
    ):
        return value * 2, "Deadline doubled: controller is a small-scale processing agent."
    return value, None


def evaluate_obligations(incident, requirements, now: datetime) -> list[Obligation]:
    """Evaluate every requirement against one incident.

    Requirements whose clock starts at another notice
    (`deadline_runs_from`, e.g. California's AG copy) are evaluated after
    the one they depend on, and run from that notice's actual send date —
    or, if it hasn't been sent yet, from its due date (flagged as
    projected, since the real deadline can only be earlier).
    """
    facts = facts_from_incident(incident)
    sent_by_requirement = {
        r.requirement_id: r.sent_at for r in incident.notification_records.all()
    }
    requirements = list(requirements)
    ordered = [r for r in requirements if r.deadline_runs_from_id is None] + [
        r for r in requirements if r.deadline_runs_from_id is not None
    ]

    results: dict[int, Obligation] = {}
    for requirement in ordered:
        applicability = check_applicability(requirement.code, facts)
        reasons = list(applicability.reasons)
        value, note = _effective_deadline_value(requirement, facts)
        if note and applicability.applies:
            reasons.append(note)

        due_at = None
        projected = False
        if applicability.applies and requirement.has_fixed_deadline and value is not None:
            start: datetime | None = incident.discovered_at
            if requirement.deadline_runs_from_id is not None:
                anchor = results.get(requirement.deadline_runs_from_id)
                start = (anchor.sent_at or anchor.due_at) if anchor else None
                projected = bool(anchor and anchor.sent_at is None)
            if start is not None:
                due_at = compute_due(start, requirement.deadline_unit, value)

        sent_at = sent_by_requirement.get(requirement.id)
        results[requirement.id] = Obligation(
            requirement=requirement,
            applies=applicability.applies,
            reasons=tuple(reasons),
            deadline_value=value,
            due_at=due_at,
            due_is_projected=projected,
            sent_at=sent_at,
            countdown=countdown(due_at, now) if due_at and sent_at is None else None,
        )

    # Back in the requirements' own display order.
    return [results[r.id] for r in requirements]


def next_open_deadline(obligations: list[Obligation]) -> Obligation | None:
    """The soonest pending or overdue notification — what the dashboard
    shows as "next deadline"."""
    open_ones = [o for o in obligations if o.status in (Status.PENDING, Status.OVERDUE)]
    return min(open_ones, key=lambda o: o.due_at, default=None)  # type: ignore[arg-type,return-value]
