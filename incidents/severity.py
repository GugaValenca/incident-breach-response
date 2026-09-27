"""
Incident severity scoring.

DISCLAIMER: this is a simplified internal triage model, NOT an official
or regulatory severity classification, and it does not decide whether
any law requires notification. Its only job is to give the response team
a consistent first read on how serious an incident is, for prioritizing
work. The legal tests are separate — see `incidents/obligations.py` —
and some of them turn on judgment calls (`Incident.risk_to_individuals`)
that this score informs but does not replace.

Deliberately isolated from views and models, the same pattern as
DPIA-Privacy-Impact-Assessment's `dpia/scoring.py`: plain data in (`SeverityInputs`), plain
data out (`SeverityResult`), so every weight and threshold is unit-tested
directly.
"""

from dataclasses import dataclass
from enum import Enum


class SeverityLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def label(self) -> str:
        return self.value.capitalize()


SEVERITY_DISCLAIMER = (
    "Severity is a simplified internal triage model, not an official classification "
    "system, and does not by itself determine any legal notification obligation."
)

# Hand-picked weights and thresholds — a deliberately simple, explainable
# model, not a calibrated one. The shape: what data (0-3) + how many people
# (0-3) + is it still happening (0-2) + was it deliberate (0-1), minus a
# discount when the data was encrypted and the key is safe.
DATA_POINTS_SPECIAL_CATEGORY = 3
DATA_POINTS_FINANCIAL_OR_CREDENTIALS = 2
DATA_POINTS_OTHER = 1

VOLUME_BANDS = ((10_000, 3), (100, 2), (1, 1))  # (at least N people, points)

CONTAINMENT_POINTS = {"investigating": 1, "ongoing": 2, "contained": 0, "resolved": 0}

MALICIOUS_INCIDENT_TYPES = frozenset({"unauthorized_access", "ransomware", "insider"})
MALICIOUS_POINTS = 1

ENCRYPTION_DISCOUNT = 3

# Upper bound (inclusive) of each level's score range; anything above
# HIGH_MAX is Critical. Chosen so an encrypted lost laptop lands Low, a
# contained misdirected email with a few hundred records lands Medium, and
# an uncontained intrusion into credentials of 10,000+ people is Critical.
LOW_MAX = 2
MEDIUM_MAX = 5
HIGH_MAX = 7


@dataclass(frozen=True)
class SeverityInputs:
    has_special_category: bool
    has_financial_or_credentials: bool
    has_other_personal_data: bool
    individuals: int
    containment_status: str
    incident_type: str
    data_encrypted: bool
    encryption_key_compromised: bool


@dataclass(frozen=True)
class SeverityFactor:
    label: str
    points: int


@dataclass(frozen=True)
class SeverityResult:
    score: int
    level: SeverityLevel
    factors: tuple[SeverityFactor, ...]


def classify(score: int) -> SeverityLevel:
    if score <= LOW_MAX:
        return SeverityLevel.LOW
    if score <= MEDIUM_MAX:
        return SeverityLevel.MEDIUM
    if score <= HIGH_MAX:
        return SeverityLevel.HIGH
    return SeverityLevel.CRITICAL


def _data_factor(inputs: SeverityInputs) -> SeverityFactor:
    if inputs.has_special_category:
        return SeverityFactor("Special-category (sensitive) data", DATA_POINTS_SPECIAL_CATEGORY)
    if inputs.has_financial_or_credentials:
        return SeverityFactor(
            "Financial, credential or identity data", DATA_POINTS_FINANCIAL_OR_CREDENTIALS
        )
    if inputs.has_other_personal_data:
        return SeverityFactor("Other personal data", DATA_POINTS_OTHER)
    return SeverityFactor("No personal data categories recorded", 0)


def _volume_factor(individuals: int) -> SeverityFactor:
    for minimum, points in VOLUME_BANDS:
        if individuals >= minimum:
            return SeverityFactor(f"{individuals:,} individuals affected", points)
    return SeverityFactor("No affected individuals recorded", 0)


def calculate_severity(inputs: SeverityInputs) -> SeverityResult:
    factors = [
        _data_factor(inputs),
        _volume_factor(inputs.individuals),
        SeverityFactor(
            f"Containment: {inputs.containment_status}",
            CONTAINMENT_POINTS.get(inputs.containment_status, 0),
        ),
    ]
    if inputs.incident_type in MALICIOUS_INCIDENT_TYPES:
        factors.append(SeverityFactor("Deliberate / malicious cause", MALICIOUS_POINTS))
    if inputs.data_encrypted and not inputs.encryption_key_compromised:
        factors.append(
            SeverityFactor("Data encrypted and key not compromised", -ENCRYPTION_DISCOUNT)
        )

    # Floored at zero: the encryption discount can neutralize an incident's
    # score but a negative total would be meaningless.
    score = max(0, sum(f.points for f in factors))
    return SeverityResult(score=score, level=classify(score), factors=tuple(factors))


def inputs_from_incident(incident) -> SeverityInputs:
    """Build SeverityInputs from a saved Incident. Callers are expected to
    have prefetched `affected_data_categories` and `jurisdiction_impacts`."""
    categories = list(incident.affected_data_categories.all())
    return SeverityInputs(
        has_special_category=any(c.is_special_category for c in categories),
        has_financial_or_credentials=any(
            c.is_financial or c.is_authentication or c.is_ca_breach_element for c in categories
        ),
        has_other_personal_data=bool(categories),
        individuals=incident.total_individuals,
        containment_status=incident.containment_status,
        incident_type=incident.incident_type,
        data_encrypted=incident.data_encrypted,
        encryption_key_compromised=incident.encryption_key_compromised,
    )


def calculate_incident_severity(incident) -> SeverityResult:
    return calculate_severity(inputs_from_incident(incident))
