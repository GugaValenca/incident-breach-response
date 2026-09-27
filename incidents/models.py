"""
Data model for the Incident-Breach-Response tracker.

An incident record answers the questions a privacy team is asked in the
first hours after a security incident: what happened and when was it
discovered, which data, systems and processing activities are affected,
how many people in which jurisdictions, is it contained — and, from those
facts, which notifications are owed, to whom, and by when.

The model separates two kinds of content on purpose:

- **Facts about an incident** (`Incident` and its related rows) — entered
  by the response team, including the documented judgment calls the law
  leaves to the controller (e.g. `risk_to_individuals`).
- **Legal content** (`LegalRequirement`) — what each framework requires,
  seeded from `incidents/management/commands/seed_incidents.py` with a
  `source_url`, a verification date and an `is_verified` flag, the same
  content policy as LGPD-GDPR-CCPA-Comparative-Analysis. The decision logic that matches the two
  lives in `incidents/obligations.py`.

IMPORTANT — legal disclaimer for anyone reviewing this code:
This application is built around a fictional e-commerce company
(NimbusCart, shared with Data-Mapping-ROPA and DPIA-Privacy-Impact-Assessment) for demonstration purposes.
Incidents, systems and figures are invented. The severity model
(`incidents/severity.py`) is a simplified internal model, NOT an official
classification system, and nothing this tool outputs is legal advice.
"""

from django.core.exceptions import ValidationError
from django.db import IntegrityError, models, transaction
from django.utils import timezone

REFERENCE_ATTEMPTS = 5

# Upper bound for free-text fields. TextField doesn't limit length in the
# database, but max_length is enforced by every form built from the model
# (including the admin), so one oversized field can't bloat a record, the
# page that renders it, or the PDF export.
MAX_TEXT_LENGTH = 5000


class DataCategory(models.Model):
    """A category of personal data, reused from Data-Mapping-ROPA.

    The boolean flags are NimbusCart's own classification of each
    category against the specific legal tests this tool evaluates. They
    are classification choices for this fictional dataset, recorded once
    per category so every incident applies them consistently — not a
    legal determination about any real data.
    """

    name = models.CharField(max_length=120, unique=True)
    description = models.TextField(max_length=MAX_TEXT_LENGTH, blank=True)
    is_special_category = models.BooleanField(
        default=False,
        help_text=(
            "Falls within LGPD Art. 5, II ('dado pessoal sensível') / GDPR Art. 9(1) "
            "(e.g. health, biometric, genetic data)."
        ),
    )
    is_financial = models.BooleanField(
        default=False,
        help_text="Financial data — one of the ANPD RCIS Art. 5 criteria (inciso III).",
    )
    is_authentication = models.BooleanField(
        default=False,
        help_text="System authentication data — one of the ANPD RCIS Art. 5 criteria (inciso IV).",
    )
    is_ca_breach_element = models.BooleanField(
        default=False,
        help_text=(
            "As NimbusCart stores it, this category meets a Cal. Civ. Code § 1798.82(h) "
            "definition of 'personal information' — name combined with a listed data "
            "element (SSN, government ID number, financial account + access code, medical "
            "or health insurance information, biometric, ALPR or genetic data), or a "
            "username/email with a password or security Q&A."
        ),
    )
    # Kept separate from is_ca_breach_element because the two California
    # definitions differ: § 1798.150 uses § 1798.81.5(d)(1)(A), whose
    # "medical information" ((d)(2)) covers medical history, treatment or
    # diagnosis by a health care professional but not a "mental or physical
    # condition" as § 1798.82 does; it has no ALPR element; and it covers
    # email + password, not username + password.
    is_ccpa_150_element = models.BooleanField(
        default=False,
        help_text=(
            "As NimbusCart stores it, this category is 'personal information' for the CCPA "
            "private right of action (Cal. Civ. Code § 1798.150(a)(1)): name combined with an "
            "element listed in § 1798.81.5(d)(1)(A) (SSN, government ID number, financial "
            "account + access code, medical or health insurance information, biometric or "
            "genetic data), or an email address with a password or security Q&A."
        ),
    )

    class Meta:
        verbose_name_plural = "Data categories"
        ordering = ("name",)

    def __str__(self) -> str:
        return self.name


class ProcessingActivity(models.Model):
    """A processing activity from Data-Mapping-ROPA, reused as reference
    data so an incident can say which activities it touched.

    Each of these apps deploys with its own database, so this is a
    copy of the ROPA's seed data (see seed_incidents.py), not a live link.
    """

    name = models.CharField(max_length=200, unique=True)
    department = models.CharField(max_length=120)
    purpose = models.TextField(max_length=MAX_TEXT_LENGTH)
    data_categories = models.ManyToManyField(DataCategory, related_name="activities")

    class Meta:
        verbose_name_plural = "Processing activities"
        ordering = ("name",)

    def __str__(self) -> str:
        return self.name


class System(models.Model):
    """An IT system or vendor platform that can be affected by an incident."""

    name = models.CharField(max_length=150, unique=True)
    owner_team = models.CharField(max_length=120)
    hosting = models.CharField(
        max_length=150,
        blank=True,
        help_text="Where it runs, e.g. 'AWS (us-east-1)' or a vendor name.",
    )
    description = models.TextField(max_length=MAX_TEXT_LENGTH, blank=True)

    class Meta:
        ordering = ("name",)

    def __str__(self) -> str:
        return self.name


class LegalRequirement(models.Model):
    """One incident-related obligation under one framework — e.g.
    "notify the ANPD within 3 business days" or "keep an internal record
    of every breach".

    The *content* here (deadline, recipient, citation) must be verified
    against a primary source before `is_verified` is set; the *decision*
    of whether it applies to a given incident is code, keyed on `code`,
    in `incidents/obligations.py`.
    """

    class Framework(models.TextChoices):
        LGPD = "lgpd", "LGPD (Brazil)"
        GDPR = "gdpr", "GDPR (EU/EEA)"
        CA_BREACH = "ca_breach", "California breach-notification law (Civ. Code § 1798.82)"
        CCPA = "ccpa", "CCPA/CPRA (California)"

    class Kind(models.TextChoices):
        NOTIFICATION = "notification", "Notification"
        RECORD = "record", "Internal record-keeping"
        EXPOSURE = "exposure", "Liability exposure (no notice owed)"

    class DeadlineUnit(models.TextChoices):
        NONE = "none", "No fixed deadline"
        HOURS = "hours", "Hours"
        CALENDAR_DAYS = "calendar_days", "Calendar days"
        BUSINESS_DAYS = "business_days", "Business days"

    code = models.SlugField(
        max_length=60,
        unique=True,
        help_text="Stable identifier the applicability logic in obligations.py is keyed on.",
    )
    framework = models.CharField(max_length=20, choices=Framework.choices)
    kind = models.CharField(max_length=20, choices=Kind.choices, default=Kind.NOTIFICATION)
    title = models.CharField(max_length=200)
    recipient = models.CharField(
        max_length=200,
        help_text="Who must be notified, e.g. 'ANPD' or 'Affected data subjects'.",
    )
    trigger_summary = models.TextField(
        max_length=MAX_TEXT_LENGTH,
        help_text="When this obligation is triggered, in plain language.",
    )
    deadline_unit = models.CharField(
        max_length=20, choices=DeadlineUnit.choices, default=DeadlineUnit.NONE
    )
    deadline_value = models.PositiveIntegerField(null=True, blank=True)
    deadline_runs_from = models.ForeignKey(
        "self",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="dependent_requirements",
        help_text=(
            "Leave empty if the deadline runs from discovery. Set it when the clock starts "
            "at another notice instead (e.g. California's AG copy runs from the consumer notice)."
        ),
    )
    deadline_text = models.CharField(
        max_length=300,
        help_text="The deadline as the source words it, e.g. 'without undue delay'.",
    )
    citation = models.CharField(max_length=200)
    source_url = models.URLField(blank=True)
    is_verified = models.BooleanField(
        default=False,
        help_text="Check only after this requirement has been verified against the primary source.",
    )
    verified_on = models.DateField(null=True, blank=True)
    verification_notes = models.TextField(
        max_length=MAX_TEXT_LENGTH,
        blank=True,
        help_text="What was checked, or a 'TODO: VERIFY ...' note if not yet verified.",
    )
    order = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ("order", "code")

    def __str__(self) -> str:
        return f"{self.get_framework_display()} — {self.title}"

    @property
    def has_fixed_deadline(self) -> bool:
        return self.deadline_unit != self.DeadlineUnit.NONE and self.deadline_value is not None


class Incident(models.Model):
    """A security incident at NimbusCart and everything known about it."""

    class IncidentType(models.TextChoices):
        UNAUTHORIZED_ACCESS = "unauthorized_access", "Unauthorized access / intrusion"
        RANSOMWARE = "ransomware", "Ransomware / malware"
        MISDIRECTED = "misdirected", "Misdirected disclosure (wrong recipient)"
        LOST_DEVICE = "lost_device", "Lost or stolen device"
        VENDOR = "vendor", "Vendor / processor incident"
        INSIDER = "insider", "Insider misuse"
        OTHER = "other", "Other"

    class Containment(models.TextChoices):
        INVESTIGATING = "investigating", "Investigating"
        ONGOING = "ongoing", "Active — not contained"
        CONTAINED = "contained", "Contained"
        RESOLVED = "resolved", "Resolved"

    class RiskToIndividuals(models.TextChoices):
        UNLIKELY = "unlikely", "Unlikely to result in a risk"
        RISK = "risk", "Likely to result in a risk"
        HIGH = "high", "Likely to result in a high risk"

    reference = models.CharField(max_length=20, unique=True, editable=False)
    title = models.CharField(max_length=200)
    summary = models.TextField(
        max_length=MAX_TEXT_LENGTH, help_text="What happened, as currently understood."
    )
    incident_type = models.CharField(max_length=30, choices=IncidentType.choices)

    occurred_at = models.DateTimeField(
        null=True, blank=True, help_text="When the incident started, if known."
    )
    discovered_at = models.DateTimeField(
        help_text=(
            "When NimbusCart became aware that the incident affected personal data. "
            "Every deadline countdown starts here."
        )
    )
    containment_status = models.CharField(
        max_length=20, choices=Containment.choices, default=Containment.INVESTIGATING
    )

    affected_activities = models.ManyToManyField(
        ProcessingActivity, related_name="incidents", blank=True
    )
    affected_data_categories = models.ManyToManyField(
        DataCategory, related_name="incidents", blank=True
    )
    affected_systems = models.ManyToManyField(System, related_name="incidents", blank=True)

    # Documented judgment calls. The law leaves these to the controller, so
    # the tool records the team's decision rather than computing it.
    risk_to_individuals = models.CharField(
        max_length=20,
        choices=RiskToIndividuals.choices,
        default=RiskToIndividuals.RISK,
        help_text=(
            "The response team's documented risk assessment for affected individuals. "
            "Drives the GDPR Art. 33/34 and LGPD Art. 48 tests."
        ),
    )
    data_encrypted = models.BooleanField(
        default=False,
        help_text="The affected data was encrypted/unintelligible to the attacker.",
    )
    encryption_key_compromised = models.BooleanField(
        default=False, help_text="The key or credential needed to decrypt it was also exposed."
    )
    involves_vulnerable_individuals = models.BooleanField(
        default=False,
        help_text="Affects data of children, adolescents or elderly people (ANPD RCIS Art. 5, II).",
    )
    involves_confidential_data = models.BooleanField(
        default=False,
        help_text="Affects data under legal, judicial or professional secrecy (ANPD RCIS Art. 5, V).",
    )
    is_large_scale = models.BooleanField(
        default=False,
        help_text=(
            "The team judges this a large-scale incident (ANPD RCIS Art. 5, VI and §2: number "
            "of people, data volume, duration, frequency, geographic reach)."
        ),
    )
    controller_is_small_agent = models.BooleanField(
        default=False,
        help_text=(
            "The controller qualifies as a small-scale processing agent under ANPD "
            "Resolução CD/ANPD nº 2/2022 (LGPD communication deadlines count double)."
        ),
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("-discovered_at",)

    def __str__(self) -> str:
        return f"{self.reference} — {self.title}"

    def clean(self):
        """Validated here rather than only in IncidentForm so the admin
        enforces the same rules."""
        errors = {}
        if self.discovered_at and self.discovered_at > timezone.now():
            errors["discovered_at"] = "Discovery can't be in the future."
        if self.occurred_at and self.discovered_at and self.occurred_at > self.discovered_at:
            errors["occurred_at"] = "An incident can't start after it was discovered."
        if self.encryption_key_compromised and not self.data_encrypted:
            errors["encryption_key_compromised"] = (
                "Only applies when the data was encrypted in the first place."
            )
        if errors:
            raise ValidationError(errors)

    def save(self, *args, **kwargs):
        if self.reference:
            super().save(*args, **kwargs)
            return
        # Two incidents saved at the same moment can compute the same next
        # reference. The unique constraint catches that; retry with a fresh
        # number inside a savepoint instead of surfacing a server error.
        for attempt in range(REFERENCE_ATTEMPTS):
            self.reference = self._next_reference()
            try:
                with transaction.atomic():
                    super().save(*args, **kwargs)
                return
            except IntegrityError:
                self.reference = ""
                if attempt == REFERENCE_ATTEMPTS - 1:
                    raise

    def _next_reference(self) -> str:
        """INC-<year>-<nnn>, numbered per discovery year. Human-friendly
        references are what a response team actually quotes in emails and
        regulator forms, so they're worth generating rather than exposing
        database ids.

        Based on the highest number already used, not a row count, so a
        deleted incident never causes the next reference to collide with
        an existing one."""
        year = (self.discovered_at or timezone.now()).year
        prefix = f"INC-{year}-"
        used = Incident.objects.filter(reference__startswith=prefix).values_list(
            "reference", flat=True
        )
        numbers = [int(ref[len(prefix) :]) for ref in used if ref[len(prefix) :].isdigit()]
        return f"{prefix}{max(numbers, default=0) + 1:03d}"

    @property
    def is_open(self) -> bool:
        return self.containment_status != self.Containment.RESOLVED

    @property
    def total_individuals(self) -> int:
        return sum(impact.individuals for impact in self.jurisdiction_impacts.all())

    def individuals_in(self, jurisdiction: str) -> int:
        return sum(
            impact.individuals
            for impact in self.jurisdiction_impacts.all()
            if impact.jurisdiction == jurisdiction
        )


class JurisdictionImpact(models.Model):
    """How many affected individuals are in one jurisdiction. The
    jurisdictions listed are the ones this tool evaluates obligations for
    (plus two catch-alls, recorded but not evaluated)."""

    class Jurisdiction(models.TextChoices):
        BRAZIL = "BR", "Brazil"
        EU_EEA = "EU", "EU / EEA"
        CALIFORNIA = "US-CA", "California (US)"
        US_OTHER = "US-OTHER", "Other US states (not evaluated)"
        OTHER = "OTHER", "Rest of world (not evaluated)"

    incident = models.ForeignKey(
        Incident, on_delete=models.CASCADE, related_name="jurisdiction_impacts"
    )
    jurisdiction = models.CharField(max_length=10, choices=Jurisdiction.choices)
    individuals = models.PositiveIntegerField(
        help_text="Number of affected individuals (best estimate)."
    )

    class Meta:
        ordering = ("jurisdiction",)
        constraints = (
            models.UniqueConstraint(
                fields=("incident", "jurisdiction"), name="unique_jurisdiction_per_incident"
            ),
        )

    def __str__(self) -> str:
        return f"{self.get_jurisdiction_display()}: {self.individuals}"


class TimelineEvent(models.Model):
    """One entry in the incident's chronology — the record GDPR Art. 33(5)
    and ANPD RCIS Art. 10 expect a controller to be able to produce."""

    incident = models.ForeignKey(
        Incident, on_delete=models.CASCADE, related_name="timeline_events"
    )
    occurred_at = models.DateTimeField()
    description = models.TextField(max_length=MAX_TEXT_LENGTH)

    class Meta:
        ordering = ("occurred_at", "id")

    def __str__(self) -> str:
        return f"{self.occurred_at:%Y-%m-%d %H:%M} — {self.description[:50]}"


class ChecklistItem(models.Model):
    """One response task, with an owner and a status."""

    class Status(models.TextChoices):
        TODO = "todo", "To do"
        IN_PROGRESS = "in_progress", "In progress"
        DONE = "done", "Done"
        NOT_APPLICABLE = "n_a", "Not applicable"

    incident = models.ForeignKey(
        Incident, on_delete=models.CASCADE, related_name="checklist_items"
    )
    title = models.CharField(max_length=200)
    phase = models.CharField(max_length=40, blank=True)
    owner = models.CharField(max_length=120, blank=True)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.TODO)
    order = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ("order", "id")

    def __str__(self) -> str:
        return self.title

    @property
    def is_finished(self) -> bool:
        return self.status in (self.Status.DONE, self.Status.NOT_APPLICABLE)


class NotificationRecord(models.Model):
    """Evidence that a specific notification was actually sent. Its
    presence is what turns an obligation's countdown into "Sent"."""

    incident = models.ForeignKey(
        Incident, on_delete=models.CASCADE, related_name="notification_records"
    )
    requirement = models.ForeignKey(
        LegalRequirement, on_delete=models.PROTECT, related_name="notification_records"
    )
    sent_at = models.DateTimeField()
    reference = models.CharField(
        max_length=120,
        blank=True,
        help_text="Protocol/ticket number, if the recipient issued one.",
    )
    notes = models.TextField(max_length=MAX_TEXT_LENGTH, blank=True)

    class Meta:
        ordering = ("sent_at",)
        constraints = (
            models.UniqueConstraint(
                fields=("incident", "requirement"), name="unique_record_per_requirement"
            ),
        )

    def clean(self):
        if self.sent_at and self.sent_at > timezone.now():
            raise ValidationError(
                {"sent_at": "A notification can't be recorded as sent in the future."}
            )

    def __str__(self) -> str:
        return (
            f"{self.incident.reference} — {self.requirement.code} sent {self.sent_at:%Y-%m-%d}"
        )
