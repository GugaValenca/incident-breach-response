from typing import ClassVar

from django import forms
from django.db import transaction

from .models import (
    ChecklistItem,
    Incident,
    JurisdictionImpact,
    NotificationRecord,
    TimelineEvent,
)

DATETIME_FORMAT = "%Y-%m-%dT%H:%M"


class DateTimeLocalInput(forms.DateTimeInput):
    """The browser's native date+time picker. Values are interpreted in
    the app's time zone (UTC), which the labels say explicitly."""

    input_type = "datetime-local"

    def __init__(self, **kwargs):
        super().__init__(format=DATETIME_FORMAT, **kwargs)


# One form field per jurisdiction instead of an inline formset: a fixed,
# short list reads better as five labelled number inputs, and the save
# logic stays a plain loop (see `IncidentForm.save_impacts`).
#
# These are plain form fields, not model form fields, so they don't inherit
# the database's integer range: without an explicit ceiling, a value past
# Postgres's 32-bit integer limit would reach the database and fail there.
MAX_INDIVIDUALS = 1_000_000_000
JURISDICTION_FIELDS = {
    f"individuals_{code.lower().replace('-', '_')}": (code, label)
    for code, label in JurisdictionImpact.Jurisdiction.choices
}


class IncidentForm(forms.ModelForm):
    class Meta:
        model = Incident
        fields = (
            "title",
            "summary",
            "incident_type",
            "occurred_at",
            "discovered_at",
            "containment_status",
            "affected_activities",
            "affected_data_categories",
            "affected_systems",
            "risk_to_individuals",
            "data_encrypted",
            "encryption_key_compromised",
            "involves_vulnerable_individuals",
            "involves_confidential_data",
            "is_large_scale",
            "controller_is_small_agent",
        )
        labels: ClassVar = {
            "occurred_at": "Occurred at (UTC)",
            "discovered_at": "Discovered at (UTC)",
        }
        widgets: ClassVar = {
            "summary": forms.Textarea(attrs={"rows": 4}),
            "occurred_at": DateTimeLocalInput(),
            "discovered_at": DateTimeLocalInput(),
            "affected_activities": forms.CheckboxSelectMultiple,
            "affected_data_categories": forms.CheckboxSelectMultiple,
            "affected_systems": forms.CheckboxSelectMultiple,
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        existing = {}
        if self.instance.pk:
            existing = {
                i.jurisdiction: i.individuals for i in self.instance.jurisdiction_impacts.all()
            }
        for name, (code, label) in JURISDICTION_FIELDS.items():
            self.fields[name] = forms.IntegerField(
                label=label,
                min_value=0,
                max_value=MAX_INDIVIDUALS,
                required=False,
                initial=existing.get(code, 0),
            )

    # Date and encryption rules live in Incident.clean(), which ModelForm
    # validation calls, so the admin enforces them too.

    def jurisdiction_fields(self):
        return [self[name] for name in JURISDICTION_FIELDS]

    @transaction.atomic
    def save(self, commit=True):
        incident = super().save(commit=commit)
        if commit:
            self.save_impacts(incident)
        return incident

    def save_impacts(self, incident: Incident) -> None:
        for name, (code, _label) in JURISDICTION_FIELDS.items():
            individuals = self.cleaned_data.get(name) or 0
            if individuals:
                JurisdictionImpact.objects.update_or_create(
                    incident=incident, jurisdiction=code, defaults={"individuals": individuals}
                )
            else:
                JurisdictionImpact.objects.filter(incident=incident, jurisdiction=code).delete()


class ChecklistItemUpdateForm(forms.ModelForm):
    class Meta:
        model = ChecklistItem
        fields = ("owner", "status")


class ChecklistItemCreateForm(forms.ModelForm):
    class Meta:
        model = ChecklistItem
        fields = ("title", "phase", "owner")


class TimelineEventForm(forms.ModelForm):
    class Meta:
        model = TimelineEvent
        fields = ("occurred_at", "description")
        labels: ClassVar = {"occurred_at": "When (UTC)"}
        widgets: ClassVar = {
            "occurred_at": DateTimeLocalInput(),
            "description": forms.TextInput(),
        }


class NotificationRecordForm(forms.ModelForm):
    class Meta:
        model = NotificationRecord
        fields = ("sent_at", "reference", "notes")
        labels: ClassVar = {"sent_at": "Sent at (UTC)"}
        widgets: ClassVar = {
            "sent_at": DateTimeLocalInput(),
            "notes": forms.TextInput(),
        }
