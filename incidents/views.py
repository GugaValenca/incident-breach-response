"""Views for the incident dashboard, incident detail/edit, the response
checklist and timeline, notification records, legal sources, and PDF
export.

Severity and obligations are never stored: they're recomputed from the
incident's facts on every request (see `_evaluate`), so editing a fact —
say, raising the affected-individuals count past a threshold — can't
leave a stale verdict behind.
"""

from dataclasses import dataclass

from django.contrib import messages
from django.db import transaction
from django.db.models import Q, QuerySet
from django.http import HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.http import require_POST
from django_ratelimit.decorators import ratelimit

from . import exports
from .checklist import create_default_checklist
from .deadlines import BUSINESS_DAY_CAVEAT
from .forms import (
    ChecklistItemCreateForm,
    ChecklistItemUpdateForm,
    IncidentForm,
    NotificationRecordForm,
    TimelineEventForm,
)
from .models import (
    ChecklistItem,
    Incident,
    JurisdictionImpact,
    LegalRequirement,
    NotificationRecord,
    TimelineEvent,
)
from .obligations import Obligation, Status, evaluate_obligations, next_open_deadline
from .severity import (
    SEVERITY_DISCLAIMER,
    SeverityLevel,
    SeverityResult,
    calculate_incident_severity,
)
from .throttling import client_ip

# The demo accepts writes from anonymous visitors (see README, "Security
# notes"), so every write shares one per-IP budget, and PDF generation — the
# most CPU-expensive request — gets its own. Over-limit requests get a 403.
WRITE_RATE = "30/m"
PDF_RATE = "10/m"
limit_writes = ratelimit(
    group="writes", key=client_ip, rate=WRITE_RATE, method="POST", block=True
)
limit_pdf = ratelimit(group="pdf", key=client_ip, rate=PDF_RATE, block=True)


@dataclass(frozen=True)
class IncidentRow:
    """One incident with everything computed about it."""

    incident: Incident
    severity: SeverityResult
    obligations: list[Obligation]

    @property
    def applicable(self) -> list[Obligation]:
        return [o for o in self.obligations if o.applies]

    @property
    def next_deadline(self) -> Obligation | None:
        return next_open_deadline(self.obligations)

    @property
    def overdue_count(self) -> int:
        return sum(1 for o in self.obligations if o.status == Status.OVERDUE)

    @property
    def frameworks(self) -> list[str]:
        """Codes of frameworks with at least one applicable requirement."""
        return list(dict.fromkeys(o.requirement.framework for o in self.applicable))


def _incident_queryset() -> QuerySet[Incident]:
    return Incident.objects.prefetch_related(
        "affected_data_categories",
        "affected_activities",
        "affected_systems",
        "jurisdiction_impacts",
        "notification_records",
        "timeline_events",
        "checklist_items",
    )


def _requirements() -> list[LegalRequirement]:
    return list(LegalRequirement.objects.all())


def _evaluate(incident: Incident, requirements: list[LegalRequirement]) -> IncidentRow:
    return IncidentRow(
        incident=incident,
        severity=calculate_incident_severity(incident),
        obligations=evaluate_obligations(incident, requirements, timezone.now()),
    )


# --- Dashboard -------------------------------------------------------------


@dataclass(frozen=True)
class DashboardFilters:
    """Parsed dashboard query params. Values not in the allowed choices are
    dropped rather than trusted, so a hand-edited URL filters on nothing
    instead of erroring."""

    query: str
    containment: str
    severity: str
    jurisdiction: str
    framework: str

    @property
    def is_active(self) -> bool:
        return any(
            (self.query, self.containment, self.severity, self.jurisdiction, self.framework)
        )


def _allowed(value: str, choices) -> str:
    return value if value in {c[0] for c in choices} else ""


SEVERITY_CHOICES = [(level.value, level.label) for level in SeverityLevel]


def _parse_filters(request: HttpRequest) -> DashboardFilters:
    get = request.GET
    return DashboardFilters(
        query=(get.get("q") or "").strip(),
        containment=_allowed(get.get("containment", ""), Incident.Containment.choices),
        severity=_allowed(get.get("severity", ""), SEVERITY_CHOICES),
        jurisdiction=_allowed(
            get.get("jurisdiction", ""), JurisdictionImpact.Jurisdiction.choices
        ),
        framework=_allowed(get.get("framework", ""), LegalRequirement.Framework.choices),
    )


def _filtered_rows(filters: DashboardFilters) -> list[IncidentRow]:
    """Database filters first (text, containment, jurisdiction), then the
    two filters on computed values (severity, applicable framework) in
    Python — those aren't stored, by design, so they can't be SQL."""
    incidents = _incident_queryset()
    if filters.query:
        incidents = incidents.filter(
            Q(title__icontains=filters.query)
            | Q(summary__icontains=filters.query)
            | Q(reference__icontains=filters.query)
        )
    if filters.containment:
        incidents = incidents.filter(containment_status=filters.containment)
    if filters.jurisdiction:
        incidents = incidents.filter(
            jurisdiction_impacts__jurisdiction=filters.jurisdiction,
            jurisdiction_impacts__individuals__gt=0,
        )

    requirements = _requirements()
    rows = [_evaluate(incident, requirements) for incident in incidents.distinct()]
    if filters.severity:
        rows = [r for r in rows if r.severity.level.value == filters.severity]
    if filters.framework:
        rows = [r for r in rows if filters.framework in r.frameworks]
    return rows


def dashboard(request: HttpRequest) -> HttpResponse:
    filters = _parse_filters(request)
    rows = _filtered_rows(filters)
    context = {
        "rows": rows,
        "total_count": len(rows),
        "open_count": sum(1 for r in rows if r.incident.is_open),
        "overdue_count": sum(r.overdue_count for r in rows),
        "filters": filters,
        "containment_choices": Incident.Containment.choices,
        "severity_choices": SEVERITY_CHOICES,
        "jurisdiction_choices": JurisdictionImpact.Jurisdiction.choices[:3],
        "framework_choices": LegalRequirement.Framework.choices,
        "severity_disclaimer": SEVERITY_DISCLAIMER,
    }
    return render(request, "incidents/dashboard.html", context)


# --- Incident detail / create / edit ----------------------------------------


def incident_detail(request: HttpRequest, pk: int) -> HttpResponse:
    incident = get_object_or_404(_incident_queryset(), pk=pk)
    row = _evaluate(incident, _requirements())
    checklist = [
        (item, ChecklistItemUpdateForm(instance=item, prefix=f"item-{item.pk}"))
        for item in incident.checklist_items.all()
    ]
    context = {
        "incident": incident,
        "row": row,
        "notifications": [o for o in row.obligations if o.requirement.kind == "notification"],
        "other_obligations": [
            o for o in row.obligations if o.requirement.kind != "notification"
        ],
        "checklist": checklist,
        "checklist_done": sum(1 for item, _ in checklist if item.is_finished),
        "new_item_form": ChecklistItemCreateForm(),
        "timeline_form": TimelineEventForm(initial={"occurred_at": timezone.now()}),
        "record_form": NotificationRecordForm(initial={"sent_at": timezone.now()}),
        "severity_disclaimer": SEVERITY_DISCLAIMER,
        "business_day_caveat": BUSINESS_DAY_CAVEAT,
    }
    return render(request, "incidents/incident_detail.html", context)


@limit_writes
def incident_create(request: HttpRequest) -> HttpResponse:
    if request.method == "POST":
        form = IncidentForm(request.POST)
        if form.is_valid():
            with transaction.atomic():
                incident = form.save()
                create_default_checklist(incident)
                TimelineEvent.objects.create(
                    incident=incident,
                    occurred_at=incident.discovered_at,
                    description="Incident discovered; record opened in the tracker.",
                )
            messages.success(request, f"{incident.reference} logged.")
            return redirect("incidents:incident_detail", pk=incident.pk)
    else:
        form = IncidentForm(initial={"discovered_at": timezone.now()})
    return render(request, "incidents/incident_form.html", {"form": form, "incident": None})


@limit_writes
def incident_edit(request: HttpRequest, pk: int) -> HttpResponse:
    incident = get_object_or_404(Incident, pk=pk)
    if request.method == "POST":
        form = IncidentForm(request.POST, instance=incident)
        if form.is_valid():
            form.save()
            messages.success(request, f"{incident.reference} updated.")
            return redirect("incidents:incident_detail", pk=incident.pk)
    else:
        form = IncidentForm(instance=incident)
    return render(request, "incidents/incident_form.html", {"form": form, "incident": incident})


# --- Small POST-only actions from the detail page ----------------------------


def _back_to(incident: Incident, anchor: str) -> HttpResponse:
    return redirect(reverse("incidents:incident_detail", args=[incident.pk]) + f"#{anchor}")


def _report_errors(request: HttpRequest, form) -> None:
    for field, errors in form.errors.items():
        label = form.fields[field].label if field in form.fields else "Form"
        for error in errors:
            messages.error(request, f"{label}: {error}")


@require_POST
@limit_writes
def checklist_update(request: HttpRequest, item_pk: int) -> HttpResponse:
    item = get_object_or_404(ChecklistItem, pk=item_pk)
    form = ChecklistItemUpdateForm(request.POST, instance=item, prefix=f"item-{item.pk}")
    if form.is_valid():
        form.save()
    else:
        _report_errors(request, form)
    return _back_to(item.incident, "checklist")


@require_POST
@limit_writes
def checklist_add(request: HttpRequest, pk: int) -> HttpResponse:
    incident = get_object_or_404(Incident, pk=pk)
    form = ChecklistItemCreateForm(request.POST)
    if form.is_valid():
        item = form.save(commit=False)
        item.incident = incident
        item.order = incident.checklist_items.count() + 1
        item.save()
    else:
        _report_errors(request, form)
    return _back_to(incident, "checklist")


@require_POST
@limit_writes
def timeline_add(request: HttpRequest, pk: int) -> HttpResponse:
    incident = get_object_or_404(Incident, pk=pk)
    form = TimelineEventForm(request.POST)
    if form.is_valid():
        event = form.save(commit=False)
        event.incident = incident
        event.save()
    else:
        _report_errors(request, form)
    return _back_to(incident, "timeline")


@require_POST
@limit_writes
def notification_record(request: HttpRequest, pk: int, requirement_pk: int) -> HttpResponse:
    """Record that a notification was sent — also logged to the timeline,
    since "when did you tell the regulator" is exactly what a later review
    asks first."""
    incident = get_object_or_404(Incident, pk=pk)
    requirement = get_object_or_404(
        LegalRequirement, pk=requirement_pk, kind=LegalRequirement.Kind.NOTIFICATION
    )
    form = NotificationRecordForm(request.POST)
    if form.is_valid():
        with transaction.atomic():
            NotificationRecord.objects.update_or_create(
                incident=incident, requirement=requirement, defaults=form.cleaned_data
            )
            TimelineEvent.objects.create(
                incident=incident,
                occurred_at=form.cleaned_data["sent_at"],
                description=f"Notification sent: {requirement.title}.",
            )
        messages.success(request, f"Recorded: {requirement.title}.")
    else:
        _report_errors(request, form)
    return _back_to(incident, "obligations")


# --- Static-ish pages and export --------------------------------------------


def legal_sources(request: HttpRequest) -> HttpResponse:
    requirements = LegalRequirement.objects.select_related("deadline_runs_from")
    return render(
        request,
        "incidents/legal_sources.html",
        {
            "requirements": requirements,
            "unverified_count": sum(1 for r in requirements if not r.is_verified),
            "business_day_caveat": BUSINESS_DAY_CAVEAT,
        },
    )


def about(request: HttpRequest) -> HttpResponse:
    return render(request, "incidents/about.html")


@limit_pdf
def export_pdf(request: HttpRequest, pk: int) -> HttpResponse:
    incident = get_object_or_404(_incident_queryset(), pk=pk)
    return exports.export_pdf(_evaluate(incident, _requirements()))
