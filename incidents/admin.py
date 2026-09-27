from django.contrib import admin
from django_ratelimit.decorators import ratelimit

from .models import (
    ChecklistItem,
    DataCategory,
    Incident,
    JurisdictionImpact,
    LegalRequirement,
    NotificationRecord,
    ProcessingActivity,
    System,
    TimelineEvent,
)
from .throttling import client_ip

admin.site.site_header = "Incident-Breach-Response Administration"
admin.site.site_title = "Incident Admin"
admin.site.index_title = "Manage incidents, reference data & legal requirements"

# The login form is the one publicly reachable, unauthenticated endpoint
# into the admin, so it's the one worth rate limiting against brute force
# (same as Projects 2 and 3). mypy sees this as reassigning a method on an
# instance, which Django's AdminSite is built to allow.
admin.site.login = ratelimit(  # type: ignore[method-assign]
    key=client_ip, rate="5/m", method="POST", block=True
)(admin.site.login)


class JurisdictionImpactInline(admin.TabularInline):
    model = JurisdictionImpact
    extra = 0


class TimelineEventInline(admin.TabularInline):
    model = TimelineEvent
    extra = 0


class ChecklistItemInline(admin.TabularInline):
    model = ChecklistItem
    extra = 0


class NotificationRecordInline(admin.TabularInline):
    model = NotificationRecord
    extra = 0


@admin.register(Incident)
class IncidentAdmin(admin.ModelAdmin):
    list_display = (
        "reference",
        "title",
        "incident_type",
        "containment_status",
        "discovered_at",
    )
    list_filter = ("containment_status", "incident_type", "risk_to_individuals")
    search_fields = ("reference", "title", "summary")
    readonly_fields = ("reference",)
    filter_horizontal = ("affected_activities", "affected_data_categories", "affected_systems")
    inlines = (
        JurisdictionImpactInline,
        TimelineEventInline,
        ChecklistItemInline,
        NotificationRecordInline,
    )


@admin.register(LegalRequirement)
class LegalRequirementAdmin(admin.ModelAdmin):
    list_display = (
        "code",
        "framework",
        "kind",
        "recipient",
        "deadline_text",
        "is_verified",
        "verified_on",
    )
    list_filter = ("framework", "kind", "is_verified")
    search_fields = ("code", "title", "citation", "verification_notes")


@admin.register(DataCategory)
class DataCategoryAdmin(admin.ModelAdmin):
    list_display = (
        "name",
        "is_special_category",
        "is_financial",
        "is_authentication",
        "is_ca_breach_element",
    )
    list_filter = (
        "is_special_category",
        "is_financial",
        "is_authentication",
        "is_ca_breach_element",
    )


@admin.register(ProcessingActivity)
class ProcessingActivityAdmin(admin.ModelAdmin):
    list_display = ("name", "department")
    filter_horizontal = ("data_categories",)


@admin.register(System)
class SystemAdmin(admin.ModelAdmin):
    list_display = ("name", "owner_team", "hosting")
