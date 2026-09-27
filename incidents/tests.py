"""Tests for the incident tracker.

Covers the parts where a silent regression would matter most: deadline
arithmetic (a wrong due date is the worst bug this app can have), each
framework's applicability rule, the severity model's weights and
boundaries, the seeded legal content honoring the verification policy,
and the views/PDF export driven through real requests.
"""

import io
import os
import subprocess
import sys
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.core.management import call_command
from django.forms import modelform_factory
from django.test import TestCase as DjangoTestCase
from django.urls import reverse
from django.utils import timezone
from pypdf import PdfReader

from . import deadlines
from .checklist import DEFAULT_CHECKLIST
from .models import (
    ChecklistItem,
    DataCategory,
    Incident,
    JurisdictionImpact,
    LegalRequirement,
    NotificationRecord,
    TimelineEvent,
)
from .obligations import (
    APPLICABILITY_RULES,
    CA_AG_THRESHOLD,
    IncidentFacts,
    Status,
    check_applicability,
    evaluate_obligations,
)
from .severity import SeverityInputs, SeverityLevel, calculate_severity, classify
from .throttling import client_ip

# 2026-09-25 is a Friday — handy for weekend-crossing business-day tests.
FRIDAY_NOON = datetime(2026, 9, 25, 12, 0, tzinfo=UTC)


class TestCase(DjangoTestCase):
    """Clears the cache before every test: the rate limiter counts requests
    there, and the suite as a whole makes more POSTs than one visitor may
    per minute."""

    def setUp(self):
        super().setUp()
        cache.clear()


def seed_quietly():
    call_command("seed_incidents", stdout=io.StringIO())


# --- Deadlines ---------------------------------------------------------------


class BusinessDayTests(TestCase):
    def test_skips_the_weekend(self):
        # Fri + 3 business days = Mon, Tue, Wed.
        self.assertEqual(deadlines.add_business_days(date(2026, 9, 25), 3), date(2026, 9, 30))

    def test_start_day_is_never_counted(self):
        # Mon + 1 business day = Tue, not Mon itself.
        self.assertEqual(deadlines.add_business_days(date(2026, 9, 21), 1), date(2026, 9, 22))

    def test_start_on_a_weekend(self):
        # Sat + 3 business days = Mon, Tue, Wed.
        self.assertEqual(deadlines.add_business_days(date(2026, 9, 26), 3), date(2026, 9, 30))

    def test_zero_days_is_the_start_date(self):
        self.assertEqual(deadlines.add_business_days(date(2026, 9, 25), 0), date(2026, 9, 25))


class ComputeDueTests(TestCase):
    def test_hours_are_an_exact_offset(self):
        due = deadlines.compute_due(FRIDAY_NOON, deadlines.HOURS, 72)
        self.assertEqual(due, datetime(2026, 9, 28, 12, 0, tzinfo=UTC))

    def test_calendar_days_end_at_end_of_day(self):
        due = deadlines.compute_due(FRIDAY_NOON, deadlines.CALENDAR_DAYS, 30)
        self.assertEqual(due, datetime(2026, 10, 25, 23, 59, 59, tzinfo=UTC))

    def test_business_days_end_at_end_of_day(self):
        due = deadlines.compute_due(FRIDAY_NOON, deadlines.BUSINESS_DAYS, 3)
        self.assertEqual(due, datetime(2026, 9, 30, 23, 59, 59, tzinfo=UTC))

    def test_unknown_unit_raises(self):
        with self.assertRaises(ValueError):
            deadlines.compute_due(FRIDAY_NOON, "fortnights", 1)


class CountdownTests(TestCase):
    def test_time_left(self):
        c = deadlines.countdown(FRIDAY_NOON + timedelta(days=2, hours=4), FRIDAY_NOON)
        self.assertFalse(c.is_overdue)
        self.assertEqual(c.label, "2d 4h left")

    def test_overdue(self):
        c = deadlines.countdown(FRIDAY_NOON - timedelta(days=3, hours=1), FRIDAY_NOON)
        self.assertTrue(c.is_overdue)
        self.assertEqual(c.label, "overdue by 3d 1h")

    def test_under_an_hour_shows_minutes(self):
        c = deadlines.countdown(FRIDAY_NOON + timedelta(minutes=45), FRIDAY_NOON)
        self.assertEqual(c.label, "45m left")


# --- Severity ----------------------------------------------------------------


def severity_inputs(**overrides):
    base = {
        "has_special_category": False,
        "has_financial_or_credentials": False,
        "has_other_personal_data": True,
        "individuals": 0,
        "containment_status": "contained",
        "incident_type": "other",
        "data_encrypted": False,
        "encryption_key_compromised": False,
    }
    base.update(overrides)
    return SeverityInputs(**base)


class SeverityTests(TestCase):
    def test_level_boundaries(self):
        self.assertEqual(classify(0), SeverityLevel.LOW)
        self.assertEqual(classify(2), SeverityLevel.LOW)
        self.assertEqual(classify(3), SeverityLevel.MEDIUM)
        self.assertEqual(classify(5), SeverityLevel.MEDIUM)
        self.assertEqual(classify(6), SeverityLevel.HIGH)
        self.assertEqual(classify(7), SeverityLevel.HIGH)
        self.assertEqual(classify(8), SeverityLevel.CRITICAL)

    def test_uncontained_intrusion_into_credentials_at_scale_is_critical(self):
        result = calculate_severity(
            severity_inputs(
                has_financial_or_credentials=True,
                individuals=15_000,
                containment_status="ongoing",
                incident_type="unauthorized_access",
            )
        )
        self.assertEqual(result.score, 8)  # 2 data + 3 volume + 2 ongoing + 1 malicious
        self.assertEqual(result.level, SeverityLevel.CRITICAL)

    def test_special_category_outweighs_other_data(self):
        result = calculate_severity(severity_inputs(has_special_category=True, individuals=150))
        self.assertEqual(result.score, 5)  # 3 data + 2 volume
        self.assertEqual(result.level, SeverityLevel.MEDIUM)

    def test_encryption_discount_is_floored_at_zero(self):
        result = calculate_severity(severity_inputs(individuals=5, data_encrypted=True))
        self.assertEqual(result.score, 0)
        self.assertEqual(result.level, SeverityLevel.LOW)

    def test_no_discount_when_the_key_was_compromised(self):
        without_key = calculate_severity(
            severity_inputs(individuals=5, data_encrypted=True, encryption_key_compromised=True)
        )
        self.assertEqual(without_key.score, 2)
        self.assertNotIn(
            "Data encrypted and key not compromised", [f.label for f in without_key.factors]
        )

    def test_no_data_and_no_people_scores_zero(self):
        result = calculate_severity(severity_inputs(has_other_personal_data=False))
        self.assertEqual(result.score, 0)


# --- Applicability rules (pure, no database) ----------------------------------


def facts(**overrides):
    return IncidentFacts(**overrides)


class LgpdRuleTests(TestCase):
    def test_not_applicable_without_brazilian_data_subjects(self):
        result = check_applicability("lgpd-anpd", facts(has_authentication=True))
        self.assertFalse(result.applies)

    def test_not_applicable_when_risk_is_unlikely(self):
        result = check_applicability(
            "lgpd-anpd",
            facts(
                individuals_by_jurisdiction={"BR": 10},
                has_authentication=True,
                risk_to_individuals="unlikely",
            ),
        )
        self.assertFalse(result.applies)

    def test_not_applicable_without_an_rcis_criterion(self):
        # Risk alone isn't enough: RCIS Art. 5 requires a criterion *cumulatively*.
        result = check_applicability("lgpd-anpd", facts(individuals_by_jurisdiction={"BR": 10}))
        self.assertFalse(result.applies)

    def test_applies_with_risk_and_a_criterion(self):
        result = check_applicability(
            "lgpd-data-subjects",
            facts(individuals_by_jurisdiction={"BR": 10}, has_authentication=True),
        )
        self.assertTrue(result.applies)
        self.assertTrue(any("authentication" in r for r in result.reasons))

    def test_large_scale_alone_is_a_criterion(self):
        result = check_applicability(
            "lgpd-anpd", facts(individuals_by_jurisdiction={"BR": 10}, is_large_scale=True)
        )
        self.assertTrue(result.applies)

    def test_incident_record_applies_even_when_nothing_is_communicated(self):
        result = check_applicability(
            "lgpd-incident-record",
            facts(individuals_by_jurisdiction={"BR": 10}, risk_to_individuals="unlikely"),
        )
        self.assertTrue(result.applies)


EU_ONLY = {"EU": 50}


class GdprRuleTests(TestCase):

    def test_authority_notice_applies_unless_risk_is_unlikely(self):
        self.assertTrue(
            check_applicability(
                "gdpr-supervisory-authority", facts(individuals_by_jurisdiction=EU_ONLY)
            ).applies
        )
        self.assertFalse(
            check_applicability(
                "gdpr-supervisory-authority",
                facts(individuals_by_jurisdiction=EU_ONLY, risk_to_individuals="unlikely"),
            ).applies
        )

    def test_data_subject_notice_needs_high_risk(self):
        self.assertFalse(
            check_applicability(
                "gdpr-data-subjects", facts(individuals_by_jurisdiction=EU_ONLY)
            ).applies
        )
        self.assertTrue(
            check_applicability(
                "gdpr-data-subjects",
                facts(individuals_by_jurisdiction=EU_ONLY, risk_to_individuals="high"),
            ).applies
        )

    def test_encryption_exception_to_data_subject_notice(self):
        result = check_applicability(
            "gdpr-data-subjects",
            facts(
                individuals_by_jurisdiction=EU_ONLY,
                risk_to_individuals="high",
                data_encrypted=True,
            ),
        )
        self.assertFalse(result.applies)
        self.assertIn("34(3)(a)", result.reasons[0])

    def test_encryption_exception_lost_when_key_compromised(self):
        result = check_applicability(
            "gdpr-data-subjects",
            facts(
                individuals_by_jurisdiction=EU_ONLY,
                risk_to_individuals="high",
                data_encrypted=True,
                encryption_key_compromised=True,
            ),
        )
        self.assertTrue(result.applies)

    def test_no_eu_data_subjects_means_no_gdpr_obligations(self):
        for code in ("gdpr-supervisory-authority", "gdpr-data-subjects", "gdpr-breach-record"):
            self.assertFalse(
                check_applicability(code, facts(risk_to_individuals="high")).applies
            )


class CaliforniaRuleTests(TestCase):
    def test_needs_a_qualifying_data_element(self):
        result = check_applicability(
            "ca-residents", facts(individuals_by_jurisdiction={"US-CA": 5})
        )
        self.assertFalse(result.applies)

    def test_applies_regardless_of_risk_assessment(self):
        # § 1798.82 has no risk-of-harm threshold.
        result = check_applicability(
            "ca-residents",
            facts(
                individuals_by_jurisdiction={"US-CA": 5},
                has_ca_breach_element=True,
                risk_to_individuals="unlikely",
            ),
        )
        self.assertTrue(result.applies)

    def test_encrypted_data_with_safe_key_is_exempt(self):
        result = check_applicability(
            "ca-residents",
            facts(
                individuals_by_jurisdiction={"US-CA": 5},
                has_ca_breach_element=True,
                data_encrypted=True,
            ),
        )
        self.assertFalse(result.applies)

    def test_attorney_general_threshold_is_more_than_500(self):
        at = facts(
            individuals_by_jurisdiction={"US-CA": CA_AG_THRESHOLD}, has_ca_breach_element=True
        )
        over = facts(
            individuals_by_jurisdiction={"US-CA": CA_AG_THRESHOLD + 1},
            has_ca_breach_element=True,
        )
        self.assertFalse(check_applicability("ca-attorney-general", at).applies)
        self.assertTrue(check_applicability("ca-attorney-general", over).applies)

    def test_ccpa_exposure_uses_its_own_definition(self):
        exposed = facts(individuals_by_jurisdiction={"US-CA": 5}, has_ccpa_150_element=True)
        self.assertTrue(check_applicability("ccpa-private-action", exposed).applies)
        self.assertFalse(
            check_applicability(
                "ccpa-private-action", facts(individuals_by_jurisdiction={"US-CA": 5})
            ).applies
        )

    def test_notice_without_ccpa_exposure_when_only_the_broader_definition_is_met(self):
        # E.g. self-reported physical conditions: "medical information" under
        # § 1798.82(i)(2), but not under § 1798.81.5(d)(2).
        physical_condition_only = facts(
            individuals_by_jurisdiction={"US-CA": 5},
            has_ca_breach_element=True,
            has_ccpa_150_element=False,
        )
        self.assertTrue(check_applicability("ca-residents", physical_condition_only).applies)
        self.assertFalse(
            check_applicability("ccpa-private-action", physical_condition_only).applies
        )

    def test_ccpa_exposure_is_cleared_by_encryption_with_a_safe_key(self):
        encrypted = facts(
            individuals_by_jurisdiction={"US-CA": 5},
            has_ccpa_150_element=True,
            data_encrypted=True,
        )
        self.assertFalse(check_applicability("ccpa-private-action", encrypted).applies)
        key_lost = facts(
            individuals_by_jurisdiction={"US-CA": 5},
            has_ccpa_150_element=True,
            data_encrypted=True,
            encryption_key_compromised=True,
        )
        self.assertTrue(check_applicability("ccpa-private-action", key_lost).applies)

    def test_unknown_requirement_code_is_never_applicable(self):
        self.assertFalse(check_applicability("not-a-rule", facts()).applies)


# --- Seeded legal content ------------------------------------------------------


class SeedContentTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        seed_quietly()

    def test_every_requirement_has_an_applicability_rule(self):
        codes = set(LegalRequirement.objects.values_list("code", flat=True))
        self.assertEqual(codes - set(APPLICABILITY_RULES), set())

    def test_verified_requirements_carry_source_and_date(self):
        for requirement in LegalRequirement.objects.filter(is_verified=True):
            with self.subTest(requirement.code):
                self.assertTrue(requirement.source_url)
                self.assertIsNotNone(requirement.verified_on)
                self.assertIn("VERIFIED", requirement.verification_notes)

    def test_unverified_requirements_carry_a_todo(self):
        # Every requirement is currently verified; this guards the policy for
        # any requirement added later without full verification.
        for requirement in LegalRequirement.objects.filter(is_verified=False):
            with self.subTest(requirement.code):
                self.assertTrue(requirement.verification_notes.startswith("TODO: VERIFY"))
                self.assertIsNone(requirement.verified_on)

    def test_fixed_deadlines_have_a_value(self):
        for requirement in LegalRequirement.objects.exclude(deadline_unit="none"):
            with self.subTest(requirement.code):
                self.assertIsNotNone(requirement.deadline_value)

    def test_sources_are_primary_or_regulatory(self):
        allowed = (
            "planalto.gov.br",
            "in.gov.br",
            "gov.br/anpd",
            "eur-lex.europa.eu",
            "edpb.europa.eu",
            "leginfo.legislature.ca.gov",
            "oag.ca.gov",
        )
        for requirement in LegalRequirement.objects.all():
            with self.subTest(requirement.code):
                self.assertTrue(any(domain in requirement.source_url for domain in allowed))

    def test_legal_content_refresh_keeps_incidents(self):
        LegalRequirement.objects.filter(code="gdpr-data-subjects").update(title="Stale title")
        DataCategory.objects.filter(name="Account Credentials").update(
            is_ccpa_150_element=False
        )
        incident_count = Incident.objects.count()
        record_count = NotificationRecord.objects.count()
        call_command("seed_incidents", "--legal-content-only", stdout=io.StringIO())
        self.assertTrue(
            DataCategory.objects.get(name="Account Credentials").is_ccpa_150_element
        )
        self.assertEqual(Incident.objects.count(), incident_count)
        self.assertEqual(NotificationRecord.objects.count(), record_count)
        self.assertEqual(
            LegalRequirement.objects.get(code="gdpr-data-subjects").title,
            "Communicate the breach to affected data subjects",
        )

    def test_lgpd_counting_method_is_labelled_as_an_interpretation(self):
        # The deadline figure is verified; how business days are counted is
        # not stated by Res. 15/2024, so it must be presented as an
        # interpretation with its sources, never as a verified rule.
        for code in ("lgpd-anpd", "lgpd-data-subjects"):
            with self.subTest(code):
                notes = LegalRequirement.objects.get(code=code).verification_notes
                self.assertIn("interpretation, not a verified rule", notes)
                self.assertIn("Res. 1/2021", notes)
                self.assertIn("9.784/1999", notes)
        self.assertNotIn("TODO", deadlines.BUSINESS_DAY_CAVEAT)
        self.assertIn("never later", deadlines.BUSINESS_DAY_CAVEAT)

    def test_sample_incidents_have_default_checklists(self):
        for incident in Incident.objects.all():
            self.assertEqual(incident.checklist_items.count(), len(DEFAULT_CHECKLIST))


# --- Evaluating obligations against saved incidents -----------------------------


class EvaluateObligationsTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        seed_quietly()
        cls.credentials = DataCategory.objects.get(name="Account Credentials")
        cls.requirements = list(LegalRequirement.objects.all())

    def make_incident(self, impacts, **fields):
        incident = Incident.objects.create(
            title="Test",
            summary="Test",
            incident_type=Incident.IncidentType.UNAUTHORIZED_ACCESS,
            discovered_at=FRIDAY_NOON,
            **fields,
        )
        incident.affected_data_categories.set([self.credentials])
        for jurisdiction, individuals in impacts.items():
            JurisdictionImpact.objects.create(
                incident=incident, jurisdiction=jurisdiction, individuals=individuals
            )
        return incident

    def evaluate(self, incident, now=FRIDAY_NOON):
        return {
            o.requirement.code: o
            for o in evaluate_obligations(incident, self.requirements, now)
        }

    def test_lgpd_deadline_is_three_business_days(self):
        obligations = self.evaluate(self.make_incident({"BR": 10}))
        self.assertEqual(
            obligations["lgpd-anpd"].due_at, datetime(2026, 9, 30, 23, 59, 59, tzinfo=UTC)
        )

    def test_small_agents_get_double_the_lgpd_deadline(self):
        incident = self.make_incident({"BR": 10}, controller_is_small_agent=True)
        obligation = self.evaluate(incident)["lgpd-anpd"]
        self.assertEqual(obligation.deadline_value, 6)
        self.assertEqual(obligation.due_at, datetime(2026, 10, 5, 23, 59, 59, tzinfo=UTC))

    def test_gdpr_deadline_is_72_hours_from_discovery(self):
        obligations = self.evaluate(self.make_incident({"EU": 10}))
        self.assertEqual(
            obligations["gdpr-supervisory-authority"].due_at, FRIDAY_NOON + timedelta(hours=72)
        )

    def test_attorney_general_deadline_is_projected_until_consumer_notice_is_sent(self):
        incident = self.make_incident({"US-CA": 600})
        projected = self.evaluate(incident)["ca-attorney-general"]
        self.assertTrue(projected.due_is_projected)
        # 30 calendar days to the consumer notice, then 15 more.
        self.assertEqual(projected.due_at.date(), date(2026, 11, 9))

        NotificationRecord.objects.create(
            incident=incident,
            requirement=LegalRequirement.objects.get(code="ca-residents"),
            sent_at=datetime(2026, 10, 1, 9, 0, tzinfo=UTC),
        )
        actual = self.evaluate(Incident.objects.get(pk=incident.pk))["ca-attorney-general"]
        self.assertFalse(actual.due_is_projected)
        self.assertEqual(actual.due_at, datetime(2026, 10, 16, 23, 59, 59, tzinfo=UTC))

    def test_status_moves_from_pending_to_overdue_to_sent(self):
        incident = self.make_incident({"EU": 10})
        self.assertEqual(
            self.evaluate(incident)["gdpr-supervisory-authority"].status, Status.PENDING
        )
        later = FRIDAY_NOON + timedelta(hours=80)
        self.assertEqual(
            self.evaluate(incident, now=later)["gdpr-supervisory-authority"].status,
            Status.OVERDUE,
        )
        NotificationRecord.objects.create(
            incident=incident,
            requirement=LegalRequirement.objects.get(code="gdpr-supervisory-authority"),
            sent_at=FRIDAY_NOON + timedelta(hours=75),
        )
        sent = self.evaluate(Incident.objects.get(pk=incident.pk), now=later)[
            "gdpr-supervisory-authority"
        ]
        self.assertEqual(sent.status, Status.SENT)
        self.assertTrue(sent.sent_late)

    def test_record_keeping_has_no_countdown(self):
        obligation = self.evaluate(self.make_incident({"EU": 10}))["gdpr-breach-record"]
        self.assertEqual(obligation.status, Status.ONGOING)
        self.assertIsNone(obligation.due_at)


# --- Views -----------------------------------------------------------------------


class ViewTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        seed_quietly()

    def incident(self, title_fragment):
        return Incident.objects.get(title__icontains=title_fragment)

    def test_dashboard_lists_every_incident(self):
        response = self.client.get(reverse("incidents:dashboard"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.context["rows"]), 4)

    def test_filter_by_severity(self):
        response = self.client.get(reverse("incidents:dashboard"), {"severity": "low"})
        self.assertEqual(
            [r.incident.title for r in response.context["rows"]],
            [self.incident("laptop").title],
        )

    def test_filter_by_framework(self):
        response = self.client.get(reverse("incidents:dashboard"), {"framework": "lgpd"})
        titles = {r.incident.title for r in response.context["rows"]}
        self.assertEqual(
            titles, {self.incident("admin credential").title, self.incident("Ransomware").title}
        )

    def test_filter_by_jurisdiction_and_containment(self):
        response = self.client.get(
            reverse("incidents:dashboard"), {"jurisdiction": "US-CA", "containment": "resolved"}
        )
        self.assertEqual(
            [r.incident.title for r in response.context["rows"]],
            [self.incident("laptop").title],
        )

    def test_search(self):
        response = self.client.get(reverse("incidents:dashboard"), {"q": "ransomware"})
        self.assertEqual(len(response.context["rows"]), 1)

    def test_invalid_filter_values_are_ignored(self):
        response = self.client.get(
            reverse("incidents:dashboard"), {"severity": "apocalyptic", "framework": "' OR 1=1"}
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.context["rows"]), 4)
        self.assertFalse(response.context["filters"].is_active)

    def test_detail_shows_obligations(self):
        response = self.client.get(
            reverse("incidents:incident_detail", args=[self.incident("admin credential").pk])
        )
        self.assertContains(response, "Notify the supervisory authority")
        self.assertNotContains(response, "Unverified")
        self.assertContains(response, "not an official classification system")

    def test_unknown_incident_is_404(self):
        response = self.client.get(reverse("incidents:incident_detail", args=[9999]))
        self.assertEqual(response.status_code, 404)

    def test_legal_sources_page_shows_every_requirement(self):
        response = self.client.get(reverse("incidents:legal_sources"))
        self.assertEqual(
            len(response.context["requirements"]), LegalRequirement.objects.count()
        )
        self.assertEqual(response.context["unverified_count"], 0)
        self.assertNotContains(response, "TODO: VERIFY")

    def test_support_partner_incident_owes_a_california_notice_but_no_ccpa_exposure(self):
        # Self-reported accessibility needs: § 1798.82 notice, no § 1798.150 flag.
        incident = self.incident("wrong customer")
        row = {
            o.requirement.code: o
            for o in evaluate_obligations(
                incident, list(LegalRequirement.objects.all()), timezone.now()
            )
        }
        self.assertTrue(row["ca-residents"].applies)
        self.assertFalse(row["ccpa-private-action"].applies)

    def test_about_links_to_projects_1_to_3(self):
        response = self.client.get(reverse("incidents:about"))
        for repo in (
            "lgpd-gdpr-ccpa-comparative-analysis",
            "data-mapping-ropa",
            "dpia-privacy-impact-assessment",
        ):
            self.assertContains(response, repo)


class IncidentFormTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        seed_quietly()
        cls.credentials = DataCategory.objects.get(name="Account Credentials")

    def form_data(self, **overrides):
        data = {
            "title": "Phishing of a support agent",
            "summary": "Agent credentials phished.",
            "incident_type": "unauthorized_access",
            "discovered_at": (timezone.now() - timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M"),
            "containment_status": "investigating",
            "risk_to_individuals": "risk",
            "affected_data_categories": [self.credentials.pk],
            "individuals_br": "12",
            "individuals_eu": "0",
            "individuals_us_ca": "700",
            "individuals_us_other": "",
            "individuals_other": "",
        }
        data.update(overrides)
        return data

    def test_create_incident_with_checklist_timeline_and_impacts(self):
        response = self.client.post(reverse("incidents:incident_create"), self.form_data())
        incident = Incident.objects.get(title="Phishing of a support agent")
        self.assertRedirects(response, reverse("incidents:incident_detail", args=[incident.pk]))
        self.assertTrue(incident.reference.startswith("INC-"))
        self.assertEqual(incident.checklist_items.count(), len(DEFAULT_CHECKLIST))
        self.assertEqual(incident.timeline_events.count(), 1)
        self.assertEqual(
            {i.jurisdiction: i.individuals for i in incident.jurisdiction_impacts.all()},
            {"BR": 12, "US-CA": 700},
        )

    def test_discovery_in_the_future_is_rejected(self):
        future = (timezone.now() + timedelta(days=1)).strftime("%Y-%m-%dT%H:%M")
        response = self.client.post(
            reverse("incidents:incident_create"), self.form_data(discovered_at=future)
        )
        self.assertEqual(response.status_code, 200)
        self.assertFormError(
            response.context["form"], "discovered_at", "Discovery can't be in the future."
        )

    def test_key_compromise_requires_encryption(self):
        response = self.client.post(
            reverse("incidents:incident_create"),
            self.form_data(encryption_key_compromised="on"),
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("encryption_key_compromised", response.context["form"].errors)

    def test_occurrence_after_discovery_is_rejected(self):
        response = self.client.post(
            reverse("incidents:incident_create"),
            self.form_data(occurred_at=timezone.now().strftime("%Y-%m-%dT%H:%M")),
        )
        self.assertIn("occurred_at", response.context["form"].errors)

    def test_edit_updates_and_removes_jurisdiction_rows(self):
        self.client.post(reverse("incidents:incident_create"), self.form_data())
        incident = Incident.objects.get(title="Phishing of a support agent")
        self.client.post(
            reverse("incidents:incident_edit", args=[incident.pk]),
            self.form_data(individuals_br="0", individuals_us_ca="701"),
        )
        self.assertEqual(
            {i.jurisdiction: i.individuals for i in incident.jurisdiction_impacts.all()},
            {"US-CA": 701},
        )


class DetailActionTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        seed_quietly()
        cls.incident = Incident.objects.get(title__icontains="admin credential")

    def test_update_checklist_item(self):
        item = self.incident.checklist_items.get(order=12)
        self.client.post(
            reverse("incidents:checklist_update", args=[item.pk]),
            {f"item-{item.pk}-owner": "Platform Team", f"item-{item.pk}-status": "done"},
        )
        item.refresh_from_db()
        self.assertEqual(
            (item.owner, item.status), ("Platform Team", ChecklistItem.Status.DONE)
        )

    def test_invalid_checklist_status_is_rejected(self):
        item = self.incident.checklist_items.get(order=12)
        self.client.post(
            reverse("incidents:checklist_update", args=[item.pk]),
            {f"item-{item.pk}-owner": "X", f"item-{item.pk}-status": "exploded"},
        )
        item.refresh_from_db()
        self.assertEqual(item.status, ChecklistItem.Status.TODO)

    def test_add_checklist_item(self):
        self.client.post(
            reverse("incidents:checklist_add", args=[self.incident.pk]),
            {"title": "Brief customer support on FAQs", "owner": "Support"},
        )
        self.assertTrue(
            self.incident.checklist_items.filter(title__startswith="Brief").exists()
        )

    def test_add_timeline_event(self):
        self.client.post(
            reverse("incidents:timeline_add", args=[self.incident.pk]),
            {"occurred_at": "2026-09-01T10:00", "description": "Forensics firm engaged."},
        )
        self.assertTrue(
            self.incident.timeline_events.filter(description="Forensics firm engaged.").exists()
        )

    def test_record_notification_also_logs_timeline(self):
        requirement = LegalRequirement.objects.get(code="gdpr-supervisory-authority")
        sent = (timezone.now() - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M")
        self.client.post(
            reverse("incidents:notification_record", args=[self.incident.pk, requirement.pk]),
            {"sent_at": sent, "reference": "SA-1"},
        )
        self.assertTrue(
            NotificationRecord.objects.filter(
                incident=self.incident, requirement=requirement
            ).exists()
        )
        self.assertTrue(
            TimelineEvent.objects.filter(
                incident=self.incident, description__contains=requirement.title
            ).exists()
        )

    def test_notification_cannot_be_recorded_in_the_future(self):
        requirement = LegalRequirement.objects.get(code="gdpr-supervisory-authority")
        future = (timezone.now() + timedelta(days=1)).strftime("%Y-%m-%dT%H:%M")
        self.client.post(
            reverse("incidents:notification_record", args=[self.incident.pk, requirement.pk]),
            {"sent_at": future},
        )
        self.assertFalse(
            NotificationRecord.objects.filter(
                requirement=requirement, incident=self.incident
            ).exists()
        )

    def test_cannot_record_a_non_notification_requirement(self):
        requirement = LegalRequirement.objects.get(code="gdpr-breach-record")
        response = self.client.post(
            reverse("incidents:notification_record", args=[self.incident.pk, requirement.pk]),
            {"sent_at": "2026-09-01T10:00"},
        )
        self.assertEqual(response.status_code, 404)

    def test_actions_reject_get(self):
        response = self.client.get(reverse("incidents:timeline_add", args=[self.incident.pk]))
        self.assertEqual(response.status_code, 405)


# --- PDF export ---------------------------------------------------------------------


class PdfExportTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        seed_quietly()
        cls.incident = Incident.objects.get(title__icontains="admin credential")

    def pdf_text(self, incident):
        response = self.client.get(reverse("incidents:export_pdf", args=[incident.pk]))
        self.assertEqual(response["Content-Type"], "application/pdf")
        self.assertIn(incident.reference, response["Content-Disposition"])
        reader = PdfReader(io.BytesIO(response.content))
        return " ".join(page.extract_text() for page in reader.pages)

    def test_pdf_contains_every_section_and_disclaimers(self):
        text = self.pdf_text(self.incident)
        for heading in (
            "Incident summary",
            "Scope",
            "Severity",
            "Notification",
            "Response checklist",
            "Timeline",
        ):
            self.assertIn(heading, text)
        self.assertIn(self.incident.reference, text)
        self.assertIn("does not constitute legal advice", text)
        self.assertIn("not an official classification", text)
        self.assertNotIn("UNVERIFIED", text)

    def test_pdf_preserves_markup_characters_in_free_text(self):
        self.incident.summary = "Attacker used <script> & SQL <b>injection</b>"
        self.incident.save()
        text = self.pdf_text(self.incident)
        self.assertIn("<script> & SQL <b>injection</b>", text)


# --- Hardening ------------------------------------------------------------------------


class ReferenceTests(TestCase):
    def make(self):
        return Incident.objects.create(
            title="T", summary="S", incident_type="other", discovered_at=FRIDAY_NOON
        )

    def test_references_are_sequential_per_discovery_year(self):
        self.assertEqual(
            [self.make().reference for _ in range(3)],
            ["INC-2026-001", "INC-2026-002", "INC-2026-003"],
        )

    def test_deleting_an_incident_never_causes_a_collision(self):
        first, _second = self.make(), self.make()
        first.delete()
        # A row count would produce INC-2026-002 again and hit the unique
        # constraint; the highest used number gives INC-2026-003.
        self.assertEqual(self.make().reference, "INC-2026-003")


class ModelValidationTests(TestCase):
    """The rules live on the models, so the admin enforces them too."""

    def test_incident_clean_rejects_future_discovery_and_bad_encryption_flags(self):
        incident = Incident(
            title="T",
            summary="S",
            incident_type="other",
            discovered_at=timezone.now() + timedelta(days=1),
            encryption_key_compromised=True,
        )
        with self.assertRaises(ValidationError) as ctx:
            incident.full_clean()
        self.assertIn("discovered_at", ctx.exception.message_dict)
        self.assertIn("encryption_key_compromised", ctx.exception.message_dict)

    def test_oversized_free_text_is_rejected_by_model_forms(self):
        # TextField's max_length is enforced by every form built from the
        # model — the same way the admin builds its forms.
        form_class = modelform_factory(Incident, fields=("summary",))
        form = form_class(data={"summary": "x" * 5001})
        self.assertFalse(form.is_valid())
        self.assertIn("summary", form.errors)


class InputLimitTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        seed_quietly()

    def test_head_count_beyond_the_ceiling_is_a_form_error_not_a_server_error(self):
        response = self.client.post(
            reverse("incidents:incident_create"),
            {
                "title": "Huge",
                "summary": "S",
                "incident_type": "other",
                "discovered_at": (timezone.now() - timedelta(hours=1)).strftime(
                    "%Y-%m-%dT%H:%M"
                ),
                "containment_status": "investigating",
                "risk_to_individuals": "risk",
                "individuals_br": "99999999999",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("individuals_br", response.context["form"].errors)
        self.assertFalse(Incident.objects.filter(title="Huge").exists())


class RateLimitTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        seed_quietly()
        cls.incident = Incident.objects.first()

    def test_writes_are_limited_per_visitor(self):
        url = reverse("incidents:timeline_add", args=[self.incident.pk])
        data = {"occurred_at": "2026-09-01T10:00", "description": "Event"}
        statuses = [self.client.post(url, data).status_code for _ in range(31)]
        self.assertEqual(statuses[:30], [302] * 30)
        self.assertEqual(statuses[30], 403)
        self.assertEqual(self.incident.timeline_events.filter(description="Event").count(), 30)

    def test_pdf_exports_are_limited_per_visitor(self):
        url = reverse("incidents:export_pdf", args=[self.incident.pk])
        statuses = [self.client.get(url).status_code for _ in range(11)]
        self.assertEqual(statuses[:10], [200] * 10)
        self.assertEqual(statuses[10], 403)


class ClientIpTests(TestCase):
    """The rate-limit key trusts X-Real-IP only where the platform
    guarantees it (Vercel); elsewhere it could be forged to dodge limits."""

    def request(self, **meta):
        from django.test import RequestFactory

        return RequestFactory().get("/", REMOTE_ADDR="10.0.0.1", **meta)

    def test_header_is_ignored_off_vercel(self):
        with self.settings(RUNNING_ON_VERCEL=False):
            self.assertEqual(client_ip("g", self.request(HTTP_X_REAL_IP="1.2.3.4")), "10.0.0.1")

    def test_header_is_used_on_vercel(self):
        with self.settings(RUNNING_ON_VERCEL=True):
            self.assertEqual(client_ip("g", self.request(HTTP_X_REAL_IP="1.2.3.4")), "1.2.3.4")

    def test_falls_back_to_remote_addr_on_vercel_without_header(self):
        with self.settings(RUNNING_ON_VERCEL=True):
            self.assertEqual(client_ip("g", self.request()), "10.0.0.1")

    def test_forged_header_cannot_reset_the_budget_off_vercel(self):
        seed_quietly()
        url = reverse("incidents:export_pdf", args=[Incident.objects.first().pk])
        statuses = [
            self.client.get(url, HTTP_X_REAL_IP=f"203.0.113.{n}").status_code for n in range(11)
        ]
        self.assertEqual(statuses[10], 403)


class SecurityHeaderTests(TestCase):
    def test_pages_send_a_strict_content_security_policy(self):
        response = self.client.get(reverse("incidents:about"))
        policy = response["Content-Security-Policy"]
        self.assertIn("default-src 'self'", policy)
        self.assertIn("frame-ancestors 'none'", policy)
        self.assertNotIn("unsafe-inline", policy)
        self.assertEqual(response["X-Frame-Options"], "DENY")

    def test_missing_page_uses_the_project_404_template(self):
        response = self.client.get("/does-not-exist/")
        self.assertEqual(response.status_code, 404)
        self.assertTemplateUsed(response, "404.html")


class SettingsFailSafeTests(TestCase):
    """Imports the settings in a fresh interpreter with a given environment,
    since settings are evaluated once per process."""

    def load_settings(self, expression="s.DEBUG", **env):
        clean_env = {
            k: v
            for k, v in os.environ.items()
            if k
            not in (
                "VERCEL",
                "DJANGO_DEBUG",
                "DJANGO_SECRET_KEY",
                "DATABASE_URL",
                "POSTGRES_URL",
            )
        }
        clean_env.update(env)
        return subprocess.run(
            [sys.executable, "-c", f"import config.settings as s; print({expression})"],
            cwd=Path(__file__).resolve().parent.parent,
            env=clean_env,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_vercel_without_a_secret_key_refuses_to_start(self):
        result = self.load_settings(VERCEL="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("DJANGO_SECRET_KEY must be set", result.stderr)

    def test_vercel_defaults_debug_off(self):
        result = self.load_settings(VERCEL="1", DJANGO_SECRET_KEY="test-only-key")
        self.assertEqual(result.stdout.strip(), "False")

    def test_local_development_still_works_with_zero_configuration(self):
        result = self.load_settings()
        self.assertEqual(result.stdout.strip(), "True")

    def test_rate_limit_counters_are_shared_when_a_database_is_configured(self):
        # Per-process memory would give every serverless instance its own
        # counters; with a database the cache (and the limits) are shared.
        backend = "s.CACHES['default']['BACKEND']"
        with_db = self.load_settings(backend, DATABASE_URL="postgres://u:p@localhost:5432/db")
        self.assertEqual(with_db.stdout.strip(), "django.core.cache.backends.db.DatabaseCache")
        local = self.load_settings("getattr(s, 'CACHES', 'default in-memory')")
        self.assertEqual(local.stdout.strip(), "default in-memory")
