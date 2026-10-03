"""
Seeds the legal requirements, NimbusCart's reference data (data
categories and processing activities reused from Data-Mapping-ROPA, plus
IT systems), and four fictional sample incidents.

Content policy for LEGAL_REQUIREMENTS (same as the LGPD-GDPR-CCPA-Comparative-Analysis seed data):
  - Every requirement seeded with `is_verified=True` was checked against a
    primary or authoritative regulatory source on VERIFICATION_DATE; its
    `source_url` points at the source used and its `verification_notes`
    record exactly what was checked (article, paragraph, amendment).
  - Anything that could NOT be fully confirmed is seeded with
    `is_verified=False` and a note starting "TODO: VERIFY ..." — never
    marked verified on the strength of memory or a secondary source.
  - Deadlines, thresholds, authorities and statute numbers appear only in
    this list; nothing in the decision logic (incidents/obligations.py)
    restates a deadline — it reads them from these rows. The one
    exception is California's "more than 500 residents" threshold
    (obligations.CA_AG_THRESHOLD), verified alongside the row that cites it.

Sample incidents are dated relative to the moment the seed runs, so the
deadline countdowns are live in a fresh demo. Re-run the seed to reset the
clocks.

Run with: python manage.py seed_incidents
Safe to re-run: clears incidents and reference data first (--keep to skip).

After re-verifying legal content, refresh just that content — the legal
requirements and the data categories' legal classification — leaving
incidents, their notification records and everything else untouched, with:
    python manage.py seed_incidents --legal-content-only
"""

from datetime import date, timedelta
from typing import Any

from django.core.management.base import BaseCommand
from django.db import transaction
from django.utils import timezone

from incidents.checklist import create_default_checklist
from incidents.models import (
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

# Date the legal content below was last checked against primary/regulatory
# sources. Update it whenever the content is re-verified.
VERIFICATION_DATE = date(2026, 9, 26)

PLANALTO_LGPD = (
    "https://www.planalto.gov.br/ccivil_03/_ato2015-2018/2018/lei/l13709compilado.htm"
)
ANPD_RCIS = (
    "https://www.in.gov.br/en/web/dou/-/resolucao-cd/anpd-n-15-de-24-de-abril-de-2024-556243024"
)
EUR_LEX_GDPR = "https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:32016R0679"
EDPB_GUIDELINES_9_2022 = (
    "https://www.edpb.europa.eu/system/files/2023-04/"
    "edpb_guidelines_202209_personal_data_breach_notification_v2.0_en.pdf"
)
CA_CIV_1798_82 = "https://leginfo.legislature.ca.gov/faces/codes_displaySection.xhtml?lawCode=CIV&sectionNum=1798.82."
CA_CIV_1798_150 = "https://leginfo.legislature.ca.gov/faces/codes_displaySection.xhtml?lawCode=CIV&sectionNum=1798.150."
CPPA_CPI_ADJUSTMENT = "https://www.cppa.ca.gov/regulations/cpi_adjustment.html"

_RCIS_VERIFIED = (
    f"VERIFIED {VERIFICATION_DATE} against planalto.gov.br (Lei 13.709/2018, Art. 48 caput and "
    "§1: communication 'em prazo razoável, conforme definido pela autoridade nacional') and the "
    "Diário Oficial da União text of Resolução CD/ANPD nº 15/2024 (in.gov.br)"
)

# Res. 15/2024 doesn't say how its business days are counted. The deadline
# figure itself is verified; the counting method is a documented
# interpretation, spelled out here and in incidents/deadlines.py.
_COUNTING_NOTE = (
    "COUNTING METHOD (interpretation, not a verified rule): Res. 15/2024 and the ANPD's "
    "incident-communication page don't say how the business days are counted. The tool "
    "applies by analogy Resolução CD/ANPD nº 1/2021, Art. 8 (gov.br/anpd: business days, "
    "start day excluded, end day included, extension when the ANPD's headquarters has no "
    "working hours on the last day) and Lei 9.784/1999, Art. 66 (planalto.gov.br: start day "
    "excluded, end day included), both checked 2026-09-26. Art. 8 governs Res. 1/2021's "
    "own deadlines, so it applies here by analogy only. On the points left open, the tool "
    "takes the conservative reading: public holidays are not skipped and days end at "
    "23:59 UTC, so the date shown is never later than the analogy gives. See "
    "incidents/deadlines.py."
)

LEGAL_REQUIREMENTS: list[dict[str, Any]] = [
    {
        "code": "lgpd-anpd",
        "framework": LegalRequirement.Framework.LGPD,
        "kind": LegalRequirement.Kind.NOTIFICATION,
        "title": "Communicate the incident to the ANPD",
        "recipient": "ANPD (Autoridade Nacional de Proteção de Dados), via its electronic form",
        "trigger_summary": (
            "A security incident that may cause relevant risk or damage to data subjects: it may "
            "significantly affect their interests and fundamental rights AND, cumulatively, "
            "involves at least one of: sensitive personal data; data of children, adolescents or "
            "elderly people; financial data; system authentication data; data under legal, "
            "judicial or professional secrecy; or large-scale data."
        ),
        "deadline_unit": LegalRequirement.DeadlineUnit.BUSINESS_DAYS,
        "deadline_value": 3,
        "deadline_text": (
            "3 business days (três dias úteis) from the controller's knowledge that the incident "
            "affected personal data; doubled for small-scale agents; the information may be "
            "supplemented within 20 business days"
        ),
        "citation": "LGPD Art. 48; Resolução CD/ANPD nº 15/2024 (RCIS), Arts. 5 and 6",
        "source_url": ANPD_RCIS,
        "is_verified": True,
        "verified_on": VERIFICATION_DATE,
        "verification_notes": (
            f"{_RCIS_VERIFIED}: Anexo, Art. 5 caput and incisos I-VI (relevant risk or damage "
            "criteria) and §2 (large scale); Art. 6 caput (três dias úteis, save a deadline in "
            "specific legislation), §1 (counted from knowledge that the incident affected "
            "personal data), §3 (supplement within vinte dias úteis), §4 (ANPD electronic form), "
            "§8 (deadlines doubled for agentes de pequeno porte). The ANPD's regulations index "
            "(gov.br/anpd) listed Res. 15/2024 as 'Vigente' with no amendments noted. "
            + _COUNTING_NOTE
        ),
        "order": 10,
    },
    {
        "code": "lgpd-data-subjects",
        "framework": LegalRequirement.Framework.LGPD,
        "kind": LegalRequirement.Kind.NOTIFICATION,
        "title": "Communicate the incident to affected data subjects",
        "recipient": (
            "Affected data subjects (titulares) — directly and individually where possible, in "
            "plain language; otherwise through public channels (website, apps, social media)"
        ),
        "trigger_summary": "Same trigger as the ANPD communication (relevant risk or damage).",
        "deadline_unit": LegalRequirement.DeadlineUnit.BUSINESS_DAYS,
        "deadline_value": 3,
        "deadline_text": (
            "3 business days (três dias úteis) from the controller's knowledge that the incident "
            "affected personal data; doubled for small-scale agents"
        ),
        "citation": "LGPD Art. 48; Resolução CD/ANPD nº 15/2024 (RCIS), Art. 9",
        "source_url": ANPD_RCIS,
        "is_verified": True,
        "verified_on": VERIFICATION_DATE,
        "verification_notes": (
            f"{_RCIS_VERIFIED}: Anexo, Art. 9 caput (três dias úteis from knowledge that the "
            "incident affected personal data; required content I-VII), §1 (simple language; "
            "direct and individualized where subjects can be identified), §3 (public channels "
            "when direct communication is unfeasible), §6 (deadline doubled for agentes de "
            "pequeno porte). " + _COUNTING_NOTE
        ),
        "order": 20,
    },
    {
        "code": "lgpd-incident-record",
        "framework": LegalRequirement.Framework.LGPD,
        "kind": LegalRequirement.Kind.RECORD,
        "title": "Keep a record of the incident",
        "recipient": "Internal incident register (producible to the ANPD)",
        "trigger_summary": (
            "Every security incident, including those not communicated to the ANPD or to data "
            "subjects."
        ),
        "deadline_unit": LegalRequirement.DeadlineUnit.NONE,
        "deadline_value": None,
        "deadline_text": "Retain for at least 5 years from the date of the record",
        "citation": "Resolução CD/ANPD nº 15/2024 (RCIS), Art. 10",
        "source_url": ANPD_RCIS,
        "is_verified": True,
        "verified_on": VERIFICATION_DATE,
        "verification_notes": (
            f"{_RCIS_VERIFIED}: Anexo, Art. 10 caput (record kept 'pelo prazo mínimo de cinco "
            "anos, contado a partir da data do registro', including incidents not communicated) "
            "and §1 (minimum content)."
        ),
        "order": 30,
    },
    {
        "code": "gdpr-supervisory-authority",
        "framework": LegalRequirement.Framework.GDPR,
        "kind": LegalRequirement.Kind.NOTIFICATION,
        "title": "Notify the supervisory authority",
        "recipient": (
            "Competent supervisory authority. NimbusCart (fictional) has no EU establishment, so "
            "every supervisory authority of a Member State where affected data subjects reside"
        ),
        "trigger_summary": (
            "Any personal data breach, unless it is unlikely to result in a risk to the rights "
            "and freedoms of natural persons."
        ),
        "deadline_unit": LegalRequirement.DeadlineUnit.HOURS,
        "deadline_value": 72,
        "deadline_text": (
            "Without undue delay and, where feasible, not later than 72 hours after having "
            "become aware of it; a later notification must give reasons for the delay; "
            "information may be provided in phases"
        ),
        "citation": "GDPR Art. 33(1), (3)-(4); EDPB Guidelines 9/2022, paras. 72-73",
        "source_url": EUR_LEX_GDPR,
        "is_verified": True,
        "verified_on": VERIFICATION_DATE,
        "verification_notes": (
            f"VERIFIED {VERIFICATION_DATE} against eur-lex.europa.eu (Regulation (EU) 2016/679, "
            "Art. 33(1) '72 hours after having become aware', risk exception and reasons for "
            "delay; Art. 33(3) minimum content; Art. 33(4) phased information; Art. 4(12) "
            "definition of personal data breach) and EDPB Guidelines 9/2022 v2.0 (adopted 28 "
            "March 2023, edpb.europa.eu), paras. 72-73: a controller not established in the EU "
            "is still bound by Arts. 33-34, and a mere Art. 27 representative doesn't trigger "
            "the one-stop-shop, so the breach is notified to every supervisory authority for "
            "which affected data subjects reside in their Member State."
        ),
        "order": 40,
    },
    {
        "code": "gdpr-data-subjects",
        "framework": LegalRequirement.Framework.GDPR,
        "kind": LegalRequirement.Kind.NOTIFICATION,
        "title": "Communicate the breach to affected data subjects",
        "recipient": "Affected data subjects, in clear and plain language",
        "trigger_summary": (
            "The breach is likely to result in a high risk to the rights and freedoms of natural "
            "persons — unless the data was rendered unintelligible (e.g. encryption), subsequent "
            "measures mean the high risk is no longer likely to materialise, or it would involve "
            "disproportionate effort (then a public communication instead)."
        ),
        "deadline_unit": LegalRequirement.DeadlineUnit.NONE,
        "deadline_value": None,
        "deadline_text": "Without undue delay (no fixed number of hours or days)",
        "citation": "GDPR Art. 34(1)-(3)",
        "source_url": EUR_LEX_GDPR,
        "is_verified": True,
        "verified_on": VERIFICATION_DATE,
        "verification_notes": (
            f"VERIFIED {VERIFICATION_DATE} against eur-lex.europa.eu (Regulation (EU) 2016/679, "
            "Art. 34(1) 'likely to result in a high risk' / 'without undue delay'; Art. 34(2) "
            "content; Art. 34(3)(a)-(c) exceptions; Art. 34(4) supervisory authority may require "
            "communication)."
        ),
        "order": 50,
    },
    {
        "code": "gdpr-breach-record",
        "framework": LegalRequirement.Framework.GDPR,
        "kind": LegalRequirement.Kind.RECORD,
        "title": "Document the breach",
        "recipient": "Internal breach register (producible to the supervisory authority)",
        "trigger_summary": "Every personal data breach, whether notified or not.",
        "deadline_unit": LegalRequirement.DeadlineUnit.NONE,
        "deadline_value": None,
        "deadline_text": (
            "Ongoing: facts, effects and remedial action, sufficient for the supervisory "
            "authority to verify compliance"
        ),
        "citation": "GDPR Art. 33(5)",
        "source_url": EUR_LEX_GDPR,
        "is_verified": True,
        "verified_on": VERIFICATION_DATE,
        "verification_notes": (
            f"VERIFIED {VERIFICATION_DATE} against eur-lex.europa.eu (Regulation (EU) 2016/679, "
            "Art. 33(5))."
        ),
        "order": 60,
    },
    {
        "code": "ca-residents",
        "framework": LegalRequirement.Framework.CA_BREACH,
        "kind": LegalRequirement.Kind.NOTIFICATION,
        "title": "Notify affected California residents",
        "recipient": "Affected California residents",
        "trigger_summary": (
            "A breach of the security of the system in which a California resident's "
            "unencrypted personal information — as defined in subdivision (h) — was, or is "
            "reasonably believed to have been, acquired by an unauthorized person (or encrypted "
            "information together with its key or credential). No risk-of-harm test."
        ),
        "deadline_unit": LegalRequirement.DeadlineUnit.CALENDAR_DAYS,
        "deadline_value": 30,
        "deadline_text": (
            "Within 30 calendar days of discovery or notification of the breach; may be delayed "
            "for the legitimate needs of law enforcement or as necessary to determine the scope "
            "of the breach and restore the reasonable integrity of the data system"
        ),
        "citation": "Cal. Civ. Code § 1798.82(a)",
        "source_url": CA_CIV_1798_82,
        "is_verified": True,
        "verified_on": VERIFICATION_DATE,
        "verification_notes": (
            f"VERIFIED {VERIFICATION_DATE} against leginfo.legislature.ca.gov (Civ. Code "
            "§ 1798.82(a)(1) trigger; (a)(2)(A) 'within 30 calendar days of discovery or "
            "notification of the data breach'; (a)(2)(B) permitted delay; (c) law enforcement "
            "delay; (h)(1)(A)-(H) and (h)(2) definition of personal information; (i)(4) "
            "'encrypted'). Current text as amended by Stats. 2025, Ch. 319 (SB 446), effective "
            "January 1, 2026. No risk-of-harm threshold appears in the section."
        ),
        "order": 70,
    },
    {
        "code": "ca-attorney-general",
        "framework": LegalRequirement.Framework.CA_BREACH,
        "kind": LegalRequirement.Kind.NOTIFICATION,
        "title": "Submit a sample notice to the California Attorney General",
        "recipient": (
            "California Attorney General — a single sample copy of the notice, excluding "
            "personally identifiable information, submitted electronically"
        ),
        "trigger_summary": (
            "More than 500 California residents must be notified as a result of a single breach."
        ),
        "deadline_unit": LegalRequirement.DeadlineUnit.CALENDAR_DAYS,
        "deadline_value": 15,
        "deadline_text": "Within 15 calendar days of notifying affected consumers",
        "citation": "Cal. Civ. Code § 1798.82(f)",
        "source_url": CA_CIV_1798_82,
        "is_verified": True,
        "verified_on": VERIFICATION_DATE,
        "verification_notes": (
            f"VERIFIED {VERIFICATION_DATE} against leginfo.legislature.ca.gov (Civ. Code "
            "§ 1798.82(f): more than 500 California residents; single sample copy excluding PII, "
            "submitted electronically to the Attorney General 'within 15 calendar days of "
            "notifying affected consumers'), as amended by Stats. 2025, Ch. 319 (SB 446)."
        ),
        "order": 80,
    },
    {
        "code": "ccpa-private-action",
        "framework": LegalRequirement.Framework.CCPA,
        "kind": LegalRequirement.Kind.EXPOSURE,
        "title": "Private right of action for data breaches (exposure flag)",
        "recipient": "No notice owed — potential consumer litigation exposure",
        "trigger_summary": (
            "A consumer whose nonencrypted and nonredacted personal information (name plus an "
            "element listed in § 1798.81.5(d)(1)(A)), or whose email address with a password or "
            "security question and answer, is subject to unauthorized access and exfiltration, "
            "theft or disclosure as a result of the "
            "business's failure to implement and maintain reasonable security may sue for "
            "statutory damages of $107-$799 per consumer per incident (the statute's base "
            "$100-$750 figures, as CPI-adjusted under § 1798.199.95(d) effective January 1, "
            "2025; next adjustment January 1, 2027) (or actual damages, if greater), after "
            "giving the business 30 days' written notice and an opportunity to cure. Breach "
            "notice itself is governed by § 1798.82 (tracked above)."
        ),
        "deadline_unit": LegalRequirement.DeadlineUnit.NONE,
        "deadline_value": None,
        "deadline_text": "Not a notification deadline",
        "citation": "Cal. Civ. Code § 1798.150(a)(1), (b); § 1798.81.5(d)(1)-(2); § 1798.199.95(d)",
        "source_url": CA_CIV_1798_150,
        "is_verified": True,
        "verified_on": date(2026, 10, 2),
        "verification_notes": (
            f"VERIFIED {VERIFICATION_DATE} against leginfo.legislature.ca.gov: § 1798.150(a)(1) "
            "(nonencrypted and nonredacted personal information 'as defined in subparagraph (A) "
            "of paragraph (1) of subdivision (d) of Section 1798.81.5', or an email address with a "
            "password or security question and answer — not 'username', unlike § 1798.82(h)(2) — "
            "unauthorized access and exfiltration, theft or disclosure; reasonable-security duty; "
            "statute's base figures $100-$750 per consumer per incident or actual damages, "
            "adjusted under § 1798.199.95(d)) and (b) (30 days' written notice and cure), as "
            "amended by Stats. 2024, Ch. 121 (AB 3286); § 1798.81.5(d)(1)(A)(i)-(vii) and (d)(2), "
            "as amended by Stats. 2021, Ch. 527 (AB 825); § 1798.81.5(d)(1)(B) confirms the "
            "name+element list in (A) is the only part of § 1798.81.5(d) that § 1798.150(a)(1) "
            "cross-references (it does not pull in (B)'s separate username-or-email option). That "
            "(A) list matches § 1798.82(h)(1) except that it has no ALPR element, but "
            "§ 1798.81.5(d)(2) defines 'medical information' more narrowly than § 1798.82(i)(2) "
            "(no 'mental or physical condition'), so the tool classifies categories for § 1798.150 "
            "separately (DataCategory.is_ccpa_150_element). "
            f"RE-VERIFIED 2026-10-02 against {CPPA_CPI_ADJUSTMENT} (CPPA's official CPI-adjustment "
            "notice: effective January 1, 2025, § 1798.150(a)(1) statutory damages are $107-$799 "
            "per consumer per incident, up from $100-$750; next adjustment January 1, 2027) and "
            "against leginfo's § 1798.199.95(d) text (lists subdivision (a) of Section 1798.150 "
            "among the provisions it adjusts). CORRECTED from a prior version of this entry that "
            "stated the stale $100-$750 base figures as if currently in effect without giving the "
            "adjusted amount."
        ),
        "order": 90,
    },
]

# Data categories from Data-Mapping-ROPA, with NimbusCart's classification
# against the legal tests this tool evaluates. Classification choices for
# this fictional dataset, not legal determinations about real data:
# (name, description, special_category, financial, authentication,
#  ca_breach_element [§ 1798.82(h)], ccpa_150_element [§ 1798.150(a)(1)])
DATA_CATEGORIES = [
    (
        "Contact Information",
        "Name, email, phone, mailing/shipping address.",
        False,
        False,
        False,
        False,
        False,
    ),
    (
        "Account Credentials",
        "Login email address and hashed password, plus authentication tokens.",
        False,
        False,
        True,
        True,  # § 1798.82(h)(2): username or email + password.
        True,  # § 1798.150(a)(1): email address + password.
    ),
    (
        "Payment Card Data",
        "Tokenized card details and billing address via a PCI-compliant processor. Full card "
        "numbers and security codes are not stored, so this is not a § 1798.82(h)(1)(C) or "
        "§ 1798.81.5(d)(1)(A)(iii) element as NimbusCart holds it.",
        False,
        True,
        False,
        False,
        False,
    ),
    (
        "Order History",
        "Past orders, items purchased, order value.",
        False,
        False,
        False,
        False,
        False,
    ),
    (
        "Browsing Behavior / Analytics Data",
        "Pages viewed, clicks, search queries, on-site behavior.",
        False,
        False,
        False,
        False,
        False,
    ),
    (
        "Device & Technical Data",
        "IP address, browser/device identifiers, cookies.",
        False,
        False,
        False,
        False,
        False,
    ),
    (
        "Marketing Preferences",
        "Opt-in/opt-out status, campaign engagement, communication preferences.",
        False,
        False,
        False,
        False,
        False,
    ),
    (
        "Customer Support Communications",
        "Content of support tickets, chat transcripts, call notes.",
        False,
        False,
        False,
        False,
        False,
    ),
    (
        "Precise Geolocation Data",
        "Delivery coordinates and real-time shipment tracking location. Flagged sensitive in "
        "Data-Mapping-ROPA's internal triage, but not listed in LGPD Art. 5, II or GDPR Art. 9(1).",
        False,
        False,
        False,
        False,
        False,
    ),
    (
        "Health / Accessibility Information",
        "Self-reported accessibility or mobility needs, stored with the customer's name. Not "
        "collected from or confirmed by a health care professional.",
        True,  # Health data: LGPD Art. 5, II / GDPR Art. 9(1).
        False,
        False,
        # § 1798.82(i)(2) "medical information" includes a "mental or physical
        # condition", which self-reported mobility needs describe.
        True,
        # § 1798.81.5(d)(2) is narrower: "medical history or medical treatment
        # or diagnosis by a health care professional". Self-reported needs are
        # none of those, so no CCPA § 1798.150 exposure from this category.
        False,
    ),
    (
        "Government-Issued ID Numbers",
        "Tax ID or national ID numbers for high-value order or customs verification, stored with name.",
        False,
        False,
        False,
        True,  # § 1798.82(h)(1)(B).
        True,  # § 1798.81.5(d)(1)(A)(ii).
    ),
]

# Processing activities from Data-Mapping-ROPA: (name, department, purpose, categories)
PROCESSING_ACTIVITIES = [
    (
        "Customer Account Registration",
        "Engineering / Customer Experience",
        "Create and manage customer accounts to enable purchases, order tracking, and personalized service.",
        ["Contact Information", "Account Credentials"],
    ),
    (
        "Payment Processing",
        "Finance",
        "Process customer payments for orders and manage billing.",
        ["Payment Card Data", "Contact Information"],
    ),
    (
        "Marketing Email Campaigns",
        "Marketing",
        "Send promotional emails and personalized offers to customers who have opted in.",
        ["Contact Information", "Marketing Preferences", "Browsing Behavior / Analytics Data"],
    ),
    (
        "Website Analytics Cookies",
        "Marketing / IT",
        "Analyze website traffic and on-site behavior to improve user experience and product recommendations.",
        ["Browsing Behavior / Analytics Data", "Device & Technical Data"],
    ),
    (
        "Customer Support Tickets",
        "Customer Support",
        "Respond to and resolve customer inquiries, complaints, and support requests.",
        ["Contact Information", "Customer Support Communications", "Order History"],
    ),
    (
        "Order Fulfillment & Shipping",
        "Logistics / Operations",
        "Fulfill and ship customer orders, coordinate with carriers, and provide delivery tracking.",
        ["Contact Information", "Order History", "Precise Geolocation Data"],
    ),
    (
        "Accessibility Accommodation Requests",
        "Customer Experience",
        "Capture customer accessibility needs (e.g. mobility assistance) to tailor delivery and in-store service.",
        ["Health / Accessibility Information"],
    ),
    (
        "Fraud Detection & Risk Scoring",
        "Trust & Safety / Security",
        "Detect and prevent fraudulent transactions and account takeovers using behavioral and device signals.",
        [
            "Device & Technical Data",
            "Browsing Behavior / Analytics Data",
            "Government-Issued ID Numbers",
        ],
    ),
    (
        "Tax & Financial Reporting",
        "Finance",
        "Comply with tax reporting obligations and maintain financial records for regulatory audits.",
        ["Payment Card Data", "Government-Issued ID Numbers"],
    ),
    (
        "Customer Loyalty & Rewards Program",
        "Marketing",
        "Manage loyalty points, rewards redemption, and personalized offers for program members.",
        ["Contact Information", "Order History", "Marketing Preferences"],
    ),
]

# (name, owner team, hosting, description)
SYSTEMS = [
    (
        "Storefront Web App",
        "Engineering",
        "AWS (us-east-1)",
        "Customer-facing e-commerce site.",
    ),
    (
        "Customer Identity Service",
        "IT & Security",
        "AWS (us-east-1)",
        "Login, sessions and account credentials.",
    ),
    (
        "Order Management System",
        "Logistics / Operations",
        "AWS (us-east-1)",
        "Orders, fulfillment and delivery tracking.",
    ),
    (
        "Payment Gateway Integration",
        "Finance",
        "Global Payment Gateway Partner (Ireland)",
        "Tokenized card processing.",
    ),
    (
        "Support Desk Platform",
        "Customer Support",
        "Customer Support Outsourcing Partner (Philippines)",
        "Ticketing and chat, shared with the outsourcing partner.",
    ),
    (
        "Email Marketing Platform",
        "Marketing",
        "Email Marketing Platform SaaS (Canada)",
        "Campaign sends and preference management.",
    ),
    (
        "Analytics Data Warehouse",
        "Marketing / IT",
        "Web Analytics Provider SaaS (United States)",
        "Site analytics and reporting.",
    ),
    (
        "Finance Laptops",
        "Finance / IT",
        "Company-managed endpoints",
        "Full-disk-encrypted laptops used by the Finance team.",
    ),
]


class Command(BaseCommand):
    help = "Seed legal requirements, NimbusCart reference data, and sample incidents."

    def add_arguments(self, parser):
        parser.add_argument(
            "--keep", action="store_true", help="Don't clear existing data before seeding."
        )
        parser.add_argument(
            "--legal-content-only",
            action="store_true",
            help=(
                "Only create/update the legal requirements and the data categories' legal "
                "classification (e.g. after re-verifying them); leave incidents untouched."
            ),
        )

    @transaction.atomic
    def handle(self, *args, **options):
        if options["legal_content_only"]:
            requirements = self._seed_requirements()
            self._seed_categories()
            self.stdout.write(
                self.style.SUCCESS(
                    "Legal requirements and data category classification refreshed."
                )
            )
            self._warn_unverified(requirements)
            return

        if not options["keep"]:
            self.stdout.write("Clearing existing data…")
            # Incidents first: NotificationRecord protects LegalRequirement.
            Incident.objects.all().delete()
            LegalRequirement.objects.all().delete()
            ProcessingActivity.objects.all().delete()
            DataCategory.objects.all().delete()
            System.objects.all().delete()

        requirements = self._seed_requirements()
        categories = self._seed_categories()
        activities = self._seed_activities(categories)
        systems = self._seed_systems()
        self._seed_incidents(requirements, categories, activities, systems)

        self.stdout.write(self.style.SUCCESS("Seed data loaded."))
        self._warn_unverified(requirements)

    def _warn_unverified(self, requirements: dict[str, LegalRequirement]) -> None:
        unverified = [r.code for r in requirements.values() if not r.is_verified]
        if unverified:
            self.stdout.write(
                self.style.WARNING(
                    f"{len(unverified)} legal requirement(s) still is_verified=False "
                    f"({', '.join(unverified)}) — see their verification_notes."
                )
            )

    # -- Legal content --------------------------------------------------

    def _seed_requirements(self) -> dict[str, LegalRequirement]:
        by_code = {}
        for data in LEGAL_REQUIREMENTS:
            requirement, _ = LegalRequirement.objects.update_or_create(
                code=data["code"], defaults=data
            )
            by_code[requirement.code] = requirement
        # California's AG deadline runs from the consumer notice, not discovery.
        ag = by_code["ca-attorney-general"]
        ag.deadline_runs_from = by_code["ca-residents"]
        ag.save(update_fields=["deadline_runs_from"])
        self.stdout.write(f"  {len(by_code)} legal requirements.")
        return by_code

    # -- Reference data -------------------------------------------------

    def _seed_categories(self) -> dict[str, DataCategory]:
        by_name = {}
        for (
            name,
            description,
            special,
            financial,
            auth,
            ca_element,
            ccpa_element,
        ) in DATA_CATEGORIES:
            by_name[name], _ = DataCategory.objects.update_or_create(
                name=name,
                defaults={
                    "description": description,
                    "is_special_category": special,
                    "is_financial": financial,
                    "is_authentication": auth,
                    "is_ca_breach_element": ca_element,
                    "is_ccpa_150_element": ccpa_element,
                },
            )
        return by_name

    def _seed_activities(self, categories) -> dict[str, ProcessingActivity]:
        by_name = {}
        for name, department, purpose, category_names in PROCESSING_ACTIVITIES:
            activity, _ = ProcessingActivity.objects.update_or_create(
                name=name, defaults={"department": department, "purpose": purpose}
            )
            activity.data_categories.set(categories[c] for c in category_names)
            by_name[name] = activity
        return by_name

    def _seed_systems(self) -> dict[str, System]:
        by_name = {}
        for name, owner, hosting, description in SYSTEMS:
            by_name[name], _ = System.objects.update_or_create(
                name=name,
                defaults={"owner_team": owner, "hosting": hosting, "description": description},
            )
        return by_name

    # -- Sample incidents -----------------------------------------------

    def _seed_incidents(self, requirements, categories, activities, systems):
        now = timezone.now().replace(second=0, microsecond=0)
        done, in_progress, n_a = (
            ChecklistItem.Status.DONE,
            ChecklistItem.Status.IN_PROGRESS,
            ChecklistItem.Status.NOT_APPLICABLE,
        )

        samples = [
            {
                "fields": {
                    "title": "Unauthorized access to customer accounts via a compromised admin credential",
                    "summary": (
                        "An attacker used a phished administrator credential to query the customer "
                        "identity database for roughly 36 hours. Logs show export of names, email "
                        "addresses, password hashes and order history. The credential was revoked "
                        "and all customer sessions invalidated; forced password resets are rolling out."
                    ),
                    "incident_type": Incident.IncidentType.UNAUTHORIZED_ACCESS,
                    "occurred_at": now - timedelta(days=3),
                    "discovered_at": now - timedelta(hours=30),
                    "containment_status": Incident.Containment.CONTAINED,
                    "risk_to_individuals": Incident.RiskToIndividuals.HIGH,
                    "is_large_scale": True,
                },
                "categories": ["Contact Information", "Account Credentials", "Order History"],
                "activities": [
                    "Customer Account Registration",
                    "Customer Loyalty & Rewards Program",
                ],
                "systems": ["Customer Identity Service", "Storefront Web App"],
                "impacts": {"BR": 1_850, "EU": 4_200, "US-CA": 960, "US-OTHER": 7_300},
                "checklist": {
                    1: done,
                    2: done,
                    3: done,
                    4: done,
                    5: done,
                    6: in_progress,
                    7: done,
                    9: in_progress,
                    10: in_progress,
                },
                "timeline": [
                    (
                        timedelta(days=-3),
                        "First anomalous admin login from an unrecognized IP (identified later in log review).",
                    ),
                    (
                        timedelta(hours=-30),
                        "SIEM alert on bulk query volume; Security Operations opens the incident.",
                    ),
                    (
                        timedelta(hours=-28),
                        "Compromised admin credential revoked; all customer sessions invalidated.",
                    ),
                    (
                        timedelta(hours=-20),
                        "Log review confirms export of names, emails, password hashes and order history.",
                    ),
                    (
                        timedelta(hours=-6),
                        "DPO documents risk to individuals as HIGH (credential reuse, phishing risk).",
                    ),
                ],
                "records": [],
            },
            {
                "fields": {
                    "title": "Support partner emailed a ticket export to the wrong customer",
                    "summary": (
                        "An agent at the outsourced support desk attached a ticket export to a reply "
                        "sent to the wrong customer. The export held names, contact details and "
                        "ticket text, including accessibility accommodation notes. The recipient "
                        "confirmed deletion in writing."
                    ),
                    "incident_type": Incident.IncidentType.VENDOR,
                    "occurred_at": now - timedelta(days=12, hours=2),
                    "discovered_at": now - timedelta(days=12),
                    "containment_status": Incident.Containment.CONTAINED,
                    "risk_to_individuals": Incident.RiskToIndividuals.RISK,
                },
                "categories": [
                    "Contact Information",
                    "Customer Support Communications",
                    "Health / Accessibility Information",
                ],
                "activities": [
                    "Customer Support Tickets",
                    "Accessibility Accommodation Requests",
                ],
                "systems": ["Support Desk Platform"],
                "impacts": {"EU": 140, "US-CA": 35},
                "checklist": dict.fromkeys(range(1, 13), done) | {3: n_a, 13: in_progress},
                "timeline": [
                    (
                        timedelta(days=-12, hours=-2),
                        "Ticket export sent to the wrong customer by the support partner.",
                    ),
                    (
                        timedelta(days=-12),
                        "Support partner reports the misdirected email to NimbusCart (vendor notice).",
                    ),
                    (
                        timedelta(days=-11),
                        "Recipient confirms in writing that the attachment was deleted.",
                    ),
                ],
                "records": [
                    (
                        "gdpr-supervisory-authority",
                        timedelta(days=-12, hours=60),
                        "DEMO-EU-SA-0142",
                    ),
                    ("ca-residents", timedelta(days=-3), ""),
                ],
            },
            {
                "fields": {
                    "title": "Ransomware on the order management system",
                    "summary": (
                        "Ransomware encrypted the order management database and the attackers claim "
                        "to have copied it. Affected records include customer contact details, order "
                        "history and delivery geolocation, mostly for Brazilian customers. Systems "
                        "are still being restored from backups."
                    ),
                    "incident_type": Incident.IncidentType.RANSOMWARE,
                    "occurred_at": now - timedelta(days=6, hours=5),
                    "discovered_at": now - timedelta(days=6),
                    "containment_status": Incident.Containment.ONGOING,
                    "risk_to_individuals": Incident.RiskToIndividuals.RISK,
                    "is_large_scale": True,
                },
                "categories": [
                    "Contact Information",
                    "Order History",
                    "Precise Geolocation Data",
                ],
                "activities": ["Order Fulfillment & Shipping"],
                "systems": ["Order Management System"],
                "impacts": {"BR": 22_000},
                "checklist": {
                    1: done,
                    2: done,
                    3: in_progress,
                    4: done,
                    5: done,
                    6: done,
                    7: done,
                    9: done,
                    10: done,
                },
                "timeline": [
                    (
                        timedelta(days=-6),
                        "Order processing halts; ransom note found on OMS database servers.",
                    ),
                    (
                        timedelta(days=-5, hours=-12),
                        "Attackers' leak-site post claims exfiltration of the order database.",
                    ),
                    (
                        timedelta(days=-4),
                        "Restoration from backups begins; order management running in degraded mode.",
                    ),
                ],
                "records": [("lgpd-anpd", timedelta(days=-4), "DEMO-ANPD-2026-0007")],
            },
            {
                "fields": {
                    "title": "Encrypted Finance laptop stolen from a car",
                    "summary": (
                        "A Finance team laptop was stolen. It holds a tax-reporting extract with "
                        "customer names and tax ID numbers. Full-disk encryption was active and "
                        "verified by IT; the recovery key is held centrally and was not on the device. "
                        "The device was remotely wiped when it next came online."
                    ),
                    "incident_type": Incident.IncidentType.LOST_DEVICE,
                    "occurred_at": now - timedelta(days=70, hours=10),
                    "discovered_at": now - timedelta(days=70),
                    "containment_status": Incident.Containment.RESOLVED,
                    "risk_to_individuals": Incident.RiskToIndividuals.UNLIKELY,
                    "data_encrypted": True,
                },
                "categories": ["Government-Issued ID Numbers", "Payment Card Data"],
                "activities": ["Tax & Financial Reporting"],
                "systems": ["Finance Laptops"],
                "impacts": {"US-CA": 2_100, "US-OTHER": 900},
                "checklist": dict.fromkeys(range(1, 15), done) | {8: n_a, 10: n_a, 11: n_a},
                "timeline": [
                    (timedelta(days=-70, hours=-10), "Laptop stolen from an employee's car."),
                    (timedelta(days=-70), "Employee reports the theft to IT; incident opened."),
                    (
                        timedelta(days=-69),
                        "IT confirms full-disk encryption was active and the key was not on the device.",
                    ),
                    (timedelta(days=-62), "Device checks in and is remotely wiped."),
                    (
                        timedelta(days=-55),
                        "Post-incident review closed; no notification obligations triggered.",
                    ),
                ],
                "records": [],
            },
        ]

        for sample in samples:
            incident = Incident.objects.create(**sample["fields"])
            incident.affected_data_categories.set(categories[c] for c in sample["categories"])
            incident.affected_activities.set(activities[a] for a in sample["activities"])
            incident.affected_systems.set(systems[s] for s in sample["systems"])
            for jurisdiction, individuals in sample["impacts"].items():
                JurisdictionImpact.objects.create(
                    incident=incident, jurisdiction=jurisdiction, individuals=individuals
                )
            for offset, description in sample["timeline"]:
                TimelineEvent.objects.create(
                    incident=incident, occurred_at=now + offset, description=description
                )
            for item in create_default_checklist(incident):
                status = sample["checklist"].get(item.order)
                if status:
                    item.status = status
                    item.save(update_fields=["status"])
            for code, offset, reference in sample["records"]:
                requirement = requirements[code]
                sent_at = now + offset
                NotificationRecord.objects.create(
                    incident=incident,
                    requirement=requirement,
                    sent_at=sent_at,
                    reference=reference,
                )
                TimelineEvent.objects.create(
                    incident=incident,
                    occurred_at=sent_at,
                    description=f"Notification sent: {requirement.title}.",
                )

        self.stdout.write(f"  {len(samples)} sample incidents.")
