"""
The default response checklist every new incident starts with.

The phases follow the generic shape most incident-response plans share
(triage → containment → assessment → notification → recovery → review).
Owners are NimbusCart's fictional teams; every item stays editable per
incident, and teams can add their own.
"""

from .models import ChecklistItem, Incident

DEFAULT_CHECKLIST: list[tuple[str, str, str]] = [
    # (phase, task, default owner)
    ("Triage", "Open the incident record and assign an incident lead", "Security Operations"),
    ("Triage", "Alert the DPO / privacy team", "Security Operations"),
    (
        "Containment",
        "Contain the incident (isolate systems, revoke credentials)",
        "IT & Security",
    ),
    ("Containment", "Preserve evidence and logs", "IT & Security"),
    (
        "Assessment",
        "Identify affected data categories, systems and processing activities",
        "Privacy Team",
    ),
    ("Assessment", "Estimate affected individuals per jurisdiction", "Privacy Team"),
    ("Assessment", "Document the risk-to-individuals assessment", "DPO"),
    ("Assessment", "Contact any processor/vendor involved", "Vendor Management"),
    ("Notification", "Confirm notification obligations with legal counsel", "Legal"),
    ("Notification", "Prepare and send regulator notifications", "DPO"),
    ("Notification", "Prepare and send notifications to individuals", "Privacy Team"),
    ("Recovery", "Remediate the root cause", "Engineering"),
    ("Review", "Update the incident record / breach register", "DPO"),
    ("Review", "Hold a post-incident review and record lessons learned", "Incident lead"),
]


def create_default_checklist(incident: Incident) -> list[ChecklistItem]:
    return ChecklistItem.objects.bulk_create(
        ChecklistItem(incident=incident, phase=phase, title=title, owner=owner, order=index)
        for index, (phase, title, owner) in enumerate(DEFAULT_CHECKLIST, start=1)
    )
