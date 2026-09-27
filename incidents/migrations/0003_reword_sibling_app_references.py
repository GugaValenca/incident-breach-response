from django.db import migrations

# The seed data used to refer to the sibling apps as "Project 1" / "Project 2".
# Databases that were seeded before the wording changed keep the old text
# until this runs; `seed_incidents` itself is not safe to re-run on a live
# database because it clears incidents first.
REPLACEMENTS = (
    (
        "(see Project 1's seed data).",
        "(see the LGPD-GDPR-CCPA-Comparative-Analysis seed data).",
    ),
    (
        "Project 2's internal triage",
        "Data-Mapping-ROPA's internal triage",
    ),
)

# Only the reference tables the seed command fills in; incidents and their
# timelines are user-entered data and are never touched.
MODEL_NAMES = ("DataCategory", "ProcessingActivity", "System", "LegalRequirement")
TEXT_FIELD_TYPES = ("CharField", "TextField")


def rewrite_text(apps, replacements):
    for model_name in MODEL_NAMES:
        model = apps.get_model("incidents", model_name)
        text_fields = [
            field.name
            for field in model._meta.concrete_fields
            if field.get_internal_type() in TEXT_FIELD_TYPES
        ]
        for obj in model.objects.all():
            changed = []
            for name in text_fields:
                value = getattr(obj, name)
                if not isinstance(value, str):
                    continue
                updated = value
                for old, new in replacements:
                    updated = updated.replace(old, new)
                if updated != value:
                    setattr(obj, name, updated)
                    changed.append(name)
            if changed:
                obj.save(update_fields=changed)


def forwards(apps, schema_editor):
    rewrite_text(apps, REPLACEMENTS)


def backwards(apps, schema_editor):
    rewrite_text(apps, tuple((new, old) for old, new in REPLACEMENTS))


class Migration(migrations.Migration):

    dependencies = [
        ("incidents", "0002_ccpa_150_element"),
    ]

    operations = [
        migrations.RunPython(forwards, backwards),
    ]
