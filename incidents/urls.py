from django.urls import path

from . import views

app_name = "incidents"

urlpatterns = [
    path("", views.dashboard, name="dashboard"),
    path("about/", views.about, name="about"),
    path("legal-sources/", views.legal_sources, name="legal_sources"),
    path("incidents/new/", views.incident_create, name="incident_create"),
    path("incidents/<int:pk>/", views.incident_detail, name="incident_detail"),
    path("incidents/<int:pk>/edit/", views.incident_edit, name="incident_edit"),
    path("incidents/<int:pk>/export/pdf/", views.export_pdf, name="export_pdf"),
    path("incidents/<int:pk>/checklist/add/", views.checklist_add, name="checklist_add"),
    path("incidents/<int:pk>/timeline/add/", views.timeline_add, name="timeline_add"),
    path(
        "incidents/<int:pk>/notifications/<int:requirement_pk>/record/",
        views.notification_record,
        name="notification_record",
    ),
    path("checklist/<int:item_pk>/update/", views.checklist_update, name="checklist_update"),
]
