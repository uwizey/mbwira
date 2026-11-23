from django.db import transaction
from django.db.models import Max

from apps.audit.services import log_action
from apps.organizations.models import Organization

from .models import Incident, IncidentStatus


def _label(value):
    return None if value in (None, "") else str(value)


@transaction.atomic
def create_incident(*, organization, reporter, incident_type, title, description, occurred_at):
    """Create an incident with the next number for this organization.

    Locking the organization row makes two simultaneous reports queue up,
    so they can never receive the same number.
    """
    Organization.objects.select_for_update().get(pk=organization.pk)
    last = Incident.objects.filter(organization=organization).aggregate(Max("number"))["number__max"]
    incident = Incident.objects.create(
        organization=organization,
        number=(last or 0) + 1,
        incident_type=incident_type,
        title=title,
        description=description,
        occurred_at=occurred_at,
        reporter=reporter,
    )
    log_action(
        reporter,
        "incident.reported",
        obj=incident,
        details={"reference": incident.reference, "type": incident_type, "title": title},
    )
    return incident


@transaction.atomic
def triage_incident(*, incident, actor, incident_type, category, severity, assignee):
    """Set type, category, severity and assignee. A reviewer taking a new
    report moves it from Reported to Under review."""
    changes = {}
    for field, new in (
        ("incident_type", incident_type),
        ("category", category),
        ("severity", severity),
        ("assignee", assignee),
    ):
        old = getattr(incident, field)
        if old != new:
            changes[field] = {"from": _label(old), "to": _label(new)}
            setattr(incident, field, new)

    moved = incident.status == IncidentStatus.REPORTED
    if moved:
        incident.status = IncidentStatus.UNDER_REVIEW

    if changes or moved:
        incident.save()

    if changes:
        log_action(
            actor,
            "incident.triaged",
            obj=incident,
            details={"reference": incident.reference, "changes": changes},
        )
    if moved:
        log_action(
            actor,
            "incident.status_changed",
            obj=incident,
            details={
                "reference": incident.reference,
                "from": IncidentStatus.REPORTED,
                "to": IncidentStatus.UNDER_REVIEW,
            },
        )
    return incident
