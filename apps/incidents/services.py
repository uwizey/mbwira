from django.conf import settings
from django.db import transaction
from django.db.models import Max
from django.utils import timezone

from apps.audit.services import log_action
from apps.organizations.models import Membership, Organization, Role

from .evidence import EvidenceRejected, inspect_upload
from .models import Incident, IncidentComment, IncidentEvidence, IncidentStatus

REPORTED = IncidentStatus.REPORTED.value
UNDER_REVIEW = IncidentStatus.UNDER_REVIEW.value
INVESTIGATING = IncidentStatus.INVESTIGATING.value
RESOLVED = IncidentStatus.RESOLVED.value
CLOSED = IncidentStatus.CLOSED.value

LABELS = dict(IncidentStatus.choices)
TRIAGE_ROLES = (Role.SECURITY_MANAGER, Role.SECURITY_ANALYST)
MANAGER_ONLY = (Role.SECURITY_MANAGER,)

# The only allowed status changes. Anything else is rejected.
# "text" is the written note the change requires (None means no note needed).
TRANSITIONS = {
    (REPORTED, UNDER_REVIEW): {
        "roles": TRIAGE_ROLES, "label": "Take for review", "text": None, "style": "primary",
    },
    (UNDER_REVIEW, INVESTIGATING): {
        "roles": TRIAGE_ROLES, "label": "Start investigating", "text": None, "style": "primary",
    },
    (INVESTIGATING, RESOLVED): {
        "roles": TRIAGE_ROLES, "label": "Mark resolved", "text": "Resolution summary", "style": "primary",
    },
    (RESOLVED, CLOSED): {
        "roles": TRIAGE_ROLES, "label": "Close incident", "text": None, "style": "primary",
    },
    (UNDER_REVIEW, CLOSED): {
        "roles": TRIAGE_ROLES, "label": "Close as duplicate or invalid",
        "text": "Reason for closing", "style": "outline",
    },
    (RESOLVED, INVESTIGATING): {
        "roles": MANAGER_ONLY, "label": "Reopen", "text": "Reason for reopening", "style": "outline",
    },
    (CLOSED, INVESTIGATING): {
        "roles": MANAGER_ONLY, "label": "Reopen", "text": "Reason for reopening", "style": "outline",
    },
}


class WorkflowError(Exception):
    """A user-facing reason why a status change, triage or comment is not allowed."""


def _label(value):
    return None if value in (None, "") else str(value)


def _role_of(user, organization_id):
    return (
        Membership.objects.filter(user=user, organization_id=organization_id)
        .values_list("role", flat=True)
        .first()
    )


def available_transitions(incident, role):
    """The status buttons this role may use right now."""
    return [
        {"to": to, "label": spec["label"], "text": spec["text"], "style": spec["style"]}
        for (frm, to), spec in TRANSITIONS.items()
        if frm == incident.status and role in spec["roles"]
    ]


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
    if incident.status in (RESOLVED, CLOSED):
        raise WorkflowError("Reopen this incident before changing its triage.")

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

    moved = incident.status == REPORTED
    if moved:
        incident.status = UNDER_REVIEW

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
            details={"reference": incident.reference, "from": REPORTED, "to": UNDER_REVIEW},
        )
    return incident


@transaction.atomic
def transition_incident(*, incident, actor, to_status, note=""):
    """Move an incident to a new status, enforcing every workflow rule."""
    incident = Incident.objects.select_for_update().get(pk=incident.pk)
    from_status = incident.status

    spec = TRANSITIONS.get((from_status, to_status))
    if spec is None:
        raise WorkflowError(
            f"An incident cannot move from {LABELS.get(from_status, from_status)} "
            f"to {LABELS.get(to_status, to_status)}."
        )

    role = _role_of(actor, incident.organization_id)
    if role not in spec["roles"]:
        raise WorkflowError("Your role is not allowed to make this change.")

    note = (note or "").strip()
    if spec["text"] and not note:
        raise WorkflowError(f"{spec['text']} is required.")

    details = {"reference": incident.reference, "from": from_status, "to": to_status}
    reopened = False

    if (from_status, to_status) == (UNDER_REVIEW, INVESTIGATING):
        missing = [
            name
            for name, value in (
                ("category", incident.category),
                ("severity", incident.severity),
                ("assignee", incident.assignee_id),
            )
            if not value
        ]
        if missing:
            raise WorkflowError(
                "Before investigating, set the " + ", ".join(missing) + " using Triage."
            )
    elif to_status == RESOLVED:
        incident.resolution_summary = note
        incident.resolved_at = timezone.now()
    elif (from_status, to_status) == (UNDER_REVIEW, CLOSED):
        incident.resolution_summary = note
    elif to_status == INVESTIGATING and from_status in (RESOLVED, CLOSED):
        details["previous_summary"] = incident.resolution_summary
        incident.resolution_summary = ""
        incident.resolved_at = None
        reopened = True

    incident.status = to_status
    incident.save()

    if reopened:
        IncidentComment.objects.create(
            incident=incident, author=actor, body=f"Reopened: {note}", is_internal=False
        )
    if note:
        details["note"] = note[:500]
    log_action(actor, "incident.status_changed", obj=incident, details=details)
    return incident


@transaction.atomic
def add_comment(*, incident, author, body, is_internal=False):
    """Add a comment. Employees may comment only on their own incidents and
    can never write internal notes."""
    role = _role_of(author, incident.organization_id)
    if role is None:
        raise WorkflowError("You are not a member of this organization.")

    body = (body or "").strip()
    if not body:
        raise WorkflowError("A comment cannot be empty.")

    if role == Role.EMPLOYEE:
        if incident.reporter_id != author.pk:
            raise WorkflowError("You can only comment on your own incidents.")
        is_internal = False

    comment = IncidentComment.objects.create(
        incident=incident, author=author, body=body, is_internal=is_internal
    )
    log_action(
        author,
        "incident.commented",
        obj=incident,
        details={
            "reference": incident.reference,
            "comment_id": comment.pk,
            "internal": is_internal,
        },
    )
    return comment

def can_upload_evidence(incident, user, role):
    """Staff may add evidence to any open incident of their organization.
    Anyone else only to an incident they reported themselves."""
    if role is None or incident.status == CLOSED:
        return False
    return role in TRIAGE_ROLES or incident.reporter_id == user.pk


@transaction.atomic
def add_evidence(*, incident, uploader, uploaded_file):
    """Validate and store one evidence file, and write the audit entry."""
    role = _role_of(uploader, incident.organization_id)
    if role is None:
        raise WorkflowError("You are not a member of this organization.")
    if incident.status == CLOSED:
        raise WorkflowError("This incident is closed. Reopen it before adding evidence.")
    if not can_upload_evidence(incident, uploader, role):
        raise WorkflowError("You cannot add evidence to this incident.")
    if incident.evidence.count() >= settings.EVIDENCE_MAX_FILES:
        raise WorkflowError(
            f"This incident already has the maximum of {settings.EVIDENCE_MAX_FILES} files."
        )

    try:
        info = inspect_upload(uploaded_file)
    except EvidenceRejected as error:
        raise WorkflowError(str(error)) from error

    evidence = IncidentEvidence.objects.create(
        incident=incident,
        file=uploaded_file,
        original_name=info["name"],
        content_type=info["content_type"],
        size=info["size"],
        sha256=info["sha256"],
        uploaded_by=uploader,
    )
    log_action(
        uploader,
        "evidence.uploaded",
        obj=incident,
        details={
            "reference": incident.reference,
            "evidence_id": evidence.pk,
            "filename": evidence.original_name,
            "size": evidence.size,
            "sha256": evidence.sha256,
        },
    )
    return evidence
