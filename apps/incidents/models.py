import os
import uuid

from django.conf import settings
from django.db import models
from django.db.models import F, Q
from django.urls import reverse

from apps.core.managers import OrganizationQuerySet

from .storage import EvidenceStorage


class IncidentType(models.TextChoices):
    SECURITY = "security", "Security incident"
    ASSET_FAILURE = "asset_failure", "IT asset failure"


class Category(models.TextChoices):
    PHISHING = "phishing", "Phishing"
    MALWARE = "malware", "Malware"
    UNAUTHORIZED_ACCESS = "unauthorized_access", "Unauthorized access"
    DATA_LOSS = "data_loss", "Data loss"
    LOST_OR_STOLEN_DEVICE = "lost_or_stolen_device", "Lost or stolen device"
    HARDWARE_FAILURE = "hardware_failure", "Hardware failure"
    NETWORK_OUTAGE = "network_outage", "Network outage"
    SOFTWARE_FAILURE = "software_failure", "Software failure"
    POWER_ISSUE = "power_issue", "Power issue"
    OTHER = "other", "Other"


CATEGORIES_BY_TYPE = {
    IncidentType.SECURITY: [
        Category.PHISHING,
        Category.MALWARE,
        Category.UNAUTHORIZED_ACCESS,
        Category.DATA_LOSS,
        Category.LOST_OR_STOLEN_DEVICE,
        Category.OTHER,
    ],
    IncidentType.ASSET_FAILURE: [
        Category.HARDWARE_FAILURE,
        Category.NETWORK_OUTAGE,
        Category.SOFTWARE_FAILURE,
        Category.POWER_ISSUE,
        Category.OTHER,
    ],
}


class Severity(models.TextChoices):
    LOW = "low", "Low"
    MEDIUM = "medium", "Medium"
    HIGH = "high", "High"
    CRITICAL = "critical", "Critical"


class IncidentStatus(models.TextChoices):
    REPORTED = "reported", "Reported"
    UNDER_REVIEW = "under_review", "Under review"
    INVESTIGATING = "investigating", "Investigating"
    RESOLVED = "resolved", "Resolved"
    CLOSED = "closed", "Closed"


class Incident(models.Model):
    organization = models.ForeignKey(
        "organizations.Organization", on_delete=models.CASCADE, related_name="incidents"
    )
    number = models.PositiveIntegerField()
    incident_type = models.CharField(max_length=20, choices=IncidentType.choices)
    title = models.CharField(max_length=200)
    description = models.TextField()
    category = models.CharField(max_length=30, choices=Category.choices, blank=True)
    severity = models.CharField(max_length=10, choices=Severity.choices, blank=True)
    status = models.CharField(
        max_length=20, choices=IncidentStatus.choices, default=IncidentStatus.REPORTED
    )
    reporter = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="reported_incidents"
    )
    assignee = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="assigned_incidents",
    )
    occurred_at = models.DateTimeField()
    resolved_at = models.DateTimeField(null=True, blank=True)
    resolution_summary = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = OrganizationQuerySet.as_manager()

    class Meta:
        ordering = ["-created_at", "-id"]
        constraints = [
            models.UniqueConstraint(
                fields=["organization", "number"], name="unique_incident_number_per_org"
            ),
            models.CheckConstraint(
                condition=~Q(status__in=["resolved", "closed"]) | ~Q(resolution_summary=""),
                name="resolved_or_closed_needs_summary",
            ),
            models.CheckConstraint(
                condition=Q(resolved_at__isnull=True) | Q(resolved_at__gte=F("occurred_at")),
                name="resolved_not_before_occurred",
            ),
        ]
        indexes = [
            models.Index(fields=["organization", "status"]),
            models.Index(fields=["organization", "severity"]),
            models.Index(fields=["organization", "-created_at"]),
        ]

    def __str__(self):
        return f"{self.reference} {self.title}"

    @property
    def reference(self):
        return f"INC-{self.number:04d}"

    def get_absolute_url(self):
        return reverse("incidents:detail", args=[self.pk])

class IncidentComment(models.Model):
    incident = models.ForeignKey(Incident, on_delete=models.CASCADE, related_name="comments")
    author = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="incident_comments"
    )
    body = models.TextField()
    is_internal = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["created_at", "id"]
        indexes = [models.Index(fields=["incident", "created_at"])]

    def __str__(self):
        return f"Comment on {self.incident.reference} by {self.author}"

class EvidenceImmutableError(Exception):
    """Raised when code tries to change an evidence record."""


def evidence_upload_path(instance, filename):
    """Random stored name. Only the (already validated) extension is kept."""
    ext = os.path.splitext(filename)[1].lower()
    return f"{instance.incident.organization_id}/{instance.incident_id}/{uuid.uuid4().hex}{ext}"


class IncidentEvidence(models.Model):
    incident = models.ForeignKey(Incident, on_delete=models.CASCADE, related_name="evidence")
    file = models.FileField(
        upload_to=evidence_upload_path, storage=EvidenceStorage(), max_length=255
    )
    original_name = models.CharField(max_length=200)
    content_type = models.CharField(max_length=100)
    size = models.PositiveIntegerField()
    sha256 = models.CharField(max_length=64)
    uploaded_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="uploaded_evidence"
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["created_at", "id"]
        verbose_name_plural = "incident evidence"
        indexes = [models.Index(fields=["incident", "created_at"])]

    def __str__(self):
        return f"{self.original_name} ({self.incident.reference})"

    def save(self, *args, **kwargs):
        if not self._state.adding:
            raise EvidenceImmutableError("Evidence cannot be modified once uploaded.")
        super().save(*args, **kwargs)
