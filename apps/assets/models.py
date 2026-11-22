from django.conf import settings
from django.db import models
from django.urls import reverse

from apps.core.managers import OrganizationQuerySet


class AssetType(models.TextChoices):
    LAPTOP = "laptop", "Laptop"
    DESKTOP = "desktop", "Desktop"
    SERVER = "server", "Server"
    NETWORK_DEVICE = "network_device", "Network device"
    PRINTER = "printer", "Printer"
    MOBILE = "mobile", "Mobile"
    OTHER = "other", "Other"


class AssetStatus(models.TextChoices):
    ACTIVE = "active", "Active"
    UNDER_REPAIR = "under_repair", "Under repair"
    RETIRED = "retired", "Retired"
    LOST = "lost", "Lost"


class Asset(models.Model):
    organization = models.ForeignKey(
        "organizations.Organization", on_delete=models.CASCADE, related_name="assets"
    )
    name = models.CharField(max_length=200)
    asset_type = models.CharField(max_length=20, choices=AssetType.choices, default=AssetType.LAPTOP)
    hostname = models.CharField(max_length=200, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    location = models.CharField(max_length=200, blank=True)
    status = models.CharField(max_length=20, choices=AssetStatus.choices, default=AssetStatus.ACTIVE)
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="owned_assets",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = OrganizationQuerySet.as_manager()

    class Meta:
        ordering = ["name"]
        indexes = [
            models.Index(fields=["organization", "status"]),
            models.Index(fields=["organization", "asset_type"]),
        ]

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse("assets:detail", args=[self.pk])
