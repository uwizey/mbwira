from django.db import models


class OrganizationQuerySet(models.QuerySet):
    """Use on every model that has an `organization` field."""

    def for_organization(self, organization):
        if organization is None:
            return self.none()
        return self.filter(organization=organization)
