from django.db import transaction

from apps.audit.services import log_action

from .models import Membership, Organization, Role


@transaction.atomic
def register_organization(*, name, admin_user):
    """Create an organization and make `admin_user` its first admin."""
    organization = Organization.objects.create(name=name)
    membership = Membership.objects.create(
        user=admin_user, organization=organization, role=Role.ORG_ADMIN
    )
    log_action(
        admin_user,
        "organization.created",
        obj=organization,
        organization=organization,
        details={"name": organization.name},
    )
    log_action(
        admin_user,
        "membership.created",
        obj=membership,
        details={"user": admin_user.email, "role": membership.role},
    )
    return organization
