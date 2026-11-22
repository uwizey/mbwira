from django.core.mail import send_mail
from django.db import transaction
from django.urls import reverse
from django.utils import timezone

from apps.audit.services import log_action

from .models import Invitation, Membership, Organization, Role


class InvitationError(Exception):
    """A user-facing reason why an invitation cannot be created or accepted."""


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


def create_invitation(*, organization, email, role, invited_by, request):
    """Create an invitation, write the audit entry and email the link."""
    email = email.strip().lower()

    if Membership.objects.filter(organization=organization, user__email__iexact=email).exists():
        raise InvitationError("This person is already a member of your organization.")

    pending = Invitation.objects.filter(
        organization=organization,
        email__iexact=email,
        accepted_at__isnull=True,
        expires_at__gt=timezone.now(),
    )
    if pending.exists():
        raise InvitationError("A pending invitation already exists for this email.")

    with transaction.atomic():
        invitation = Invitation.objects.create(
            organization=organization, email=email, role=role, invited_by=invited_by
        )
        log_action(
            invited_by,
            "invitation.created",
            obj=invitation,
            organization=organization,
            details={"email": email, "role": role},
        )

    link = request.build_absolute_uri(
        reverse("organizations:accept_invitation", args=[invitation.token])
    )
    send_mail(
        subject=f"You are invited to join {organization.name} on Mbwira",
        message=(
            f"{invited_by.full_name} invited you to join {organization.name} "
            f"as {invitation.get_role_display()}.\n\n"
            f"Accept the invitation (valid for 7 days, one use only):\n{link}\n"
        ),
        from_email=None,
        recipient_list=[email],
    )
    return invitation


@transaction.atomic
def accept_invitation(*, invitation, user):
    """Turn a valid invitation into a membership. Single use."""
    invitation = Invitation.objects.select_for_update().get(pk=invitation.pk)

    if not invitation.is_valid:
        raise InvitationError("This invitation is no longer valid.")
    if user.email.lower() != invitation.email.lower():
        raise InvitationError("This invitation was sent to a different email address.")
    if Membership.objects.filter(user=user, organization=invitation.organization).exists():
        raise InvitationError("You are already a member of this organization.")

    membership = Membership.objects.create(
        user=user, organization=invitation.organization, role=invitation.role
    )
    invitation.accepted_at = timezone.now()
    invitation.save(update_fields=["accepted_at"])

    log_action(
        user,
        "invitation.accepted",
        obj=invitation,
        organization=invitation.organization,
        details={"email": invitation.email},
    )
    log_action(
        user,
        "membership.created",
        obj=membership,
        details={"user": user.email, "role": membership.role},
    )
    return membership
