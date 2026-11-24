from datetime import timedelta

from django.contrib.auth import get_user_model
from django.test import Client, TestCase
from django.urls import reverse
from django.utils import timezone

from .models import Invitation, Membership, Organization, Role

User = get_user_model()
PASSWORD = "Str0ng-pass-123"


class TeamLinkTests(TestCase):
    def setUp(self):
        self.org = Organization.objects.create(name="Alpha")
        self.other = Organization.objects.create(name="Beta")
        self.admin = User.objects.create_user(
            email="admin@alpha.org", password=PASSWORD, full_name="Admin"
        )
        Membership.objects.create(user=self.admin, organization=self.org, role=Role.ORG_ADMIN)
        self.pending = Invitation.objects.create(organization=self.org, email="p@alpha.org")
        self.accepted = Invitation.objects.create(
            organization=self.org, email="a@alpha.org", accepted_at=timezone.now()
        )
        self.expired = Invitation.objects.create(
            organization=self.org,
            email="e@alpha.org",
            expires_at=timezone.now() - timedelta(minutes=1),
        )
        self.foreign = Invitation.objects.create(organization=self.other, email="x@beta.org")
        self.client = Client()
        self.client.force_login(self.admin)

    def link(self, invitation):
        return reverse("organizations:accept_invitation", args=[invitation.token])

    def test_pending_invitation_shows_a_copyable_link(self):
        response = self.client.get(reverse("organizations:team"))
        self.assertContains(response, self.link(self.pending))

    def test_used_and_expired_invitations_show_no_link(self):
        response = self.client.get(reverse("organizations:team"))
        self.assertNotContains(response, self.accepted.token)
        self.assertNotContains(response, self.expired.token)

    def test_other_organizations_links_are_never_shown(self):
        response = self.client.get(reverse("organizations:team"))
        self.assertNotContains(response, self.foreign.token)
