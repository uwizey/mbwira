from datetime import timedelta

from django.contrib.auth import get_user_model
from django.core import mail
from django.test import Client, TestCase
from django.urls import reverse
from django.utils import timezone

from apps.audit.models import AuditLog

from .models import Invitation, Membership, Organization, Role

User = get_user_model()
PASSWORD = "Str0ng-pass-123"


def make_member(org, email, role):
    user = User.objects.create_user(email=email, password=PASSWORD, full_name=email)
    Membership.objects.create(user=user, organization=org, role=role)
    return user


def logged_in_client(user):
    client = Client()
    client.force_login(user)
    return client


class InviteTests(TestCase):
    def setUp(self):
        self.org = Organization.objects.create(name="Alpha")
        self.admin = make_member(self.org, "admin@alpha.org", Role.ORG_ADMIN)
        self.client = logged_in_client(self.admin)

    def invite(self, email="new@alpha.org", role=Role.SECURITY_ANALYST):
        return self.client.post(reverse("organizations:team"), {"email": email, "role": role})

    def test_admin_can_invite_and_email_contains_the_link(self):
        response = self.invite()
        self.assertRedirects(response, reverse("organizations:team"))
        invitation = Invitation.objects.get(email="new@alpha.org")
        self.assertEqual(invitation.role, Role.SECURITY_ANALYST)
        self.assertEqual(len(mail.outbox), 1)
        self.assertIn(invitation.token, mail.outbox[0].body)
        self.assertEqual(mail.outbox[0].to, ["new@alpha.org"])

    def test_invitation_is_audited(self):
        self.invite()
        self.assertTrue(
            AuditLog.objects.filter(organization=self.org, action="invitation.created").exists()
        )

    def test_non_admin_cannot_open_or_use_the_team_page(self):
        analyst = make_member(self.org, "analyst@alpha.org", Role.SECURITY_ANALYST)
        client = logged_in_client(analyst)
        self.assertEqual(client.get(reverse("organizations:team")).status_code, 403)
        response = client.post(
            reverse("organizations:team"), {"email": "x@alpha.org", "role": Role.EMPLOYEE}
        )
        self.assertEqual(response.status_code, 403)
        self.assertFalse(Invitation.objects.exists())

    def test_cannot_invite_an_existing_member(self):
        self.invite(email="admin@alpha.org")
        self.assertFalse(Invitation.objects.exists())

    def test_cannot_send_a_second_pending_invitation(self):
        self.invite()
        self.invite()
        self.assertEqual(Invitation.objects.filter(email="new@alpha.org").count(), 1)
        self.assertEqual(len(mail.outbox), 1)

    def test_team_page_shows_only_own_organization(self):
        other = Organization.objects.create(name="Beta")
        make_member(other, "bob@beta.org", Role.EMPLOYEE)
        Invitation.objects.create(organization=other, email="secret@beta.org")
        response = self.client.get(reverse("organizations:team"))
        self.assertNotContains(response, "bob@beta.org")
        self.assertNotContains(response, "secret@beta.org")


class AcceptTests(TestCase):
    def setUp(self):
        self.org = Organization.objects.create(name="Alpha")
        self.admin = make_member(self.org, "admin@alpha.org", Role.ORG_ADMIN)
        self.invitation = Invitation.objects.create(
            organization=self.org,
            email="new@alpha.org",
            role=Role.SECURITY_ANALYST,
            invited_by=self.admin,
        )
        self.url = reverse("organizations:accept_invitation", args=[self.invitation.token])

    def signup_data(self):
        return {"full_name": "New Person", "password1": PASSWORD, "password2": PASSWORD}

    def test_new_person_creates_account_and_joins_with_the_invited_role(self):
        client = Client()
        response = client.post(self.url, self.signup_data())
        self.assertRedirects(response, reverse("home"))
        user = User.objects.get(email="new@alpha.org")
        membership = Membership.objects.get(user=user, organization=self.org)
        self.assertEqual(membership.role, Role.SECURITY_ANALYST)
        self.assertEqual(client.session["_auth_user_id"], str(user.pk))
        self.invitation.refresh_from_db()
        self.assertIsNotNone(self.invitation.accepted_at)

    def test_acceptance_is_audited(self):
        Client().post(self.url, self.signup_data())
        actions = set(
            AuditLog.objects.filter(organization=self.org).values_list("action", flat=True)
        )
        self.assertIn("invitation.accepted", actions)
        self.assertIn("membership.created", actions)

    def test_token_cannot_be_used_twice(self):
        Client().post(self.url, self.signup_data())
        self.assertEqual(Client().get(self.url).status_code, 410)
        self.assertEqual(Client().post(self.url, self.signup_data()).status_code, 410)
        self.assertEqual(Membership.objects.filter(organization=self.org).count(), 2)

    def test_expired_token_fails(self):
        self.invitation.expires_at = timezone.now() - timedelta(minutes=1)
        self.invitation.save()
        self.assertEqual(Client().get(self.url).status_code, 410)
        self.assertEqual(Client().post(self.url, self.signup_data()).status_code, 410)
        self.assertFalse(User.objects.filter(email="new@alpha.org").exists())

    def test_unknown_token_is_404(self):
        url = reverse("organizations:accept_invitation", args=["not-a-real-token"])
        self.assertEqual(Client().get(url).status_code, 404)

    def test_weak_password_is_rejected(self):
        data = {"full_name": "New", "password1": "12345678", "password2": "12345678"}
        response = Client().post(self.url, data)
        self.assertEqual(response.status_code, 200)
        self.assertFalse(User.objects.filter(email="new@alpha.org").exists())

    def test_existing_user_is_sent_to_login_first(self):
        User.objects.create_user(email="new@alpha.org", password=PASSWORD, full_name="Old")
        response = Client().get(self.url)
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse("accounts:login"), response.url)

    def test_logged_in_existing_user_can_accept_and_switches_organization(self):
        other_org = Organization.objects.create(name="Beta")
        user = make_member(other_org, "new@alpha.org", Role.EMPLOYEE)
        client = logged_in_client(user)
        client.post(self.url)
        self.assertTrue(Membership.objects.filter(user=user, organization=self.org).exists())
        self.assertEqual(client.session["active_organization_id"], self.org.pk)

    def test_wrong_logged_in_user_cannot_accept(self):
        stranger = make_member(Organization.objects.create(name="Beta"), "bob@beta.org", Role.EMPLOYEE)
        client = logged_in_client(stranger)
        response = client.post(self.url)
        self.assertContains(response, "different email address")
        self.assertFalse(Membership.objects.filter(user=stranger, organization=self.org).exists())
        self.invitation.refresh_from_db()
        self.assertIsNone(self.invitation.accepted_at)
