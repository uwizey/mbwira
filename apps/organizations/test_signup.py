from django.contrib.auth import get_user_model
from django.test import Client, TestCase
from django.urls import reverse

from apps.audit.models import AuditLog
from apps.organizations.models import Membership, Organization, Role

User = get_user_model()
GOOD_PASSWORD = "Str0ng-pass-123"


def payload(**overrides):
    data = {
        "organization_name": "Alpha Hospital",
        "full_name": "Alice Admin",
        "email": "alice@alpha.org",
        "password1": GOOD_PASSWORD,
        "password2": GOOD_PASSWORD,
    }
    data.update(overrides)
    return data


class SignupTests(TestCase):
    def test_signup_creates_user_organization_admin_membership_and_logs_in(self):
        response = self.client.post(reverse("organizations:signup"), payload())
        self.assertRedirects(response, reverse("home"))

        user = User.objects.get(email="alice@alpha.org")
        organization = Organization.objects.get(name="Alpha Hospital")
        membership = Membership.objects.get(user=user, organization=organization)
        self.assertEqual(membership.role, Role.ORG_ADMIN)
        self.assertEqual(self.client.session["_auth_user_id"], str(user.pk))

    def test_signup_writes_audit_entries(self):
        self.client.post(reverse("organizations:signup"), payload())
        organization = Organization.objects.get(name="Alpha Hospital")
        actions = set(
            AuditLog.objects.filter(organization=organization).values_list("action", flat=True)
        )
        self.assertEqual(actions, {"organization.created", "membership.created"})

    def test_duplicate_email_is_rejected(self):
        User.objects.create_user(email="alice@alpha.org", password=GOOD_PASSWORD, full_name="Existing")
        response = self.client.post(reverse("organizations:signup"), payload())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(Organization.objects.count(), 0)

    def test_mismatched_passwords_are_rejected(self):
        response = self.client.post(
            reverse("organizations:signup"), payload(password2="Different-pass-456")
        )
        self.assertEqual(response.status_code, 200)
        self.assertFalse(User.objects.filter(email="alice@alpha.org").exists())

    def test_weak_password_is_rejected(self):
        response = self.client.post(
            reverse("organizations:signup"), payload(password1="12345678", password2="12345678")
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(Organization.objects.count(), 0)

    def test_logged_in_user_is_redirected_away_from_signup(self):
        self.client.post(reverse("organizations:signup"), payload())
        response = self.client.get(reverse("organizations:signup"))
        self.assertRedirects(response, reverse("home"))


class TwoSignupsAreIsolatedTests(TestCase):
    def test_each_admin_sees_only_their_own_organization(self):
        alice = Client()
        bob = Client()
        alice.post(reverse("organizations:signup"), payload())
        bob.post(
            reverse("organizations:signup"),
            payload(organization_name="Beta University", full_name="Bob", email="bob@beta.org"),
        )

        alice_home = alice.get(reverse("home"))
        self.assertContains(alice_home, "Alpha Hospital")
        self.assertNotContains(alice_home, "Beta University")

        bob_home = bob.get(reverse("home"))
        self.assertContains(bob_home, "Beta University")
        self.assertNotContains(bob_home, "Alpha Hospital")
