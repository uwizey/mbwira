from django.contrib.auth import get_user_model
from django.db import IntegrityError, transaction
from django.test import TestCase
from django.utils import timezone

from .models import Invitation, Membership, Organization, Role

User = get_user_model()


class OrganizationTests(TestCase):
    def test_slug_is_generated_and_unique(self):
        a = Organization.objects.create(name="Kigali Hospital")
        b = Organization.objects.create(name="Kigali Hospital")
        self.assertEqual(a.slug, "kigali-hospital")
        self.assertEqual(b.slug, "kigali-hospital-2")


class MembershipTests(TestCase):
    def test_one_membership_per_user_and_organization(self):
        user = User.objects.create_user(email="a@example.com", password="Str0ng-pass-123", full_name="A")
        org = Organization.objects.create(name="Org A")
        Membership.objects.create(user=user, organization=org, role=Role.EMPLOYEE)
        with self.assertRaises(IntegrityError), transaction.atomic():
            Membership.objects.create(user=user, organization=org, role=Role.ORG_ADMIN)

    def test_same_user_can_have_different_roles_in_two_organizations(self):
        user = User.objects.create_user(email="a@example.com", password="Str0ng-pass-123", full_name="A")
        org1 = Organization.objects.create(name="Org 1")
        org2 = Organization.objects.create(name="Org 2")
        Membership.objects.create(user=user, organization=org1, role=Role.SECURITY_ANALYST)
        Membership.objects.create(user=user, organization=org2, role=Role.EMPLOYEE)
        self.assertEqual(user.memberships.count(), 2)


class InvitationTests(TestCase):
    def setUp(self):
        self.org = Organization.objects.create(name="Org A")

    def test_new_invitation_is_valid_and_has_random_token(self):
        one = Invitation.objects.create(organization=self.org, email="x@example.com")
        two = Invitation.objects.create(organization=self.org, email="y@example.com")
        self.assertTrue(one.is_valid)
        self.assertNotEqual(one.token, two.token)
        self.assertGreaterEqual(len(one.token), 32)

    def test_expired_invitation_is_not_valid(self):
        inv = Invitation.objects.create(organization=self.org, email="x@example.com")
        inv.expires_at = timezone.now() - timezone.timedelta(minutes=1)
        self.assertTrue(inv.is_expired)
        self.assertFalse(inv.is_valid)

    def test_used_invitation_is_not_valid(self):
        inv = Invitation.objects.create(organization=self.org, email="x@example.com")
        inv.accepted_at = timezone.now()
        self.assertFalse(inv.is_valid)
