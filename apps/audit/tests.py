from django.contrib.auth import get_user_model
from django.test import TestCase

from apps.organizations.models import Organization

from .models import AuditLog, AuditLogImmutableError
from .services import log_action

User = get_user_model()


class AuditLogTests(TestCase):
    def setUp(self):
        self.org = Organization.objects.create(name="Org A")
        self.user = User.objects.create_user(
            email="a@example.com", password="Str0ng-pass-123", full_name="A"
        )

    def test_log_action_records_who_what_and_when(self):
        entry = log_action(
            self.user,
            "organization.created",
            obj=self.org,
            organization=self.org,
            details={"name": "Org A"},
        )
        self.assertEqual(entry.actor, self.user)
        self.assertEqual(entry.organization, self.org)
        self.assertEqual(entry.object_type, "organizations.organization")
        self.assertEqual(entry.object_id, str(self.org.pk))
        self.assertEqual(entry.details, {"name": "Org A"})
        self.assertIsNotNone(entry.created_at)

    def test_system_action_may_have_no_actor(self):
        entry = log_action(None, "system.cleanup")
        self.assertIsNone(entry.actor)

    def test_entry_cannot_be_modified(self):
        entry = log_action(self.user, "x", organization=self.org)
        entry.action = "tampered"
        with self.assertRaises(AuditLogImmutableError):
            entry.save()

    def test_entry_cannot_be_deleted(self):
        entry = log_action(self.user, "x", organization=self.org)
        with self.assertRaises(AuditLogImmutableError):
            entry.delete()

    def test_queryset_update_and_delete_are_blocked(self):
        log_action(self.user, "x", organization=self.org)
        with self.assertRaises(AuditLogImmutableError):
            AuditLog.objects.all().update(action="tampered")
        with self.assertRaises(AuditLogImmutableError):
            AuditLog.objects.all().delete()
