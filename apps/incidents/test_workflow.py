from datetime import timedelta

from django.contrib.auth import get_user_model
from django.test import Client, TestCase
from django.urls import reverse
from django.utils import timezone

from apps.audit.models import AuditLog
from apps.organizations.models import Membership, Organization, Role

from .models import Incident
from .services import (
    WorkflowError,
    add_comment,
    available_transitions,
    create_incident,
    transition_incident,
)

User = get_user_model()
PASSWORD = "Str0ng-pass-123"


def make_member(org, email, role):
    user = User.objects.create_user(email=email, password=PASSWORD, full_name=email)
    Membership.objects.create(user=user, organization=org, role=role)
    return user


def client_for(user):
    client = Client()
    client.force_login(user)
    return client


def make_incident(org, reporter, title):
    return create_incident(
        organization=org,
        reporter=reporter,
        incident_type="security",
        title=title,
        description="Details",
        occurred_at=timezone.now() - timedelta(hours=1),
    )


class WorkflowBase(TestCase):
    def setUp(self):
        self.org_a = Organization.objects.create(name="Alpha")
        self.org_b = Organization.objects.create(name="Beta")
        self.admin = make_member(self.org_a, "admin@a.org", Role.ORG_ADMIN)
        self.manager = make_member(self.org_a, "manager@a.org", Role.SECURITY_MANAGER)
        self.analyst = make_member(self.org_a, "analyst@a.org", Role.SECURITY_ANALYST)
        self.emp1 = make_member(self.org_a, "emp1@a.org", Role.EMPLOYEE)
        self.emp2 = make_member(self.org_a, "emp2@a.org", Role.EMPLOYEE)
        self.analyst_b = make_member(self.org_b, "analyst@b.org", Role.SECURITY_ANALYST)
        self.emp_b = make_member(self.org_b, "emp@b.org", Role.EMPLOYEE)
        self.incident = make_incident(self.org_a, self.emp1, "Alpha one")
        self.other = make_incident(self.org_b, self.emp_b, "Beta secret")

    def put(self, status):
        """Force the incident into a state, bypassing the workflow (test setup only)."""
        fields = {
            "status": status,
            "category": "phishing",
            "severity": "high",
            "assignee": self.analyst,
        }
        if status in ("resolved", "closed"):
            fields["resolution_summary"] = "Fixed it"
            fields["resolved_at"] = timezone.now()
        Incident.objects.filter(pk=self.incident.pk).update(**fields)
        self.incident.refresh_from_db()

    def move(self, to_status, note="", actor=None):
        return transition_incident(
            incident=self.incident, actor=actor or self.analyst, to_status=to_status, note=note
        )


class TransitionRuleTests(WorkflowBase):
    def test_full_lifecycle(self):
        self.move("under_review")
        Incident.objects.filter(pk=self.incident.pk).update(
            category="phishing", severity="high", assignee=self.analyst
        )
        self.move("investigating")
        self.move("resolved", "Removed the email and reset the password")
        self.move("closed")
        self.incident.refresh_from_db()
        self.assertEqual(self.incident.status, "closed")
        self.assertEqual(
            self.incident.resolution_summary, "Removed the email and reset the password"
        )
        self.assertIsNotNone(self.incident.resolved_at)
        changes = AuditLog.objects.filter(
            action="incident.status_changed", object_id=str(self.incident.pk)
        )
        self.assertEqual(changes.count(), 4)

    def test_invalid_jumps_are_rejected(self):
        cases = [
            ("reported", "resolved"),
            ("reported", "closed"),
            ("reported", "investigating"),
            ("under_review", "resolved"),
            ("investigating", "closed"),
            ("investigating", "under_review"),
            ("resolved", "under_review"),
            ("resolved", "reported"),
            ("closed", "resolved"),
            ("closed", "closed"),
        ]
        for current, target in cases:
            with self.subTest(current=current, target=target):
                self.put(current)
                with self.assertRaises(WorkflowError):
                    self.move(target, "note", actor=self.manager)
                self.incident.refresh_from_db()
                self.assertEqual(self.incident.status, current)

    def test_unknown_status_is_rejected(self):
        with self.assertRaises(WorkflowError):
            self.move("banana", "note")

    def test_resolving_requires_a_summary(self):
        self.put("investigating")
        for note in ("", "   "):
            with self.assertRaises(WorkflowError):
                self.move("resolved", note)
        self.incident.refresh_from_db()
        self.assertEqual(self.incident.status, "investigating")

    def test_resolving_records_summary_and_time(self):
        self.put("investigating")
        self.move("resolved", "  Replaced the faulty switch  ")
        self.incident.refresh_from_db()
        self.assertEqual(self.incident.resolution_summary, "Replaced the faulty switch")
        self.assertIsNotNone(self.incident.resolved_at)

    def test_investigating_needs_category_severity_and_assignee(self):
        Incident.objects.filter(pk=self.incident.pk).update(status="under_review")
        with self.assertRaises(WorkflowError) as context:
            self.move("investigating")
        for word in ("category", "severity", "assignee"):
            self.assertIn(word, str(context.exception))
        self.put("under_review")
        self.move("investigating")
        self.incident.refresh_from_db()
        self.assertEqual(self.incident.status, "investigating")

    def test_closing_a_duplicate_needs_a_reason_and_keeps_it(self):
        Incident.objects.filter(pk=self.incident.pk).update(status="under_review")
        with self.assertRaises(WorkflowError):
            self.move("closed")
        self.move("closed", "Duplicate of INC-0007")
        self.incident.refresh_from_db()
        self.assertEqual(self.incident.status, "closed")
        self.assertEqual(self.incident.resolution_summary, "Duplicate of INC-0007")
        self.assertIsNone(self.incident.resolved_at)

    def test_closing_a_resolved_incident_needs_no_extra_note(self):
        self.put("resolved")
        self.move("closed")
        self.incident.refresh_from_db()
        self.assertEqual(self.incident.status, "closed")
        self.assertEqual(self.incident.resolution_summary, "Fixed it")


class ReopenTests(WorkflowBase):
    def reopen(self, actor, note="Still broken"):
        return transition_incident(
            incident=self.incident, actor=actor, to_status="investigating", note=note
        )

    def test_only_a_manager_can_reopen(self):
        for state in ("resolved", "closed"):
            with self.subTest(state=state):
                self.put(state)
                with self.assertRaises(WorkflowError):
                    self.reopen(self.analyst)
                self.reopen(self.manager)
                self.incident.refresh_from_db()
                self.assertEqual(self.incident.status, "investigating")

    def test_reopen_needs_a_reason(self):
        self.put("resolved")
        with self.assertRaises(WorkflowError):
            self.reopen(self.manager, note="")

    def test_reopen_records_the_reason_as_a_comment_and_clears_the_resolution(self):
        self.put("closed")
        self.reopen(self.manager, note="Problem came back")
        self.incident.refresh_from_db()
        self.assertEqual(self.incident.resolution_summary, "")
        self.assertIsNone(self.incident.resolved_at)
        comment = self.incident.comments.get()
        self.assertIn("Problem came back", comment.body)
        self.assertFalse(comment.is_internal)
        entry = AuditLog.objects.get(
            action="incident.status_changed", object_id=str(self.incident.pk)
        )
        self.assertEqual(entry.details["previous_summary"], "Fixed it")

    def test_triage_is_blocked_on_resolved_or_closed_incidents(self):
        from .services import triage_incident

        self.put("closed")
        with self.assertRaises(WorkflowError):
            triage_incident(
                incident=self.incident,
                actor=self.analyst,
                incident_type="security",
                category="malware",
                severity="low",
                assignee=self.analyst,
            )


class ServicePermissionTests(WorkflowBase):
    def test_employee_and_org_admin_cannot_change_status(self):
        for actor in (self.emp1, self.admin):
            with self.assertRaises(WorkflowError):
                self.move("under_review", actor=actor)

    def test_a_member_of_another_organization_cannot_change_status(self):
        with self.assertRaises(WorkflowError):
            self.move("under_review", actor=self.analyst_b)


class AvailableTransitionsTests(WorkflowBase):
    def targets(self, status, role):
        self.put(status)
        return {t["to"] for t in available_transitions(self.incident, role)}

    def test_buttons_per_status_and_role(self):
        analyst, manager = Role.SECURITY_ANALYST, Role.SECURITY_MANAGER
        self.assertEqual(self.targets("reported", analyst), {"under_review"})
        self.assertEqual(self.targets("under_review", analyst), {"investigating", "closed"})
        self.assertEqual(self.targets("investigating", analyst), {"resolved"})
        self.assertEqual(self.targets("resolved", analyst), {"closed"})
        self.assertEqual(self.targets("resolved", manager), {"closed", "investigating"})
        self.assertEqual(self.targets("closed", analyst), set())
        self.assertEqual(self.targets("closed", manager), {"investigating"})
        for role in (Role.EMPLOYEE, Role.ORG_ADMIN):
            self.assertEqual(self.targets("reported", role), set())


class TransitionViewTests(WorkflowBase):
    def url(self, incident=None):
        return reverse("incidents:transition", args=[(incident or self.incident).pk])

    def test_analyst_can_move_an_incident(self):
        response = client_for(self.analyst).post(self.url(), {"to_status": "under_review"})
        self.assertRedirects(response, self.incident.get_absolute_url())
        self.incident.refresh_from_db()
        self.assertEqual(self.incident.status, "under_review")

    def test_employee_and_org_admin_get_403(self):
        for user in (self.emp1, self.admin):
            response = client_for(user).post(self.url(), {"to_status": "under_review"})
            self.assertEqual(response.status_code, 403)
        self.incident.refresh_from_db()
        self.assertEqual(self.incident.status, "reported")

    def test_get_is_not_allowed(self):
        self.assertEqual(client_for(self.analyst).get(self.url()).status_code, 405)

    def test_another_organizations_incident_is_404(self):
        response = client_for(self.analyst).post(self.url(self.other), {"to_status": "under_review"})
        self.assertEqual(response.status_code, 404)
        self.other.refresh_from_db()
        self.assertEqual(self.other.status, "reported")

    def test_invalid_change_shows_a_message_and_changes_nothing(self):
        response = client_for(self.analyst).post(
            self.url(), {"to_status": "banana"}, follow=True
        )
        self.assertContains(response, "cannot move")
        self.incident.refresh_from_db()
        self.assertEqual(self.incident.status, "reported")

    def test_missing_summary_shows_a_message(self):
        self.put("investigating")
        response = client_for(self.analyst).post(
            self.url(), {"to_status": "resolved", "note": ""}, follow=True
        )
        self.assertContains(response, "is required")
        self.incident.refresh_from_db()
        self.assertEqual(self.incident.status, "investigating")

    def test_resolving_through_the_view(self):
        self.put("investigating")
        client_for(self.analyst).post(
            self.url(), {"to_status": "resolved", "note": "Replaced the cable"}
        )
        self.incident.refresh_from_db()
        self.assertEqual(self.incident.status, "resolved")
        self.assertEqual(self.incident.resolution_summary, "Replaced the cable")

    def test_action_buttons_only_show_for_roles_that_can_use_them(self):
        detail = self.incident.get_absolute_url()
        self.assertContains(client_for(self.analyst).get(detail), self.url())
        self.assertNotContains(client_for(self.admin).get(detail), self.url())
        self.assertNotContains(client_for(self.emp1).get(detail), self.url())


class CommentTests(WorkflowBase):
    def url(self, incident=None):
        return reverse("incidents:comment", args=[(incident or self.incident).pk])

    def test_employee_can_comment_on_their_own_incident(self):
        response = client_for(self.emp1).post(self.url(), {"body": "It happens every day"})
        self.assertEqual(response.status_code, 302)
        comment = self.incident.comments.get()
        self.assertEqual(comment.author, self.emp1)

    def test_employee_cannot_write_internal_notes(self):
        client_for(self.emp1).post(self.url(), {"body": "Sneaky", "is_internal": "on"})
        self.assertFalse(self.incident.comments.get().is_internal)

    def test_employee_cannot_comment_on_a_colleagues_incident(self):
        response = client_for(self.emp2).post(self.url(), {"body": "Hello"})
        self.assertEqual(response.status_code, 404)
        self.assertEqual(self.incident.comments.count(), 0)

    def test_staff_can_write_internal_notes(self):
        for user in (self.analyst, self.manager, self.admin):
            client_for(user).post(self.url(), {"body": f"Note {user.pk}", "is_internal": "on"})
        self.assertEqual(self.incident.comments.filter(is_internal=True).count(), 3)

    def test_org_admin_can_comment(self):
        response = client_for(self.admin).post(self.url(), {"body": "Please prioritize"})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.incident.comments.count(), 1)

    def test_other_organization_gets_404_and_nothing_is_saved(self):
        response = client_for(self.analyst_b).post(self.url(), {"body": "Intruder"})
        self.assertEqual(response.status_code, 404)
        self.assertEqual(self.incident.comments.count(), 0)

    def test_empty_comment_is_rejected(self):
        client_for(self.analyst).post(self.url(), {"body": "   "})
        self.assertEqual(self.incident.comments.count(), 0)

    def test_service_rejects_a_non_member(self):
        with self.assertRaises(WorkflowError):
            add_comment(incident=self.incident, author=self.analyst_b, body="Hi")

    def test_comment_is_audited(self):
        client_for(self.analyst).post(self.url(), {"body": "Checking logs"})
        self.assertTrue(
            AuditLog.objects.filter(
                action="incident.commented", object_id=str(self.incident.pk)
            ).exists()
        )

    def test_employee_never_sees_internal_notes_but_staff_do(self):
        add_comment(incident=self.incident, author=self.analyst, body="PUBLIC-REPLY")
        add_comment(
            incident=self.incident, author=self.analyst, body="INTERNAL-ONLY", is_internal=True
        )
        detail = self.incident.get_absolute_url()
        employee_page = client_for(self.emp1).get(detail)
        self.assertContains(employee_page, "PUBLIC-REPLY")
        self.assertNotContains(employee_page, "INTERNAL-ONLY")
        for user in (self.analyst, self.manager, self.admin):
            page = client_for(user).get(detail)
            self.assertContains(page, "PUBLIC-REPLY")
            self.assertContains(page, "INTERNAL-ONLY")

    def test_employee_cannot_tick_the_internal_box(self):
        page = client_for(self.emp1).get(self.incident.get_absolute_url())
        self.assertNotContains(page, "Internal note")
