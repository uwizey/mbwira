from datetime import timedelta

from django.contrib.auth import get_user_model
from django.db import IntegrityError, transaction
from django.test import Client, TestCase
from django.urls import reverse
from django.utils import timezone

from apps.audit.models import AuditLog
from apps.organizations.models import Membership, Organization, Role

from .models import Incident
from .services import create_incident

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


def make_incident(org, reporter, title="Printer down", incident_type="asset_failure"):
    return create_incident(
        organization=org,
        reporter=reporter,
        incident_type=incident_type,
        title=title,
        description="Details",
        occurred_at=timezone.now() - timedelta(hours=1),
    )


def report_data(**overrides):
    data = {
        "incident_type": "security",
        "title": "Phishing email",
        "description": "I received a suspicious email.",
        "occurred_at": "2024-01-15T09:30",
    }
    data.update(overrides)
    return data


class Base(TestCase):
    def setUp(self):
        self.org_a = Organization.objects.create(name="Alpha")
        self.org_b = Organization.objects.create(name="Beta")
        self.admin_a = make_member(self.org_a, "admin@a.org", Role.ORG_ADMIN)
        self.manager_a = make_member(self.org_a, "manager@a.org", Role.SECURITY_MANAGER)
        self.analyst_a = make_member(self.org_a, "analyst@a.org", Role.SECURITY_ANALYST)
        self.emp_a1 = make_member(self.org_a, "emp1@a.org", Role.EMPLOYEE)
        self.emp_a2 = make_member(self.org_a, "emp2@a.org", Role.EMPLOYEE)
        self.analyst_b = make_member(self.org_b, "analyst@b.org", Role.SECURITY_ANALYST)
        self.emp_b = make_member(self.org_b, "emp@b.org", Role.EMPLOYEE)
        self.inc_a1 = make_incident(self.org_a, self.emp_a1, title="Alpha one")
        self.inc_a2 = make_incident(self.org_a, self.emp_a2, title="Alpha two")
        self.inc_b = make_incident(self.org_b, self.emp_b, title="Beta secret")


class NumberingAndConstraintTests(Base):
    def test_numbers_are_sequential_per_organization(self):
        self.assertEqual(self.inc_a1.reference, "INC-0001")
        self.assertEqual(self.inc_a2.reference, "INC-0002")

    def test_each_organization_has_its_own_sequence(self):
        self.assertEqual(self.inc_b.reference, "INC-0001")

    def test_database_rejects_a_duplicate_number_in_one_organization(self):
        with self.assertRaises(IntegrityError), transaction.atomic():
            Incident.objects.create(
                organization=self.org_a, number=1, incident_type="security", title="Dup",
                description="x", occurred_at=timezone.now(), reporter=self.emp_a1,
            )

    def test_database_rejects_resolved_without_summary(self):
        with self.assertRaises(IntegrityError), transaction.atomic():
            Incident.objects.filter(pk=self.inc_a1.pk).update(status="resolved")

    def test_database_rejects_resolved_time_before_occurred_time(self):
        with self.assertRaises(IntegrityError), transaction.atomic():
            Incident.objects.filter(pk=self.inc_a1.pk).update(
                status="resolved",
                resolution_summary="Fixed",
                resolved_at=self.inc_a1.occurred_at - timedelta(days=1),
            )

    def test_database_accepts_a_valid_resolution(self):
        Incident.objects.filter(pk=self.inc_a1.pk).update(
            status="resolved",
            resolution_summary="Replaced the cable",
            resolved_at=self.inc_a1.occurred_at + timedelta(hours=1),
        )
        self.inc_a1.refresh_from_db()
        self.assertEqual(self.inc_a1.status, "resolved")


class ReportTests(Base):
    def test_employee_can_report_and_is_redirected_to_the_detail_page(self):
        response = client_for(self.emp_a1).post(reverse("incidents:create"), report_data())
        incident = Incident.objects.get(title="Phishing email")
        self.assertRedirects(response, incident.get_absolute_url())
        self.assertEqual(incident.reference, "INC-0003")
        self.assertEqual(incident.status, "reported")
        self.assertEqual(incident.reporter, self.emp_a1)
        self.assertEqual(incident.organization, self.org_a)

    def test_report_is_audited(self):
        client_for(self.emp_a1).post(reverse("incidents:create"), report_data())
        incident = Incident.objects.get(title="Phishing email")
        self.assertTrue(
            AuditLog.objects.filter(
                organization=self.org_a, action="incident.reported", object_id=str(incident.pk)
            ).exists()
        )

    def test_organization_and_triage_fields_cannot_be_set_by_the_reporter(self):
        data = report_data(organization=self.org_b.pk, severity="critical", status="closed",
                           category="phishing", assignee=self.analyst_a.pk)
        client_for(self.emp_a1).post(reverse("incidents:create"), data)
        incident = Incident.objects.get(title="Phishing email")
        self.assertEqual(incident.organization, self.org_a)
        self.assertEqual(incident.status, "reported")
        self.assertEqual(incident.severity, "")
        self.assertEqual(incident.category, "")
        self.assertIsNone(incident.assignee)

    def test_every_role_can_report(self):
        for user in (self.admin_a, self.manager_a, self.analyst_a):
            response = client_for(user).post(reverse("incidents:create"), report_data(title=f"By {user.pk}"))
            self.assertEqual(response.status_code, 302)

    def test_future_time_is_rejected(self):
        future = (timezone.now() + timedelta(days=2)).strftime("%Y-%m-%dT%H:%M")
        response = client_for(self.emp_a1).post(reverse("incidents:create"), report_data(occurred_at=future))
        self.assertEqual(response.status_code, 200)
        self.assertFalse(Incident.objects.filter(title="Phishing email").exists())

    def test_anonymous_is_redirected_to_login(self):
        response = Client().get(reverse("incidents:create"))
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse("accounts:login"), response.url)

    def test_user_without_organization_is_denied(self):
        loner = User.objects.create_user(email="loner@x.org", password=PASSWORD, full_name="Loner")
        self.assertEqual(client_for(loner).get(reverse("incidents:create")).status_code, 403)


class VisibilityTests(Base):
    def test_my_incidents_shows_only_own_reports(self):
        response = client_for(self.emp_a1).get(reverse("incidents:mine"))
        self.assertContains(response, "Alpha one")
        self.assertNotContains(response, "Alpha two")
        self.assertNotContains(response, "Beta secret")

    def test_employee_cannot_open_the_staff_list(self):
        self.assertEqual(client_for(self.emp_a1).get(reverse("incidents:list")).status_code, 403)

    def test_employee_can_open_own_incident(self):
        response = client_for(self.emp_a1).get(self.inc_a1.get_absolute_url())
        self.assertEqual(response.status_code, 200)

    def test_employee_gets_404_for_a_colleagues_incident(self):
        self.assertEqual(client_for(self.emp_a1).get(self.inc_a2.get_absolute_url()).status_code, 404)

    def test_employee_gets_404_for_another_organizations_incident(self):
        self.assertEqual(client_for(self.emp_a1).get(self.inc_b.get_absolute_url()).status_code, 404)

    def test_staff_list_shows_all_of_own_organization_only(self):
        for user in (self.admin_a, self.manager_a, self.analyst_a):
            response = client_for(user).get(reverse("incidents:list"))
            self.assertContains(response, "Alpha one")
            self.assertContains(response, "Alpha two")
            self.assertNotContains(response, "Beta secret")

    def test_changing_the_id_in_the_url_gives_404_across_organizations(self):
        self.assertEqual(client_for(self.analyst_a).get(self.inc_b.get_absolute_url()).status_code, 404)

    def test_staff_can_open_any_incident_in_their_organization(self):
        for user in (self.admin_a, self.manager_a, self.analyst_a):
            self.assertEqual(client_for(user).get(self.inc_a1.get_absolute_url()).status_code, 200)

    def test_only_triage_roles_see_the_triage_button(self):
        url = self.inc_a1.get_absolute_url()
        triage_url = reverse("incidents:triage", args=[self.inc_a1.pk])
        self.assertContains(client_for(self.analyst_a).get(url), triage_url)
        self.assertNotContains(client_for(self.admin_a).get(url), triage_url)
        self.assertNotContains(client_for(self.emp_a1).get(url), triage_url)


class FilterTests(Base):
    def setUp(self):
        super().setUp()
        Incident.objects.filter(pk=self.inc_a1.pk).update(severity="critical", status="investigating")

    def test_filter_by_severity(self):
        response = client_for(self.analyst_a).get(reverse("incidents:list"), {"severity": "critical"})
        self.assertContains(response, "Alpha one")
        self.assertNotContains(response, "Alpha two")

    def test_filter_by_status(self):
        response = client_for(self.analyst_a).get(reverse("incidents:list"), {"status": "investigating"})
        self.assertContains(response, "Alpha one")
        self.assertNotContains(response, "Alpha two")

    def test_search_by_title(self):
        response = client_for(self.analyst_a).get(reverse("incidents:list"), {"q": "two"})
        self.assertContains(response, "Alpha two")
        self.assertNotContains(response, "Alpha one")


class TriageTests(Base):
    def triage_url(self, incident=None):
        return reverse("incidents:triage", args=[(incident or self.inc_a1).pk])

    def triage_data(self, **overrides):
        data = {
            "incident_type": "security",
            "category": "phishing",
            "severity": "high",
            "assignee": self.analyst_a.pk,
        }
        data.update(overrides)
        return data

    def test_employee_and_org_admin_cannot_triage(self):
        for user in (self.emp_a1, self.admin_a):
            client = client_for(user)
            self.assertEqual(client.get(self.triage_url()).status_code, 403)
            self.assertEqual(client.post(self.triage_url(), self.triage_data()).status_code, 403)
        self.inc_a1.refresh_from_db()
        self.assertEqual(self.inc_a1.severity, "")

    def test_analyst_triage_sets_fields_assigns_and_moves_to_under_review(self):
        response = client_for(self.analyst_a).post(self.triage_url(), self.triage_data())
        self.assertRedirects(response, self.inc_a1.get_absolute_url())
        self.inc_a1.refresh_from_db()
        self.assertEqual(self.inc_a1.incident_type, "security")
        self.assertEqual(self.inc_a1.category, "phishing")
        self.assertEqual(self.inc_a1.severity, "high")
        self.assertEqual(self.inc_a1.assignee, self.analyst_a)
        self.assertEqual(self.inc_a1.status, "under_review")

    def test_manager_can_triage(self):
        response = client_for(self.manager_a).post(self.triage_url(), self.triage_data())
        self.assertEqual(response.status_code, 302)

    def test_triage_is_audited(self):
        client_for(self.analyst_a).post(self.triage_url(), self.triage_data())
        actions = set(
            AuditLog.objects.filter(object_id=str(self.inc_a1.pk), organization=self.org_a)
            .values_list("action", flat=True)
        )
        self.assertIn("incident.triaged", actions)
        self.assertIn("incident.status_changed", actions)

    def test_triaging_again_does_not_change_the_status(self):
        client = client_for(self.analyst_a)
        client.post(self.triage_url(), self.triage_data())
        Incident.objects.filter(pk=self.inc_a1.pk).update(status="investigating")
        client.post(self.triage_url(), self.triage_data(severity="critical"))
        self.inc_a1.refresh_from_db()
        self.assertEqual(self.inc_a1.status, "investigating")
        self.assertEqual(self.inc_a1.severity, "critical")

    def test_category_must_match_the_incident_type(self):
        response = client_for(self.analyst_a).post(
            self.triage_url(), self.triage_data(incident_type="asset_failure", category="phishing")
        )
        self.assertEqual(response.status_code, 200)
        self.inc_a1.refresh_from_db()
        self.assertEqual(self.inc_a1.severity, "")

    def test_category_and_severity_are_required(self):
        response = client_for(self.analyst_a).post(
            self.triage_url(), self.triage_data(category="", severity="")
        )
        self.assertEqual(response.status_code, 200)

    def test_assignee_must_be_a_security_member_of_the_same_organization(self):
        for bad in (self.analyst_b, self.emp_a2, self.admin_a):
            response = client_for(self.analyst_a).post(self.triage_url(), self.triage_data(assignee=bad.pk))
            self.assertEqual(response.status_code, 200)
        self.inc_a1.refresh_from_db()
        self.assertIsNone(self.inc_a1.assignee)

    def test_assignee_is_optional(self):
        response = client_for(self.analyst_a).post(self.triage_url(), self.triage_data(assignee=""))
        self.assertEqual(response.status_code, 302)

    def test_cannot_triage_another_organizations_incident(self):
        client = client_for(self.analyst_a)
        self.assertEqual(client.get(self.triage_url(self.inc_b)).status_code, 404)
        self.assertEqual(client.post(self.triage_url(self.inc_b), self.triage_data()).status_code, 404)
        self.inc_b.refresh_from_db()
        self.assertEqual(self.inc_b.severity, "")
        self.assertEqual(self.inc_b.status, "reported")
