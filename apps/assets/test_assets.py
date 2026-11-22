from django.contrib.auth import get_user_model
from django.test import Client, TestCase
from django.urls import reverse

from apps.audit.models import AuditLog
from apps.organizations.models import Membership, Organization, Role

from .models import Asset

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


def form_data(**overrides):
    data = {
        "name": "LAPTOP-001",
        "asset_type": "laptop",
        "hostname": "lap001",
        "ip_address": "",
        "location": "Head office",
        "status": "active",
        "owner": "",
    }
    data.update(overrides)
    return data


class TwoOrgAssetTestCase(TestCase):
    def setUp(self):
        self.org_a = Organization.objects.create(name="Alpha")
        self.org_b = Organization.objects.create(name="Beta")
        self.admin_a = make_member(self.org_a, "admin@a.org", Role.ORG_ADMIN)
        self.analyst_a = make_member(self.org_a, "analyst@a.org", Role.SECURITY_ANALYST)
        self.manager_a = make_member(self.org_a, "manager@a.org", Role.SECURITY_MANAGER)
        self.employee_a = make_member(self.org_a, "employee@a.org", Role.EMPLOYEE)
        self.analyst_b = make_member(self.org_b, "analyst@b.org", Role.SECURITY_ANALYST)
        self.asset_a = Asset.objects.create(
            organization=self.org_a, name="ALPHA-SERVER", asset_type="server"
        )
        self.asset_b = Asset.objects.create(
            organization=self.org_b, name="BETA-SECRET-SERVER", asset_type="server"
        )


class PermissionTests(TwoOrgAssetTestCase):
    def test_anonymous_is_redirected_to_login(self):
        response = Client().get(reverse("assets:list"))
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse("accounts:login"), response.url)

    def test_employee_cannot_see_or_create_assets(self):
        client = client_for(self.employee_a)
        self.assertEqual(client.get(reverse("assets:list")).status_code, 403)
        self.assertEqual(client.get(reverse("assets:detail", args=[self.asset_a.pk])).status_code, 403)
        self.assertEqual(client.post(reverse("assets:create"), form_data()).status_code, 403)

    def test_manager_can_view_but_not_create_or_edit(self):
        client = client_for(self.manager_a)
        self.assertEqual(client.get(reverse("assets:list")).status_code, 200)
        self.assertEqual(client.get(reverse("assets:detail", args=[self.asset_a.pk])).status_code, 200)
        self.assertEqual(client.get(reverse("assets:create")).status_code, 403)
        edit = client.post(reverse("assets:edit", args=[self.asset_a.pk]), form_data(name="Hacked"))
        self.assertEqual(edit.status_code, 403)
        self.asset_a.refresh_from_db()
        self.assertEqual(self.asset_a.name, "ALPHA-SERVER")

    def test_admin_and_analyst_can_create(self):
        for user in (self.admin_a, self.analyst_a):
            response = client_for(user).post(reverse("assets:create"), form_data(name=f"by-{user.pk}"))
            self.assertEqual(response.status_code, 302)
        self.assertEqual(Asset.objects.filter(organization=self.org_a).count(), 3)


class CreateAndEditTests(TwoOrgAssetTestCase):
    def test_organization_is_set_by_the_server_not_the_form(self):
        client = client_for(self.analyst_a)
        client.post(reverse("assets:create"), form_data(name="Sneaky", organization=self.org_b.pk))
        asset = Asset.objects.get(name="Sneaky")
        self.assertEqual(asset.organization, self.org_a)

    def test_creating_writes_an_audit_entry(self):
        client_for(self.analyst_a).post(reverse("assets:create"), form_data(name="Audited"))
        asset = Asset.objects.get(name="Audited")
        self.assertTrue(
            AuditLog.objects.filter(
                organization=self.org_a, action="asset.created", object_id=str(asset.pk)
            ).exists()
        )

    def test_editing_writes_an_audit_entry_with_changed_fields(self):
        data = form_data(name="ALPHA-SERVER", asset_type="server", status="under_repair")
        client_for(self.analyst_a).post(reverse("assets:edit", args=[self.asset_a.pk]), data)
        self.asset_a.refresh_from_db()
        self.assertEqual(self.asset_a.status, "under_repair")
        entry = AuditLog.objects.get(action="asset.updated", object_id=str(self.asset_a.pk))
        self.assertIn("status", entry.details["changed"])

    def test_owner_must_belong_to_the_same_organization(self):
        response = client_for(self.analyst_a).post(
            reverse("assets:create"), form_data(name="Bad owner", owner=self.analyst_b.pk)
        )
        self.assertEqual(response.status_code, 200)
        self.assertFalse(Asset.objects.filter(name="Bad owner").exists())

    def test_owner_from_same_organization_is_accepted(self):
        response = client_for(self.analyst_a).post(
            reverse("assets:create"), form_data(name="Owned", owner=self.employee_a.pk)
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(Asset.objects.get(name="Owned").owner, self.employee_a)


class IsolationTests(TwoOrgAssetTestCase):
    def test_list_shows_only_own_organizations_assets(self):
        response = client_for(self.analyst_a).get(reverse("assets:list"))
        self.assertContains(response, "ALPHA-SERVER")
        self.assertNotContains(response, "BETA-SECRET-SERVER")

    def test_changing_the_id_in_the_url_gives_404_for_detail(self):
        response = client_for(self.analyst_a).get(reverse("assets:detail", args=[self.asset_b.pk]))
        self.assertEqual(response.status_code, 404)

    def test_other_organizations_edit_page_is_404(self):
        response = client_for(self.analyst_a).get(reverse("assets:edit", args=[self.asset_b.pk]))
        self.assertEqual(response.status_code, 404)

    def test_cannot_edit_another_organizations_asset(self):
        response = client_for(self.analyst_a).post(
            reverse("assets:edit", args=[self.asset_b.pk]), form_data(name="Hijacked")
        )
        self.assertEqual(response.status_code, 404)
        self.asset_b.refresh_from_db()
        self.assertEqual(self.asset_b.name, "BETA-SECRET-SERVER")

    def test_audit_entries_stay_inside_their_organization(self):
        client_for(self.analyst_a).post(reverse("assets:create"), form_data(name="Audited"))
        self.assertFalse(
            AuditLog.objects.filter(organization=self.org_b, action="asset.created").exists()
        )


class FilterTests(TwoOrgAssetTestCase):
    def setUp(self):
        super().setUp()
        Asset.objects.create(organization=self.org_a, name="LAPTOP-A1", asset_type="laptop", status="lost")
        Asset.objects.create(organization=self.org_a, name="PRINTER-A1", asset_type="printer")

    def test_filter_by_type(self):
        response = client_for(self.analyst_a).get(reverse("assets:list"), {"type": "printer"})
        self.assertContains(response, "PRINTER-A1")
        self.assertNotContains(response, "LAPTOP-A1")

    def test_filter_by_status(self):
        response = client_for(self.analyst_a).get(reverse("assets:list"), {"status": "lost"})
        self.assertContains(response, "LAPTOP-A1")
        self.assertNotContains(response, "PRINTER-A1")

    def test_search_by_name(self):
        response = client_for(self.analyst_a).get(reverse("assets:list"), {"q": "printer"})
        self.assertContains(response, "PRINTER-A1")
        self.assertNotContains(response, "LAPTOP-A1")
