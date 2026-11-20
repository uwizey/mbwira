from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser
from django.core.exceptions import PermissionDenied
from django.http import HttpResponse
from django.test import RequestFactory, TestCase
from django.views import View
from django.views.generic import ListView

from apps.audit.models import AuditLog
from apps.audit.services import log_action
from apps.organizations.models import Membership, Organization, Role

from .middleware import ActiveOrganizationMiddleware
from .mixins import OrganizationScopedMixin, RoleRequiredMixin

User = get_user_model()
PASSWORD = "Str0ng-pass-123"


def make_user(email):
    return User.objects.create_user(email=email, password=PASSWORD, full_name=email)


def make_request(user=None):
    request = RequestFactory().get("/")
    request.user = user if user is not None else AnonymousUser()
    ActiveOrganizationMiddleware(lambda r: HttpResponse())(request)
    return request


class TwoOrganizationsTestCase(TestCase):
    def setUp(self):
        self.org_a = Organization.objects.create(name="Org A")
        self.org_b = Organization.objects.create(name="Org B")
        self.alice = make_user("alice@a.com")
        self.bob = make_user("bob@b.com")
        Membership.objects.create(
            user=self.alice, organization=self.org_a, role=Role.SECURITY_ANALYST
        )
        Membership.objects.create(
            user=self.bob, organization=self.org_b, role=Role.EMPLOYEE
        )


class MiddlewareTests(TwoOrganizationsTestCase):
    def test_organization_comes_from_the_users_membership(self):
        request = make_request(self.alice)
        self.assertEqual(request.organization, self.org_a)
        self.assertEqual(request.membership.role, Role.SECURITY_ANALYST)

    def test_anonymous_user_has_no_organization(self):
        request = make_request()
        self.assertIsNone(request.organization)

    def test_user_without_membership_has_no_organization(self):
        request = make_request(make_user("loner@x.com"))
        self.assertIsNone(request.organization)

    def test_session_cannot_switch_to_an_organization_the_user_is_not_in(self):
        request = RequestFactory().get("/")
        request.user = self.alice
        request.session = {"active_organization_id": self.org_b.pk}
        ActiveOrganizationMiddleware(lambda r: HttpResponse())(request)
        self.assertEqual(request.organization, self.org_a)


class ScopedQuerySetTests(TwoOrganizationsTestCase):
    def test_for_organization_returns_only_that_organizations_rows(self):
        log_action(self.alice, "a.event", organization=self.org_a)
        log_action(self.bob, "b.event", organization=self.org_b)
        rows = AuditLog.objects.for_organization(self.org_a)
        self.assertEqual([r.action for r in rows], ["a.event"])

    def test_no_organization_returns_nothing(self):
        log_action(self.alice, "a.event", organization=self.org_a)
        self.assertEqual(AuditLog.objects.for_organization(None).count(), 0)


class ScopedViewTests(TwoOrganizationsTestCase):
    def test_scoped_mixin_hides_other_organizations_objects(self):
        entry_b = log_action(self.bob, "b.event", organization=self.org_b)

        class ScopedList(OrganizationScopedMixin, ListView):
            model = AuditLog

        view = ScopedList()
        view.request = make_request(self.alice)
        self.assertFalse(view.get_queryset().filter(pk=entry_b.pk).exists())


class RoleMixinTests(TwoOrganizationsTestCase):
    class AnalystOnly(RoleRequiredMixin, View):
        allowed_roles = (Role.SECURITY_ANALYST,)

        def get(self, request):
            return HttpResponse("ok")

    def test_allowed_role_gets_in(self):
        response = self.AnalystOnly.as_view()(make_request(self.alice))
        self.assertEqual(response.status_code, 200)

    def test_other_role_is_denied(self):
        with self.assertRaises(PermissionDenied):
            self.AnalystOnly.as_view()(make_request(self.bob))

    def test_anonymous_is_redirected_to_login(self):
        response = self.AnalystOnly.as_view()(make_request())
        self.assertEqual(response.status_code, 302)

    def test_user_without_organization_is_denied(self):
        with self.assertRaises(PermissionDenied):
            self.AnalystOnly.as_view()(make_request(make_user("loner@x.com")))
