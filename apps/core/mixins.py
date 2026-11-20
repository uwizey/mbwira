from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.exceptions import PermissionDenied


class OrganizationRequiredMixin(LoginRequiredMixin):
    """Login required, and the user must belong to an organization."""

    def dispatch(self, request, *args, **kwargs):
        if request.user.is_authenticated and request.organization is None:
            raise PermissionDenied("You are not a member of any organization.")
        return super().dispatch(request, *args, **kwargs)


class RoleRequiredMixin(OrganizationRequiredMixin):
    """Only the roles listed in allowed_roles may use the view.

    An empty allowed_roles denies everyone (safe default).
    """

    allowed_roles = ()

    def dispatch(self, request, *args, **kwargs):
        if request.user.is_authenticated and request.organization is not None:
            if request.membership.role not in self.allowed_roles:
                raise PermissionDenied("Your role cannot use this page.")
        return super().dispatch(request, *args, **kwargs)


class OrganizationScopedMixin(OrganizationRequiredMixin):
    """For list and detail views of tenant models.

    Another organization's object is simply not in the queryset, so the
    detail view returns 404 and never reveals that the object exists.
    """

    def get_queryset(self):
        return super().get_queryset().for_organization(self.request.organization)
