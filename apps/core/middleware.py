SESSION_KEY = "active_organization_id"


class ActiveOrganizationMiddleware:
    """Sets request.organization and request.membership on the server.

    The organization is never read from form input or the URL.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        from apps.organizations.models import Membership

        request.organization = None
        request.membership = None

        user = getattr(request, "user", None)
        if user is not None and user.is_authenticated:
            memberships = Membership.objects.select_related("organization").filter(user=user)
            session = getattr(request, "session", None)
            active_id = session.get(SESSION_KEY) if session is not None else None

            membership = None
            if active_id:
                membership = memberships.filter(organization_id=active_id).first()
            if membership is None:
                membership = memberships.order_by("created_at", "id").first()

            if membership is not None:
                request.membership = membership
                request.organization = membership.organization

        return self.get_response(request)
