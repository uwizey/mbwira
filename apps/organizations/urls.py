from django.urls import path

from .views import OrganizationSignupView, TeamView, accept_invitation_view

app_name = "organizations"

urlpatterns = [
    path("signup/", OrganizationSignupView.as_view(), name="signup"),
    path("team/", TeamView.as_view(), name="team"),
    path("invitations/<str:token>/", accept_invitation_view, name="accept_invitation"),
]
