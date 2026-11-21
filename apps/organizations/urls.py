from django.urls import path

from .views import OrganizationSignupView

app_name = "organizations"

urlpatterns = [
    path("signup/", OrganizationSignupView.as_view(), name="signup"),
]
