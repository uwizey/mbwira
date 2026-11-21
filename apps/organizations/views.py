from django.contrib.auth import get_user_model, login
from django.db import transaction
from django.shortcuts import redirect
from django.urls import reverse_lazy
from django.views.generic import FormView

from .forms import OrganizationSignupForm
from .services import register_organization

User = get_user_model()


class OrganizationSignupView(FormView):
    template_name = "organizations/signup.html"
    form_class = OrganizationSignupForm
    success_url = reverse_lazy("home")

    def dispatch(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            return redirect("home")
        return super().dispatch(request, *args, **kwargs)

    def form_valid(self, form):
        data = form.cleaned_data
        with transaction.atomic():
            user = User.objects.create_user(
                email=data["email"],
                password=data["password1"],
                full_name=data["full_name"],
            )
            register_organization(name=data["organization_name"], admin_user=user)
        login(self.request, user)
        return super().form_valid(form)
