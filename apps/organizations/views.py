from django.contrib import messages
from django.contrib.auth import get_user_model, login
from django.db import transaction
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse, reverse_lazy
from django.views.generic import FormView

from apps.core.middleware import SESSION_KEY
from apps.core.mixins import RoleRequiredMixin

from .forms import AcceptInvitationForm, InvitationForm, OrganizationSignupForm
from .models import Invitation, Role
from .services import (
    InvitationError,
    accept_invitation,
    create_invitation,
    register_organization,
)

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


class TeamView(RoleRequiredMixin, FormView):
    """Org admins see their members and invitations, and invite new people."""

    template_name = "organizations/team.html"
    form_class = InvitationForm
    success_url = reverse_lazy("organizations:team")
    allowed_roles = (Role.ORG_ADMIN,)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        organization = self.request.organization
        context["memberships"] = organization.memberships.select_related("user").order_by(
            "user__full_name"
        )
        context["invitations"] = organization.invitations.order_by("-created_at")[:20]
        return context

    def form_valid(self, form):
        try:
            create_invitation(
                organization=self.request.organization,
                email=form.cleaned_data["email"],
                role=form.cleaned_data["role"],
                invited_by=self.request.user,
                request=self.request,
            )
        except InvitationError as error:
            form.add_error("email", str(error))
            return self.form_invalid(form)
        messages.success(self.request, "Invitation sent.")
        return super().form_valid(form)


def accept_invitation_view(request, token):
    invitation = get_object_or_404(
        Invitation.objects.select_related("organization"), token=token
    )
    if not invitation.is_valid:
        return render(request, "organizations/invitation_invalid.html", status=410)

    template = "organizations/accept_invitation.html"
    context = {"invitation": invitation}
    user = request.user

    if user.is_authenticated:
        if user.email.lower() != invitation.email.lower():
            context["mismatch"] = True
            return render(request, template, context)
        if request.method == "POST":
            try:
                accept_invitation(invitation=invitation, user=user)
            except InvitationError as error:
                messages.error(request, str(error))
                return redirect("home")
            request.session[SESSION_KEY] = invitation.organization_id
            messages.success(request, f"You joined {invitation.organization.name}.")
            return redirect("home")
        return render(request, template, context)

    if User.objects.filter(email__iexact=invitation.email).exists():
        messages.info(request, "Log in with the invited email address to accept.")
        return redirect(f"{reverse('accounts:login')}?next={request.path}")

    form = AcceptInvitationForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        try:
            with transaction.atomic():
                new_user = User.objects.create_user(
                    email=invitation.email.lower(),
                    password=form.cleaned_data["password1"],
                    full_name=form.cleaned_data["full_name"],
                )
                accept_invitation(invitation=invitation, user=new_user)
        except InvitationError as error:
            messages.error(request, str(error))
            return redirect("accounts:login")
        login(request, new_user)
        request.session[SESSION_KEY] = invitation.organization_id
        messages.success(request, f"Welcome to {invitation.organization.name}.")
        return redirect("home")

    context["form"] = form
    return render(request, template, context)
