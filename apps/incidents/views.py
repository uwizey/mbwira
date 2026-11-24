from django.contrib import messages
from django.shortcuts import get_object_or_404, redirect
from django.utils import timezone
from django.views import View
from django.views.generic import DetailView, FormView, ListView

from apps.core.mixins import OrganizationRequiredMixin, OrganizationScopedMixin, RoleRequiredMixin
from apps.organizations.models import Role

from .forms import CommentForm, ReportIncidentForm, TriageForm
from .models import Incident, IncidentStatus, IncidentType, Severity
from .services import (
    WorkflowError,
    add_comment,
    available_transitions,
    create_incident,
    transition_incident,
    triage_incident,
)

STAFF_ROLES = (Role.ORG_ADMIN, Role.SECURITY_MANAGER, Role.SECURITY_ANALYST)
TRIAGE_ROLES = (Role.SECURITY_MANAGER, Role.SECURITY_ANALYST)


def incidents_for(request):
    """Own organization only. Employees additionally see only their own reports."""
    queryset = Incident.objects.for_organization(request.organization)
    if request.membership.role == Role.EMPLOYEE:
        queryset = queryset.filter(reporter=request.user)
    return queryset


class IncidentQuerysetMixin(OrganizationScopedMixin):
    def get_queryset(self):
        queryset = super().get_queryset().select_related("reporter", "assignee")
        if self.request.membership.role == Role.EMPLOYEE:
            queryset = queryset.filter(reporter=self.request.user)
        return queryset


class IncidentCreateView(OrganizationRequiredMixin, FormView):
    template_name = "incidents/incident_form.html"
    form_class = ReportIncidentForm

    def get_initial(self):
        return {"occurred_at": timezone.localtime(timezone.now())}

    def form_valid(self, form):
        incident = create_incident(
            organization=self.request.organization,
            reporter=self.request.user,
            **form.cleaned_data,
        )
        messages.success(self.request, f"{incident.reference} reported. Thank you.")
        return redirect(incident)


class MyIncidentsView(IncidentQuerysetMixin, ListView):
    model = Incident
    template_name = "incidents/incident_list.html"
    paginate_by = 25

    def get_queryset(self):
        return super().get_queryset().filter(reporter=self.request.user)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context.update(page_title="My incidents", show_filters=False, show_reporter=False)
        return context


class IncidentListView(RoleRequiredMixin, IncidentQuerysetMixin, ListView):
    model = Incident
    template_name = "incidents/incident_list.html"
    allowed_roles = STAFF_ROLES
    paginate_by = 25

    def get_queryset(self):
        queryset = super().get_queryset()
        params = self.request.GET
        search = params.get("q", "").strip()
        if search:
            queryset = queryset.filter(title__icontains=search)
        if params.get("type") in IncidentType.values:
            queryset = queryset.filter(incident_type=params["type"])
        if params.get("severity") in Severity.values:
            queryset = queryset.filter(severity=params["severity"])
        if params.get("status") in IncidentStatus.values:
            queryset = queryset.filter(status=params["status"])
        return queryset

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        params = self.request.GET.copy()
        params.pop("page", None)
        context.update(
            page_title="Incidents",
            show_filters=True,
            show_reporter=True,
            types=IncidentType.choices,
            severities=Severity.choices,
            statuses=IncidentStatus.choices,
            querystring=params.urlencode(),
            q=self.request.GET.get("q", ""),
            selected_type=self.request.GET.get("type", ""),
            selected_severity=self.request.GET.get("severity", ""),
            selected_status=self.request.GET.get("status", ""),
        )
        return context


class IncidentDetailView(IncidentQuerysetMixin, DetailView):
    model = Incident
    template_name = "incidents/incident_detail.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        role = self.request.membership.role
        incident = self.object
        comments = incident.comments.select_related("author")
        if role == Role.EMPLOYEE:
            comments = comments.filter(is_internal=False)
        context.update(
            can_triage=role in TRIAGE_ROLES,
            can_mark_internal=role != Role.EMPLOYEE,
            comments=comments,
            transitions=available_transitions(incident, role),
            comment_form=CommentForm(),
        )
        return context


class TriageView(RoleRequiredMixin, FormView):
    template_name = "incidents/triage_form.html"
    form_class = TriageForm
    allowed_roles = TRIAGE_ROLES

    def get_incident(self):
        if not hasattr(self, "_incident"):
            queryset = Incident.objects.for_organization(self.request.organization)
            self._incident = get_object_or_404(
                queryset.select_related("assignee"), pk=self.kwargs["pk"]
            )
        return self._incident

    def get_initial(self):
        incident = self.get_incident()
        return {
            "incident_type": incident.incident_type,
            "category": incident.category,
            "severity": incident.severity,
            "assignee": incident.assignee_id,
        }

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["organization"] = self.request.organization
        return kwargs

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["incident"] = self.get_incident()
        return context

    def form_valid(self, form):
        try:
            incident = triage_incident(
                incident=self.get_incident(), actor=self.request.user, **form.cleaned_data
            )
        except WorkflowError as error:
            messages.error(self.request, str(error))
            return redirect(self.get_incident())
        messages.success(self.request, f"{incident.reference} updated.")
        return redirect(incident)


class TransitionView(RoleRequiredMixin, View):
    """Status changes, POST only. Who may do what is decided in transition_incident()."""

    allowed_roles = TRIAGE_ROLES

    def post(self, request, pk):
        incident = get_object_or_404(incidents_for(request), pk=pk)
        try:
            transition_incident(
                incident=incident,
                actor=request.user,
                to_status=request.POST.get("to_status", ""),
                note=request.POST.get("note", ""),
            )
        except WorkflowError as error:
            messages.error(request, str(error))
        else:
            messages.success(request, f"{incident.reference} updated.")
        return redirect(incident)


class CommentCreateView(OrganizationRequiredMixin, View):
    def post(self, request, pk):
        incident = get_object_or_404(incidents_for(request), pk=pk)
        form = CommentForm(request.POST)
        if form.is_valid():
            try:
                add_comment(
                    incident=incident,
                    author=request.user,
                    body=form.cleaned_data["body"],
                    is_internal=form.cleaned_data["is_internal"],
                )
            except WorkflowError as error:
                messages.error(request, str(error))
            else:
                messages.success(request, "Comment added.")
        else:
            messages.error(request, "Write a comment first.")
        return redirect(f"{incident.get_absolute_url()}#comments")
