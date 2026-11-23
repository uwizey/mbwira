from django.contrib import messages
from django.shortcuts import get_object_or_404, redirect
from django.utils import timezone
from django.views.generic import DetailView, FormView, ListView

from apps.core.mixins import OrganizationRequiredMixin, OrganizationScopedMixin, RoleRequiredMixin
from apps.organizations.models import Role

from .forms import ReportIncidentForm, TriageForm
from .models import Incident, IncidentStatus, IncidentType, Severity
from .services import create_incident, triage_incident

STAFF_ROLES = (Role.ORG_ADMIN, Role.SECURITY_MANAGER, Role.SECURITY_ANALYST)
TRIAGE_ROLES = (Role.SECURITY_MANAGER, Role.SECURITY_ANALYST)


class IncidentQuerysetMixin(OrganizationScopedMixin):
    """Own organization only. Employees additionally see only their own reports."""

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
        context["can_triage"] = self.request.membership.role in TRIAGE_ROLES
        return context


class TriageView(RoleRequiredMixin, FormView):
    template_name = "incidents/triage_form.html"
    form_class = TriageForm
    allowed_roles = TRIAGE_ROLES

    def get_incident(self):
        if not hasattr(self, "_incident"):
            queryset = Incident.objects.for_organization(self.request.organization)
            self._incident = get_object_or_404(queryset.select_related("assignee"), pk=self.kwargs["pk"])
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
        incident = triage_incident(
            incident=self.get_incident(), actor=self.request.user, **form.cleaned_data
        )
        messages.success(self.request, f"{incident.reference} updated.")
        return redirect(incident)
