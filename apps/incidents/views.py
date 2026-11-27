from django.conf import settings
from django.contrib import messages
from django.db import transaction
from django.http import FileResponse, Http404
from django.shortcuts import get_object_or_404, redirect
from django.utils import timezone
from django.views import View
from django.views.generic import DetailView, FormView, ListView

from apps.audit.services import log_action
from apps.core.mixins import OrganizationRequiredMixin, OrganizationScopedMixin, RoleRequiredMixin
from apps.organizations.models import Role

from .evidence import INLINE_TYPES
from .forms import CommentForm, ReportIncidentForm, TriageForm
from .models import Incident, IncidentEvidence, IncidentStatus, IncidentType, Severity
from .services import (
    WorkflowError,
    add_comment,
    add_evidence,
    available_transitions,
    can_upload_evidence,
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
        data = dict(form.cleaned_data)
        attachment = data.pop("attachment", None)
        try:
            with transaction.atomic():
                incident = create_incident(
                    organization=self.request.organization,
                    reporter=self.request.user,
                    **data,
                )
                if attachment:
                    add_evidence(
                        incident=incident, uploader=self.request.user, uploaded_file=attachment
                    )
        except WorkflowError as error:
            form.add_error(None, str(error))
            return self.form_invalid(form)
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
        user = self.request.user
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
            evidence=incident.evidence.select_related("uploaded_by"),
            can_upload=can_upload_evidence(incident, user, role),
            max_mb=settings.EVIDENCE_MAX_BYTES // (1024 * 1024),
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


class EvidenceUploadView(OrganizationRequiredMixin, View):
    def post(self, request, pk):
        incident = get_object_or_404(incidents_for(request), pk=pk)
        try:
            evidence = add_evidence(
                incident=incident,
                uploader=request.user,
                uploaded_file=request.FILES.get("file"),
            )
        except WorkflowError as error:
            messages.error(request, str(error))
        else:
            messages.success(request, f"{evidence.original_name} uploaded.")
        return redirect(f"{incident.get_absolute_url()}#evidence")


class EvidenceDownloadView(OrganizationRequiredMixin, View):
    """The only way to read an evidence file. Same visibility rules as the incident,
    so another organization's file (or a colleague's, for an employee) is a 404."""

    def get(self, request, pk):
        evidence = get_object_or_404(
            IncidentEvidence.objects.select_related("incident"),
            pk=pk,
            incident__in=incidents_for(request),
        )
        try:
            handle = evidence.file.open("rb")
        except (FileNotFoundError, ValueError) as error:
            raise Http404("This file is no longer available on the server.") from error

        log_action(
            request.user,
            "evidence.downloaded",
            obj=evidence.incident,
            details={
                "reference": evidence.incident.reference,
                "evidence_id": evidence.pk,
                "filename": evidence.original_name,
            },
        )

        inline = evidence.content_type in INLINE_TYPES and request.GET.get("download") != "1"
        response = FileResponse(
            handle,
            as_attachment=not inline,
            filename=evidence.original_name,
            content_type=evidence.content_type,
        )
        response["X-Content-Type-Options"] = "nosniff"
        response["Content-Security-Policy"] = "default-src 'none'; sandbox"
        response["Cache-Control"] = "private, no-store"
        return response
