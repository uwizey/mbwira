from django.contrib import messages
from django.db.models import Q
from django.http import HttpResponseRedirect
from django.views.generic import CreateView, DetailView, ListView, UpdateView

from apps.audit.services import log_action
from apps.core.mixins import OrganizationScopedMixin, RoleRequiredMixin
from apps.organizations.models import Role

from .forms import AssetForm
from .models import Asset, AssetStatus, AssetType

VIEW_ROLES = (Role.ORG_ADMIN, Role.SECURITY_MANAGER, Role.SECURITY_ANALYST)
WRITE_ROLES = (Role.ORG_ADMIN, Role.SECURITY_ANALYST)


class CanEditMixin:
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["can_edit"] = self.request.membership.role in WRITE_ROLES
        return context


class AssetListView(CanEditMixin, RoleRequiredMixin, OrganizationScopedMixin, ListView):
    model = Asset
    template_name = "assets/asset_list.html"
    allowed_roles = VIEW_ROLES
    paginate_by = 25

    def get_queryset(self):
        queryset = super().get_queryset().select_related("owner")
        params = self.request.GET
        search = params.get("q", "").strip()
        asset_type = params.get("type", "")
        status = params.get("status", "")
        if search:
            queryset = queryset.filter(
                Q(name__icontains=search)
                | Q(hostname__icontains=search)
                | Q(location__icontains=search)
                | Q(ip_address__icontains=search)
            )
        if asset_type in AssetType.values:
            queryset = queryset.filter(asset_type=asset_type)
        if status in AssetStatus.values:
            queryset = queryset.filter(status=status)
        return queryset

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        params = self.request.GET.copy()
        params.pop("page", None)
        context.update(
            types=AssetType.choices,
            statuses=AssetStatus.choices,
            querystring=params.urlencode(),
            q=self.request.GET.get("q", ""),
            selected_type=self.request.GET.get("type", ""),
            selected_status=self.request.GET.get("status", ""),
        )
        return context


class AssetDetailView(CanEditMixin, RoleRequiredMixin, OrganizationScopedMixin, DetailView):
    model = Asset
    template_name = "assets/asset_detail.html"
    allowed_roles = VIEW_ROLES

    def get_queryset(self):
        return super().get_queryset().select_related("owner")


class AssetCreateView(RoleRequiredMixin, CreateView):
    model = Asset
    form_class = AssetForm
    template_name = "assets/asset_form.html"
    allowed_roles = WRITE_ROLES

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["organization"] = self.request.organization
        return kwargs

    def form_valid(self, form):
        asset = form.save(commit=False)
        asset.organization = self.request.organization
        asset.save()
        self.object = asset
        log_action(
            self.request.user,
            "asset.created",
            obj=asset,
            organization=asset.organization,
            details={"name": asset.name, "type": asset.asset_type},
        )
        messages.success(self.request, "Asset registered.")
        return HttpResponseRedirect(self.get_success_url())


class AssetUpdateView(RoleRequiredMixin, OrganizationScopedMixin, UpdateView):
    model = Asset
    form_class = AssetForm
    template_name = "assets/asset_form.html"
    allowed_roles = WRITE_ROLES

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["organization"] = self.request.organization
        return kwargs

    def form_valid(self, form):
        changed = list(form.changed_data)
        asset = form.save()
        self.object = asset
        if changed:
            log_action(
                self.request.user,
                "asset.updated",
                obj=asset,
                organization=asset.organization,
                details={"changed": changed},
            )
        messages.success(self.request, "Asset updated.")
        return HttpResponseRedirect(self.get_success_url())
