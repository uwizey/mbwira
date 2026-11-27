from django.contrib import admin

from .models import Incident, IncidentComment, IncidentEvidence


@admin.register(Incident)
class IncidentAdmin(admin.ModelAdmin):
    list_display = ("reference", "title", "organization", "status", "severity", "reporter", "assignee")
    list_filter = ("organization", "status", "severity", "incident_type")
    search_fields = ("title",)


admin.site.register(IncidentComment)


@admin.register(IncidentEvidence)
class IncidentEvidenceAdmin(admin.ModelAdmin):
    list_display = ("original_name", "incident", "size", "uploaded_by", "created_at")
    readonly_fields = [field.name for field in IncidentEvidence._meta.fields]

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False
