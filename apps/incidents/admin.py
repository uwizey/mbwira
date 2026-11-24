
# Register your models here.
from django.contrib import admin

from .models import Incident, IncidentComment


@admin.register(Incident)
class IncidentAdmin(admin.ModelAdmin):
    list_display = ("reference", "title", "organization", "status", "severity", "reporter", "assignee")
    list_filter = ("organization", "status", "severity", "incident_type")
    search_fields = ("title",)


admin.site.register(IncidentComment)
