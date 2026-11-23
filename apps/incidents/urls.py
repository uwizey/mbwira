from django.urls import path

from .views import (
    IncidentCreateView,
    IncidentDetailView,
    IncidentListView,
    MyIncidentsView,
    TriageView,
)

app_name = "incidents"

urlpatterns = [
    path("", IncidentListView.as_view(), name="list"),
    path("mine/", MyIncidentsView.as_view(), name="mine"),
    path("new/", IncidentCreateView.as_view(), name="create"),
    path("<int:pk>/", IncidentDetailView.as_view(), name="detail"),
    path("<int:pk>/triage/", TriageView.as_view(), name="triage"),
]
