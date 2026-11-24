from django.urls import path

from .views import (
    CommentCreateView,
    IncidentCreateView,
    IncidentDetailView,
    IncidentListView,
    MyIncidentsView,
    TransitionView,
    TriageView,
)

app_name = "incidents"

urlpatterns = [
    path("", IncidentListView.as_view(), name="list"),
    path("mine/", MyIncidentsView.as_view(), name="mine"),
    path("new/", IncidentCreateView.as_view(), name="create"),
    path("<int:pk>/", IncidentDetailView.as_view(), name="detail"),
    path("<int:pk>/triage/", TriageView.as_view(), name="triage"),
    path("<int:pk>/transition/", TransitionView.as_view(), name="transition"),
    path("<int:pk>/comment/", CommentCreateView.as_view(), name="comment"),
]
