from django import forms
from django.contrib.auth import get_user_model
from django.utils import timezone

from apps.organizations.models import Role

from .models import CATEGORIES_BY_TYPE, Category, IncidentType, Severity

User = get_user_model()


class ReportIncidentForm(forms.Form):
    incident_type = forms.ChoiceField(
        label="What happened?",
        choices=IncidentType.choices,
        help_text="Security incident: phishing, malware, lost device. IT failure: outage, broken hardware.",
    )
    title = forms.CharField(max_length=200)
    description = forms.CharField(
        widget=forms.Textarea(attrs={"rows": 5}),
        help_text="What did you see? Which device or system? Who else is affected?",
    )
    occurred_at = forms.DateTimeField(
        label="When did it happen?",
        widget=forms.DateTimeInput(attrs={"type": "datetime-local"}, format="%Y-%m-%dT%H:%M"),
        input_formats=["%Y-%m-%dT%H:%M", "%Y-%m-%d %H:%M"],
    )

    def clean_occurred_at(self):
        value = self.cleaned_data["occurred_at"]
        if value > timezone.now():
            raise forms.ValidationError("The time cannot be in the future.")
        return value


class TriageForm(forms.Form):
    incident_type = forms.ChoiceField(choices=IncidentType.choices)
    category = forms.ChoiceField(choices=[("", "Select a category")] + list(Category.choices))
    severity = forms.ChoiceField(choices=[("", "Select a severity")] + list(Severity.choices))
    assignee = forms.ModelChoiceField(
        queryset=User.objects.none(), required=False, empty_label="Unassigned"
    )

    def __init__(self, *args, organization, **kwargs):
        super().__init__(*args, **kwargs)
        # Only security managers and analysts of this organization can be assigned.
        self.fields["assignee"].queryset = User.objects.filter(
            memberships__organization=organization,
            memberships__role__in=[Role.SECURITY_MANAGER, Role.SECURITY_ANALYST],
        ).distinct().order_by("full_name")

    def clean(self):
        cleaned = super().clean()
        incident_type = cleaned.get("incident_type")
        category = cleaned.get("category")
        if incident_type and category and category not in CATEGORIES_BY_TYPE[incident_type]:
            self.add_error("category", "This category does not match the incident type.")
        return cleaned
class CommentForm(forms.Form):
    body = forms.CharField(
        label="",
        widget=forms.Textarea(
            attrs={"rows": 3, "class": "form-control", "placeholder": "Add a comment"}
        ),
    )
    is_internal = forms.BooleanField(
        required=False,
        label="Internal note (hidden from the reporter)",
        widget=forms.CheckboxInput(attrs={"class": "form-check-input"}),
    )
