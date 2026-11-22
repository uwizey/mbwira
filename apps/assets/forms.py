from django import forms
from django.contrib.auth import get_user_model

from .models import Asset

User = get_user_model()


class AssetForm(forms.ModelForm):
    class Meta:
        model = Asset
        fields = ["name", "asset_type", "hostname", "ip_address", "location", "status", "owner"]

    def __init__(self, *args, organization, **kwargs):
        super().__init__(*args, **kwargs)
        # The owner must be a member of the same organization.
        self.fields["owner"].queryset = User.objects.filter(
            memberships__organization=organization
        ).order_by("full_name")
        self.fields["owner"].required = False
        self.fields["owner"].empty_label = "Unassigned"
