from django import forms
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password

from .models import Role

User = get_user_model()


def _check_passwords(form, cleaned):
    password1 = cleaned.get("password1")
    password2 = cleaned.get("password2")
    if password1 and password2:
        if password1 != password2:
            form.add_error("password2", "The two passwords do not match.")
        else:
            try:
                validate_password(password1)
            except forms.ValidationError as error:
                form.add_error("password1", error)


class OrganizationSignupForm(forms.Form):
    organization_name = forms.CharField(max_length=200)
    full_name = forms.CharField(max_length=150)
    email = forms.EmailField()
    password1 = forms.CharField(label="Password", widget=forms.PasswordInput)
    password2 = forms.CharField(label="Confirm password", widget=forms.PasswordInput)

    def clean_email(self):
        email = self.cleaned_data["email"].lower()
        if User.objects.filter(email__iexact=email).exists():
            raise forms.ValidationError("An account with this email already exists.")
        return email

    def clean(self):
        cleaned = super().clean()
        _check_passwords(self, cleaned)
        return cleaned


class InvitationForm(forms.Form):
    email = forms.EmailField()
    role = forms.ChoiceField(choices=Role.choices, initial=Role.EMPLOYEE)


class AcceptInvitationForm(forms.Form):
    full_name = forms.CharField(max_length=150)
    password1 = forms.CharField(label="Password", widget=forms.PasswordInput)
    password2 = forms.CharField(label="Confirm password", widget=forms.PasswordInput)

    def clean(self):
        cleaned = super().clean()
        _check_passwords(self, cleaned)
        return cleaned
