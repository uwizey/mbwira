from django.contrib.auth import get_user_model
from django.db import IntegrityError, transaction
from django.test import TestCase
from django.urls import reverse

User = get_user_model()
PASSWORD = "Str0ng-pass-123"


class UserModelTests(TestCase):
    def test_create_user_normalizes_email(self):
        user = User.objects.create_user(
            email="Jane@Example.COM", password=PASSWORD, full_name="Jane"
        )
        self.assertEqual(user.email, "jane@example.com")
        self.assertTrue(user.check_password(PASSWORD))
        self.assertFalse(user.is_staff)

    def test_email_is_required(self):
        with self.assertRaises(ValueError):
            User.objects.create_user(email="", password=PASSWORD, full_name="X")

    def test_email_must_be_unique(self):
        User.objects.create_user(email="a@example.com", password=PASSWORD, full_name="A")
        with self.assertRaises(IntegrityError), transaction.atomic():
            User.objects.create_user(email="a@example.com", password=PASSWORD, full_name="B")

    def test_create_superuser_flags(self):
        admin = User.objects.create_superuser(
            email="root@example.com", password=PASSWORD, full_name="Root"
        )
        self.assertTrue(admin.is_staff)
        self.assertTrue(admin.is_superuser)


class AuthViewTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            email="jane@example.com", password=PASSWORD, full_name="Jane"
        )

    def test_home_requires_login(self):
        response = self.client.get(reverse("home"))
        self.assertRedirects(response, "/accounts/login/?next=/")

    def test_login_with_email_works(self):
        response = self.client.post(
            reverse("accounts:login"),
            {"username": "jane@example.com", "password": PASSWORD},
        )
        self.assertRedirects(response, reverse("home"))

    def test_login_with_wrong_password_fails(self):
        response = self.client.post(
            reverse("accounts:login"),
            {"username": "jane@example.com", "password": "wrong"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("_auth_user_id", self.client.session)

    def test_logout_requires_post_and_signs_out(self):
        self.client.force_login(self.user)
        self.assertEqual(self.client.get(reverse("accounts:logout")).status_code, 405)
        self.client.post(reverse("accounts:logout"))
        self.assertNotIn("_auth_user_id", self.client.session)

    def test_password_change_requires_login(self):
        response = self.client.get(reverse("accounts:password_change"))
        self.assertEqual(response.status_code, 302)