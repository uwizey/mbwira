import hashlib
import os
import shutil
import tempfile
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import Client, SimpleTestCase, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from apps.audit.models import AuditLog
from apps.organizations.models import Membership, Organization, Role

from .evidence import EvidenceRejected, clean_filename, inspect_upload
from .models import EvidenceImmutableError, Incident, IncidentEvidence
from .services import add_evidence, create_incident

User = get_user_model()
PASSWORD = "Str0ng-pass-123"

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32
JPG = b"\xff\xd8\xff\xe0" + b"\x00" * 32
GIF = b"GIF89a" + b"\x00" * 32
PDF = b"%PDF-1.4\n%%EOF\n"


def upload(name, content):
    return SimpleUploadedFile(name, content, content_type="application/octet-stream")


def make_member(org, email, role):
    user = User.objects.create_user(email=email, password=PASSWORD, full_name=email)
    Membership.objects.create(user=user, organization=org, role=role)
    return user


def client_for(user):
    client = Client()
    client.force_login(user)
    return client


def make_incident(org, reporter, title):
    return create_incident(
        organization=org,
        reporter=reporter,
        incident_type="security",
        title=title,
        description="Details",
        occurred_at=timezone.now() - timedelta(hours=1),
    )


def report_data(**overrides):
    data = {
        "incident_type": "security",
        "title": "Phishing email",
        "description": "I received a suspicious email.",
        "occurred_at": "2024-01-15T09:30",
    }
    data.update(overrides)
    return data


class InspectUploadTests(SimpleTestCase):
    def test_accepts_each_allowed_type_with_matching_content(self):
        cases = [
            ("shot.png", PNG, "image/png"),
            ("photo.jpg", JPG, "image/jpeg"),
            ("photo.JPEG", JPG, "image/jpeg"),
            ("anim.gif", GIF, "image/gif"),
            ("report.pdf", PDF, "application/pdf"),
            ("notes.txt", b"plain text", "text/plain"),
            ("server.log", b"line one\nline two", "text/plain"),
            ("mail.eml", b"From: a@b.c\n\nHello", "text/plain"),
        ]
        for name, content, expected in cases:
            with self.subTest(name=name):
                info = inspect_upload(upload(name, content))
                self.assertEqual(info["content_type"], expected)

    def test_rejects_disallowed_extensions(self):
        for name in ("virus.exe", "page.html", "image.svg", "script.js", "archive.zip", "noextension"):
            with self.subTest(name=name):
                with self.assertRaises(EvidenceRejected):
                    inspect_upload(upload(name, PNG))

    def test_rejects_content_that_does_not_match_the_extension(self):
        for name in ("fake.png", "fake.jpg", "fake.gif", "fake.pdf"):
            with self.subTest(name=name):
                with self.assertRaises(EvidenceRejected):
                    inspect_upload(upload(name, b"MZ\x90\x00 this is really a program"))

    def test_rejects_binary_data_in_a_text_file(self):
        with self.assertRaises(EvidenceRejected):
            inspect_upload(upload("notes.txt", b"abc\x00def"))

    def test_rejects_empty_files(self):
        with self.assertRaises(EvidenceRejected):
            inspect_upload(upload("empty.txt", b""))

    def test_rejects_files_over_the_size_limit(self):
        with override_settings(EVIDENCE_MAX_BYTES=100):
            with self.assertRaises(EvidenceRejected):
                inspect_upload(upload("big.txt", b"a" * 101))
            inspect_upload(upload("ok.txt", b"a" * 100))

    def test_requires_a_file(self):
        with self.assertRaises(EvidenceRejected):
            inspect_upload(None)

    def test_fingerprint_is_the_sha256_of_the_content(self):
        info = inspect_upload(upload("shot.png", PNG))
        self.assertEqual(info["sha256"], hashlib.sha256(PNG).hexdigest())
        self.assertEqual(info["size"], len(PNG))

    def test_filenames_are_reduced_to_a_safe_base_name(self):
        self.assertEqual(clean_filename("../../etc/passwd.txt"), "passwd.txt")
        self.assertEqual(clean_filename("..\\..\\evil.txt"), "evil.txt")
        self.assertEqual(clean_filename("bad\x00name\n.png"), "badname.png")
        self.assertTrue(clean_filename("a" * 400 + ".png").endswith(".png"))
        self.assertLessEqual(len(clean_filename("a" * 400 + ".png")), 150)


class EvidenceBase(TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="mbwira-test-evidence-")
        override = override_settings(EVIDENCE_ROOT=self.root)
        override.enable()
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)
        self.addCleanup(override.disable)

        self.org_a = Organization.objects.create(name="Alpha")
        self.org_b = Organization.objects.create(name="Beta")
        self.admin = make_member(self.org_a, "admin@a.org", Role.ORG_ADMIN)
        self.manager = make_member(self.org_a, "manager@a.org", Role.SECURITY_MANAGER)
        self.analyst = make_member(self.org_a, "analyst@a.org", Role.SECURITY_ANALYST)
        self.emp1 = make_member(self.org_a, "emp1@a.org", Role.EMPLOYEE)
        self.emp2 = make_member(self.org_a, "emp2@a.org", Role.EMPLOYEE)
        self.analyst_b = make_member(self.org_b, "analyst@b.org", Role.SECURITY_ANALYST)
        self.emp_b = make_member(self.org_b, "emp@b.org", Role.EMPLOYEE)
        self.incident = make_incident(self.org_a, self.emp1, "Alpha one")
        self.other = make_incident(self.org_b, self.emp_b, "Beta secret")

    def upload_url(self, incident=None):
        return reverse("incidents:evidence_upload", args=[(incident or self.incident).pk])

    def attach(self, name="shot.png", content=PNG, uploader=None, incident=None):
        return add_evidence(
            incident=incident or self.incident,
            uploader=uploader or self.analyst,
            uploaded_file=upload(name, content),
        )

    def download_url(self, evidence):
        return reverse("incidents:evidence_download", args=[evidence.pk])


class UploadPermissionTests(EvidenceBase):
    def test_employee_can_upload_to_their_own_incident(self):
        response = client_for(self.emp1).post(self.upload_url(), {"file": upload("shot.png", PNG)})
        self.assertRedirects(
            response, f"{self.incident.get_absolute_url()}#evidence", fetch_redirect_response=False
        )
        evidence = IncidentEvidence.objects.get()
        self.assertEqual(evidence.uploaded_by, self.emp1)
        self.assertEqual(evidence.incident, self.incident)

    def test_employee_cannot_upload_to_a_colleagues_incident(self):
        response = client_for(self.emp2).post(self.upload_url(), {"file": upload("shot.png", PNG)})
        self.assertEqual(response.status_code, 404)
        self.assertEqual(IncidentEvidence.objects.count(), 0)

    def test_manager_and_analyst_can_upload_to_any_incident_in_their_organization(self):
        for user in (self.manager, self.analyst):
            response = client_for(user).post(self.upload_url(), {"file": upload("shot.png", PNG)})
            self.assertEqual(response.status_code, 302)
        self.assertEqual(IncidentEvidence.objects.count(), 2)

    def test_org_admin_cannot_add_evidence_to_someone_elses_incident(self):
        client_for(self.admin).post(self.upload_url(), {"file": upload("shot.png", PNG)})
        self.assertEqual(IncidentEvidence.objects.count(), 0)

    def test_org_admin_can_add_evidence_to_an_incident_they_reported(self):
        own = make_incident(self.org_a, self.admin, "Admin report")
        client_for(self.admin).post(self.upload_url(own), {"file": upload("shot.png", PNG)})
        self.assertEqual(IncidentEvidence.objects.filter(incident=own).count(), 1)

    def test_other_organization_gets_404_and_nothing_is_saved(self):
        response = client_for(self.analyst_b).post(
            self.upload_url(), {"file": upload("shot.png", PNG)}
        )
        self.assertEqual(response.status_code, 404)
        self.assertEqual(IncidentEvidence.objects.count(), 0)

    def test_anonymous_is_redirected_to_login(self):
        response = Client().post(self.upload_url(), {"file": upload("shot.png", PNG)})
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse("accounts:login"), response.url)

    def test_closed_incident_rejects_new_evidence(self):
        Incident.objects.filter(pk=self.incident.pk).update(status="closed", resolution_summary="Done")
        client_for(self.analyst).post(self.upload_url(), {"file": upload("shot.png", PNG)})
        self.assertEqual(IncidentEvidence.objects.count(), 0)

    def test_file_count_limit(self):
        with override_settings(EVIDENCE_MAX_FILES=1):
            client = client_for(self.analyst)
            client.post(self.upload_url(), {"file": upload("one.png", PNG)})
            client.post(self.upload_url(), {"file": upload("two.png", PNG)})
        self.assertEqual(IncidentEvidence.objects.count(), 1)

    def test_bad_file_is_rejected_with_a_message(self):
        response = client_for(self.analyst).post(
            self.upload_url(), {"file": upload("virus.exe", b"MZ")}, follow=True
        )
        self.assertContains(response, "not allowed")
        self.assertEqual(IncidentEvidence.objects.count(), 0)

    def test_posting_without_a_file_shows_a_message(self):
        response = client_for(self.analyst).post(self.upload_url(), {}, follow=True)
        self.assertContains(response, "Choose a file")


class StorageTests(EvidenceBase):
    def test_file_is_stored_privately_under_a_random_name(self):
        evidence = self.attach(name="holiday-photo.png")
        self.assertEqual(evidence.original_name, "holiday-photo.png")
        self.assertNotIn("holiday", evidence.file.name)
        self.assertTrue(evidence.file.name.endswith(".png"))
        self.assertTrue(os.path.exists(evidence.file.path))
        self.assertTrue(os.path.abspath(evidence.file.path).startswith(os.path.abspath(self.root)))

    def test_file_has_no_public_url(self):
        evidence = self.attach()
        with self.assertRaises(ValueError):
            _ = evidence.file.url

    def test_metadata_is_recorded(self):
        evidence = self.attach(name="shot.png", content=PNG)
        self.assertEqual(evidence.size, len(PNG))
        self.assertEqual(evidence.sha256, hashlib.sha256(PNG).hexdigest())
        self.assertEqual(evidence.content_type, "image/png")

    def test_evidence_records_cannot_be_modified(self):
        evidence = self.attach()
        evidence.original_name = "changed.png"
        with self.assertRaises(EvidenceImmutableError):
            evidence.save()

    def test_upload_is_audited_with_the_fingerprint(self):
        evidence = self.attach(uploader=self.analyst)
        entry = AuditLog.objects.get(action="evidence.uploaded", object_id=str(self.incident.pk))
        self.assertEqual(entry.organization, self.org_a)
        self.assertEqual(entry.actor, self.analyst)
        self.assertEqual(entry.details["sha256"], evidence.sha256)
        self.assertEqual(entry.details["filename"], "shot.png")


class DownloadTests(EvidenceBase):
    def setUp(self):
        super().setUp()
        self.evidence = self.attach(name="shot.png", content=PNG)
        self.url = self.download_url(self.evidence)

    def read(self, response):
        return b"".join(response.streaming_content)

    def test_everyone_who_can_open_the_incident_can_download(self):
        for user in (self.admin, self.manager, self.analyst, self.emp1):
            with self.subTest(user=user.email):
                response = client_for(user).get(self.url)
                self.assertEqual(response.status_code, 200)
                self.assertEqual(self.read(response), PNG)

    def test_employee_cannot_download_a_colleagues_file(self):
        self.assertEqual(client_for(self.emp2).get(self.url).status_code, 404)

    def test_other_organization_gets_404(self):
        self.assertEqual(client_for(self.analyst_b).get(self.url).status_code, 404)

    def test_anonymous_is_redirected_to_login(self):
        response = Client().get(self.url)
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse("accounts:login"), response.url)

    def test_images_open_inline_and_can_be_forced_to_download(self):
        response = client_for(self.analyst).get(self.url)
        self.assertEqual(response["Content-Type"], "image/png")
        self.assertTrue(response["Content-Disposition"].startswith("inline"))
        forced = client_for(self.analyst).get(self.url + "?download=1")
        self.assertTrue(forced["Content-Disposition"].startswith("attachment"))

    def test_non_images_are_always_attachments(self):
        pdf = self.attach(name="report.pdf", content=PDF)
        response = client_for(self.analyst).get(self.download_url(pdf))
        self.assertTrue(response["Content-Disposition"].startswith("attachment"))
        self.assertEqual(response["Content-Type"], "application/pdf")

    def test_safety_headers_are_set(self):
        response = client_for(self.analyst).get(self.url)
        self.assertEqual(response["X-Content-Type-Options"], "nosniff")
        self.assertIn("sandbox", response["Content-Security-Policy"])
        self.assertIn("no-store", response["Cache-Control"])

    def test_download_is_audited(self):
        client_for(self.emp1).get(self.url)
        entry = AuditLog.objects.get(action="evidence.downloaded")
        self.assertEqual(entry.actor, self.emp1)
        self.assertEqual(entry.organization, self.org_a)
        self.assertEqual(entry.details["evidence_id"], self.evidence.pk)

    def test_missing_file_on_disk_is_a_404(self):
        os.remove(self.evidence.file.path)
        self.assertEqual(client_for(self.analyst).get(self.url).status_code, 404)

    def test_incident_page_lists_the_file_and_shows_the_upload_form_to_those_who_may(self):
        page_url = self.incident.get_absolute_url()
        analyst_page = client_for(self.analyst).get(page_url)
        self.assertContains(analyst_page, "shot.png")
        self.assertContains(analyst_page, self.upload_url())
        admin_page = client_for(self.admin).get(page_url)
        self.assertContains(admin_page, "shot.png")
        self.assertNotContains(admin_page, self.upload_url())


class ReportWithAttachmentTests(EvidenceBase):
    def test_employee_can_attach_a_screenshot_while_reporting(self):
        data = report_data(attachment=upload("phish.png", PNG))
        response = client_for(self.emp1).post(reverse("incidents:create"), data)
        incident = Incident.objects.get(title="Phishing email")
        self.assertRedirects(response, incident.get_absolute_url())
        evidence = incident.evidence.get()
        self.assertEqual(evidence.original_name, "phish.png")
        self.assertEqual(evidence.uploaded_by, self.emp1)
        actions = set(
            AuditLog.objects.filter(object_id=str(incident.pk)).values_list("action", flat=True)
        )
        self.assertIn("incident.reported", actions)
        self.assertIn("evidence.uploaded", actions)

    def test_a_bad_attachment_stops_the_report_from_being_created(self):
        data = report_data(attachment=upload("virus.exe", b"MZ"))
        response = client_for(self.emp1).post(reverse("incidents:create"), data)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "not allowed")
        self.assertFalse(Incident.objects.filter(title="Phishing email").exists())

    def test_reporting_without_an_attachment_still_works(self):
        response = client_for(self.emp1).post(reverse("incidents:create"), report_data())
        self.assertEqual(response.status_code, 302)
        self.assertEqual(IncidentEvidence.objects.count(), 0)
