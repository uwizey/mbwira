import os

from django.conf import settings
from django.core.files.storage import FileSystemStorage


class EvidenceStorage(FileSystemStorage):
    """Private storage: files live outside the static and media folders
    and have no public URL."""

    @property
    def base_location(self):
        return str(settings.EVIDENCE_ROOT)

    @property
    def location(self):
        return os.path.abspath(self.base_location)

    @property
    def base_url(self):
        return None
