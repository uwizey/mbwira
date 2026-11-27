import hashlib
import os
import re

from django.conf import settings


class EvidenceRejected(Exception):
    """A user-facing reason why a file cannot be accepted."""


# Served content types are fixed here. The browser's claim is never trusted.
ALLOWED_TYPES = {
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".pdf": "application/pdf",
    ".txt": "text/plain",
    ".log": "text/plain",
    ".csv": "text/plain",
    ".eml": "text/plain",
}
ALLOWED_LABEL = "PNG, JPG, GIF, PDF, TXT, LOG, CSV, EML"
INLINE_TYPES = {"image/png", "image/jpeg", "image/gif"}
TEXT_EXTENSIONS = {".txt", ".log", ".csv", ".eml"}
SIGNATURES = {
    ".png": (b"\x89PNG\r\n\x1a\n",),
    ".jpg": (b"\xff\xd8\xff",),
    ".jpeg": (b"\xff\xd8\xff",),
    ".gif": (b"GIF87a", b"GIF89a"),
    ".pdf": (b"%PDF-",),
}


def clean_filename(name):
    """Keep only the base name, drop control characters, cap the length."""
    name = os.path.basename((name or "").replace("\\", "/"))
    name = re.sub(r"[\x00-\x1f\x7f]", "", name).strip()
    stem, ext = os.path.splitext(name)
    return stem[: 150 - len(ext)] + ext


def inspect_upload(uploaded_file):
    """Validate an uploaded file and return its safe details.

    Raises EvidenceRejected with a readable reason when it is not acceptable.
    """
    if uploaded_file is None:
        raise EvidenceRejected("Choose a file to upload.")

    name = clean_filename(uploaded_file.name)
    ext = os.path.splitext(name)[1].lower()
    if ext not in ALLOWED_TYPES:
        raise EvidenceRejected(f"This file type is not allowed. Allowed types: {ALLOWED_LABEL}.")

    size = uploaded_file.size
    if not size:
        raise EvidenceRejected("The file is empty.")
    limit = settings.EVIDENCE_MAX_BYTES
    if size > limit:
        raise EvidenceRejected(f"The file is too large. The limit is {limit // (1024 * 1024)} MB.")

    digest = hashlib.sha256()
    head = b""
    for chunk in uploaded_file.chunks():
        if len(head) < 16:
            head = (head + chunk)[:16]
        if ext in TEXT_EXTENSIONS and b"\x00" in chunk:
            raise EvidenceRejected("This file does not look like a text file.")
        digest.update(chunk)
    uploaded_file.seek(0)

    signatures = SIGNATURES.get(ext)
    if signatures and not head.startswith(signatures):
        raise EvidenceRejected("The file content does not match its extension.")

    return {
        "name": name,
        "content_type": ALLOWED_TYPES[ext],
        "size": size,
        "sha256": digest.hexdigest(),
    }
