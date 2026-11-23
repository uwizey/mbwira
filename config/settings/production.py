from .base import *  # noqa: F401,F403

DEBUG = False

# Render sets RENDER_EXTERNAL_HOSTNAME automatically for web services.
RENDER_HOST = env("RENDER_EXTERNAL_HOSTNAME", default="")  # noqa: F405
if RENDER_HOST:
    ALLOWED_HOSTS = [*ALLOWED_HOSTS, RENDER_HOST]  # noqa: F405
    CSRF_TRUSTED_ORIGINS = [f"https://{RENDER_HOST}"]

SECURE_SSL_REDIRECT = True
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SECURE_HSTS_SECONDS = 3600
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_CONTENT_TYPE_NOSNIFF = True

# Real SMTP is set up in Phase 5. Until then, set EMAIL_BACKEND on the host to the
# console backend so invitation emails appear in the logs instead of crashing.
EMAIL_BACKEND = env(  # noqa: F405
    "EMAIL_BACKEND", default="django.core.mail.backends.smtp.EmailBackend"
)
EMAIL_HOST = env("EMAIL_HOST", default="")  # noqa: F405
EMAIL_PORT = env.int("EMAIL_PORT", default=587)  # noqa: F405
EMAIL_HOST_USER = env("EMAIL_HOST_USER", default="")  # noqa: F405
EMAIL_HOST_PASSWORD = env("EMAIL_HOST_PASSWORD", default="")  # noqa: F405
EMAIL_USE_TLS = True

STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "staticfiles": {"BACKEND": "whitenoise.storage.CompressedManifestStaticFilesStorage"},
}
