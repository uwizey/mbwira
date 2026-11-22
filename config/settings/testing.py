from .development import *  # noqa: F401,F403

# Fast, insecure hasher. Tests only. Never use this outside tests.
PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]
