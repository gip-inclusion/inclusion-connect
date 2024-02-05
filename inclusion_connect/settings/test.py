import os

from .base import *  # pylint: disable=wildcard-import,unused-wildcard-import,wrong-import-position # noqa: E402,F403
from .base import OAUTH2_PROVIDER  # Avoid flake8 error


SECRET_KEY = b"VERY_SECRET_KEY_FOR_TESTS"

DATABASES["default"]["HOST"] = os.getenv("PGHOST", "127.0.0.1")  # noqa: F405
DATABASES["default"]["PORT"] = os.getenv("PGPORT", "5433")  # noqa: F405
DATABASES["default"]["NAME"] = os.getenv("PGDATABASE", "inclusion_connect")  # noqa: F405
DATABASES["default"]["USER"] = os.getenv("PGUSER", "postgres")  # noqa: F405
DATABASES["default"]["PASSWORD"] = os.getenv("PGPASSWORD", "password")  # noqa: F405

try:
    LOGGING["loggers"]["inclusion_connect"]["handlers"].remove("elasticsearch")  # noqa: F405
except ValueError:
    pass

STORAGES = {
    "staticfiles": {
        # `ManifestStaticFilesStorage` (used in base settings) requires `collectstatic` to be run.
        "BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage",
    },
}

# PEAMA Federation
# ----------------

PEAMA_CLIENT_ID = "PEAMA_CLIENT_ID"
PEAMA_ENABLED = True
PEAMA_CLIENT_SECRET = "PEAMA_CLIENT_SECRET"
PEAMA_AUTH_ENDPOINT = "https://peama/auth"
PEAMA_TOKEN_ENDPOINT = "https://peama/token?realm=/agent"
PEAMA_USER_ENDPOINT = "https://peama/user?realm=/agent"
PEAMA_SCOPES = "openid email profile siteAgent"
PEAMA_JWKS_ENDPOINT = "https://peama/jwks"
PEAMA_LOGOUT_ENDPOINT = "https://peama/logout?realm=/agent"

# OIDC Config
# -----------
OAUTH2_PROVIDER["OIDC_ISS_ENDPOINT"] = "http://testserver/auth"
