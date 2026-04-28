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


# OIDC Config
# -----------
OAUTH2_PROVIDER["OIDC_ISS_ENDPOINT"] = "http://testserver/auth"
