import datetime
import os

from .base import *  # pylint: disable=wildcard-import,unused-wildcard-import,wrong-import-position # noqa: E402,F403


# Django settings
# ---------------
SECRET_KEY = "foobar"

DEBUG = True

ALLOWED_HOSTS = ["localhost", "127.0.0.1", "192.168.0.1", "0.0.0.0"]

EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
EMAIL_HOST = "localhost"
EMAIL_PORT = 1025

SESSION_COOKIE_SECURE = False

INSTALLED_APPS.extend(  # noqa: F405
    [
        "django_extensions",
        "debug_toolbar",
        "django_admin_logs",
    ]
)

STORAGES = {
    "staticfiles": {
        # `ManifestStaticFilesStorage` (used in base settings) requires `collectstatic` to be run.
        "BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage",
    },
}

NEW_TERMS_DATE = datetime.datetime.fromisoformat("2023-01-01T00:00:00+00:00")

MIDDLEWARE += ["debug_toolbar.middleware.DebugToolbarMiddleware"]  # noqa F405
DEBUG_TOOLBAR_CONFIG = {
    # https://django-debug-toolbar.readthedocs.io/en/latest/panels.html#panels
    "DISABLE_PANELS": [
        "debug_toolbar.panels.redirects.RedirectsPanel",
        # ProfilingPanel makes the django admin extremely slow...
        "debug_toolbar.panels.profiling.ProfilingPanel",
    ],
    "SHOW_TEMPLATE_CONTEXT": True,
}


# ITOU settings
# -------------

DATABASES["default"]["HOST"] = os.getenv("PGHOST", "127.0.0.1")  # noqa: F405
DATABASES["default"]["PORT"] = os.getenv("PGPORT", "5433")  # noqa: F405
DATABASES["default"]["NAME"] = os.getenv("PGDATABASE", "inclusion_connect")  # noqa: F405
DATABASES["default"]["USER"] = os.getenv("PGUSER", "postgres")  # noqa: F405
DATABASES["default"]["PASSWORD"] = os.getenv("PGPASSWORD", "password")  # noqa: F405

try:
    LOGGING["loggers"]["inclusion_connect"]["handlers"].remove("elasticsearch")  # noqa: F405
except ValueError:
    pass

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
