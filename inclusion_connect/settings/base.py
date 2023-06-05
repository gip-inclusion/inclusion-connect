"""
Django settings for inclusion_connect project.

Generated by 'django-admin startproject' using Django 4.1.7.

For more information on this file, see
https://docs.djangoproject.com/en/4.1/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/4.1/ref/settings/
"""

import datetime
import os
from pathlib import Path

from dotenv import load_dotenv


load_dotenv()


# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/4.1/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = os.getenv("DJANGO_SECRET_KEY")

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = False

ALLOWED_HOSTS = os.getenv("ALLOWED_HOSTS", "connect.inclusion.beta.gouv.fr").split(",")
DEFAULT_FROM_EMAIL = os.getenv("DEFAULT_FROM_EMAIL", "Inclusion Connect <contact@inclusion.beta.gouv.fr>")

# Application definition

DJANGO_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
]

THIRD_PARTY_APPS = [
    "bootstrap4",
    "corsheaders",
    "oauth2_provider",
]

LOCAL_APPS = [
    "inclusion_connect.keycloak_compat",
    "inclusion_connect.oidc_overrides",
    "inclusion_connect.users",
    "inclusion_connect.utils",
]

INSTALLED_APPS = DJANGO_APPS + THIRD_PARTY_APPS + LOCAL_APPS

MIDDLEWARE = [
    "csp.middleware.CSPMiddleware",
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "inclusion_connect.middleware.never_cache",
    "inclusion_connect.accounts.middleware.post_login_actions",
]

ROOT_URLCONF = "inclusion_connect.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [os.path.join(BASE_DIR, "templates")],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.template.context_processors.media",
                "django.template.context_processors.static",
                "django.template.context_processors.tz",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                # Django CSP
                "csp.context_processors.nonce",
            ],
        },
    },
]

WSGI_APPLICATION = "inclusion_connect.wsgi.application"

RUN_SERVER_PORT = 8080


# Database
# https://docs.djangoproject.com/en/4.1/ref/settings/#databases

# Note how we use Clever Cloud environment variables here. No way for now to alias them :/
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": os.getenv("POSTGRESQL_ADDON_DB"),
        # FIXME(vperron): We should get rid of those Clever Cloud proprietary values in our code
        # and alias them as soon as we can in our pre-build and pre-run scripts. But those scripts
        # will be defined in a later PR.
        "HOST": os.getenv("POSTGRESQL_ADDON_DIRECT_HOST") or os.getenv("POSTGRESQL_ADDON_HOST"),
        "PORT": os.getenv("POSTGRESQL_ADDON_DIRECT_PORT") or os.getenv("POSTGRESQL_ADDON_PORT"),
        "USER": os.getenv("POSTGRESQL_ADDON_CUSTOM_USER") or os.getenv("POSTGRESQL_ADDON_USER"),
        "PASSWORD": os.getenv("POSTGRESQL_ADDON_CUSTOM_PASSWORD") or os.getenv("POSTGRESQL_ADDON_PASSWORD"),
        "ATOMIC_REQUESTS": True,
        "OPTIONS": {
            "connect_timeout": 5,
        },
    }
}

if os.getenv("DATABASE_PERSISTENT_CONNECTIONS") == "True":
    # Since we have the health checks enabled, no need to define a max age:
    # if the connection was closed on the database side, the check will detect it
    DATABASES["default"]["CONN_MAX_AGE"] = None
    DATABASES["default"]["CONN_HEALTH_CHECKS"] = True


# Password validation
# https://docs.djangoproject.com/en/4.1/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator", "OPTIONS": {"min_length": 12}},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
    {"NAME": "inclusion_connect.utils.password_validation.CnilCompositionPasswordValidator"},
]


# Internationalization
# https://docs.djangoproject.com/en/4.1/topics/i18n/

LANGUAGE_CODE = "fr-FR"

TIME_ZONE = "Europe/Paris"

USE_I18N = True

USE_TZ = True

DATE_INPUT_FORMATS = ["%d/%m/%Y", "%d-%m-%Y", "%d %m %Y"]

STATIC_ROOT = os.path.join(BASE_DIR, "static_collected")

# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/4.1/howto/static-files/

STATIC_URL = "static/"

STATICFILES_STORAGE = "django.contrib.staticfiles.storage.ManifestStaticFilesStorage"

STATICFILES_FINDERS = (
    "django.contrib.staticfiles.finders.FileSystemFinder",
    "django.contrib.staticfiles.finders.AppDirectoriesFinder",
)

STATICFILES_DIRS = (os.path.join(BASE_DIR, "static"),)

# Session
CSRF_USE_SESSIONS = True

SECURE_CONTENT_TYPE_NOSNIFF = True

SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True

SESSION_COOKIE_HTTPONLY = True

SESSION_COOKIE_SECURE = True

# Don't interfer with other local django apps
SESSION_COOKIE_NAME = "INCLUSION_CONNECT"

# Force browser to end session when closing.
SESSION_EXPIRE_AT_BROWSER_CLOSE = True

# Set django session ligespan to 30 minutes
SESSION_COOKIE_AGE = 60 * 30

X_FRAME_OPTIONS = "DENY"

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "handlers": {
        "console": {"class": "logging.StreamHandler"},
        "null": {"class": "logging.NullHandler"},
        "api_console": {
            "class": "logging.StreamHandler",
            "formatter": "api_simple",
        },
    },
    "formatters": {
        "api_simple": {
            "format": "{levelname} {asctime} {pathname} : {message}",
            "style": "{",
        },
    },
    "loggers": {
        "django": {
            "handlers": ["console"],
            "level": os.getenv("DJANGO_LOG_LEVEL", "INFO"),
        },
        # Silence `Invalid HTTP_HOST header` errors.
        # This should be done at the HTTP server level when possible.
        # https://docs.djangoproject.com/en/3.0/topics/logging/#django-security
        "django.security.DisallowedHost": {
            "handlers": ["null"],
            "propagate": False,
        },
        "inclusion_connect": {
            "handlers": ["console"],
            "level": os.getenv("IC_LOG_LEVEL", "INFO"),
        },
        # Logger for DRF API application
        # Will be "log-drained": may need to adjust format
        "api_drf": {
            "handlers": ["api_console"],
            "level": os.getenv("DJANGO_LOG_LEVEL", "INFO"),
        },
        # Huey; async tasks
        "huey": {
            "handlers": ["console"],
            "level": os.getenv("HUEY_LOG_LEVEL", "WARNING"),
        },
    },
}

AUTH_USER_MODEL = "users.User"

AUTHENTICATION_BACKENDS = ("inclusion_connect.auth.backends.EmailAuthenticationBackend",)

PASSWORD_RESET_TIMEOUT = 24 * 60 * 60  # 1 day in seconds

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

LOGIN_URL = "/accounts/login/"

BOOTSTRAP4 = {
    "required_css_class": "form-group-required",
    # Remove the default `.is-valid` class that Bootstrap will style in green
    # otherwise empty required fields will be marked as valid. This might be
    # a bug in django-bootstrap4, it should be investigated.
    "success_css_class": "",
}

# Inclusion Connect settings
# --------------------------

# Environment, sets the type of env of the app (PROD, FAST-MACHINE, DEMO, DEV…)
IC_ENVIRONMENT = os.getenv("IC_ENVIRONMENT", "PROD")

SENTRY_DSN = os.getenv("SENTRY_DSN")
try:
    _sentry_traces_sample_rate = float(os.getenv("SENTRY_TRACES_SAMPLE_RATE", ""))
except ValueError:
    _sentry_traces_sample_rate = 0

if SENTRY_DSN:
    from ._sentry import sentry_init

    sentry_init(dsn=SENTRY_DSN, traces_sample_rate=_sentry_traces_sample_rate)

new_terms_date_str = os.getenv("NEW_TERMS_DATE", "2023-03-02T00:00:00+00:00")
NEW_TERMS_DATE = datetime.datetime.fromisoformat(new_terms_date_str)

# email link validity
EMAIL_LINKS_VALIDITY_DAYS = 1
PASSWORD_RESET_TIMEOUT = EMAIL_LINKS_VALIDITY_DAYS

# Email
# -----

# Email https://anymail.readthedocs.io/en/stable/esps/mailjet/
ANYMAIL = {
    # it's the default but our probes need this at import time.
    "MAILJET_API_URL": "https://api.mailjet.com/v3.1/",
    "MAILJET_API_KEY": os.getenv("API_MAILJET_KEY"),
    "MAILJET_SECRET_KEY": os.getenv("API_MAILJET_SECRET"),
    "WEBHOOK_SECRET": os.getenv("MAILJET_WEBHOOK_SECRET"),
}

EMAIL_BACKEND = "anymail.backends.mailjet.EmailBackend"

# Django-oauth-toolkit
# --------------------

oidc_rsa_private_key = Path("oidc.pem").read_text()

OAUTH2_PROVIDER = {
    "OIDC_ENABLED": True,
    "OIDC_RSA_PRIVATE_KEY": oidc_rsa_private_key,
    "SCOPES": {
        "openid": "OpenID Connect scope",
        "profile": "Profil utilisateur",
        "email": "Email de l'utilisateur",
    },
    "PKCE_REQUIRED": False,
    "OAUTH2_VALIDATOR_CLASS": "inclusion_connect.oidc_overrides.validators.CustomOAuth2Validator",
    "REFRESH_TOKEN_EXPIRE_SECONDS": SESSION_COOKIE_AGE,
    "OIDC_RP_INITIATED_LOGOUT_ENABLED": True,
    "OIDC_RP_INITIATED_LOGOUT_ALWAYS_PROMPT": False,
}

OAUTH2_PROVIDER_APPLICATION_MODEL = "oidc_overrides.Application"

ALLOW_ALL_REDIRECT_URIS = os.getenv("ALLOW_ALL_REDIRECT_URIS") == "True"

# Keycloak Compatibility
# ----------------------

# Allow relms from every keycloak instance (easier that loading from variables)
KEYCLOAK_REALMS = ["local", "Review_apps", "Demo", "inclusion-connect"]

PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.PBKDF2PasswordHasher",
    "inclusion_connect.keycloak_compat.hashers.KeycloakPasswordHasher",
]

# Content Security Policy
# -----------------------

# Beware, some browser extensions may prevent the reports to be sent to sentry with CORS errors.
CSP_DEFAULT_SRC = ["'self'"]
CSP_FRAME_SRC = []
CSP_IMG_SRC = [
    "'self'",
    "https://www.gstatic.com",  # Used by google translate
    "https://translate.google.com",  # Used by google translate
]
CSP_STYLE_SRC = [
    "'self'",
    # It would be better to whilelist styles hashes but it's to much work for now.
    "'unsafe-inline'",
    "*.googleapis.com",  # Google translate
]
CSP_FONT_SRC = [
    # There are many users that override the font with extensions or with services such as google translates.
    # For accessibility reasons we need to allow the user to chose the used font.
    "*",
]
CSP_SCRIPT_SRC = [
    "'self'",
    "https://translate.googleapis.com",  # Allow google translate
]
CSP_CONNECT_SRC = [
    "'self'",
    "https://translate.googleapis.com",  # Allow google translate
]

CSP_INCLUDE_NONCE_IN = ["script-src"]
CSP_REPORT_URI = os.getenv("CSP_REPORT_URI", None)
