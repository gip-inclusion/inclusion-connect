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
from urllib.parse import urlparse, urlunparse

import dj_database_url
from django.core.serializers.json import DjangoJSONEncoder
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
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "django.forms",
]

THIRD_PARTY_APPS = [
    "django_bootstrap5",
    "corsheaders",
    "mozilla_django_oidc",
    "oauth2_provider",
]

LOCAL_APPS = [
    "inclusion_connect.admin.apps.AdminConfig",
    "inclusion_connect.keycloak_compat",
    "inclusion_connect.oidc_overrides",
    "inclusion_connect.stats",
    "inclusion_connect.users",
    "inclusion_connect.utils",
]

INSTALLED_APPS = DJANGO_APPS + THIRD_PARTY_APPS + LOCAL_APPS

MIDDLEWARE = [
    "csp.middleware.CSPMiddleware",
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.gzip.GZipMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "inclusion_connect.middleware.never_cache",
    "inclusion_connect.middleware.limit_staff_users_to_admin",
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
                # Inclusion connect
                "inclusion_connect.utils.context_processors.expose_settings",
            ],
        },
    },
]

# Override default Django forms widgets templates.
# Requires django.forms in INSTALLED_APPS
# https://timonweb.com/django/overriding-field-widgets-in-django-doesnt-work-template-not-found-the-solution/
FORM_RENDERER = "django.forms.renderers.TemplatesSetting"

WSGI_APPLICATION = "inclusion_connect.wsgi.application"

RUN_SERVER_PORT = 8080


# Database
# https://docs.djangoproject.com/en/4.1/ref/settings/#databases

DATABASES = {
    "default": dj_database_url.config(env="POSTGRESQL_ADDON_URI", ssl_require=True)
    | {
        "ENGINE": "django.db.backends.postgresql",
        "ATOMIC_REQUESTS": True,
        # Since we have the health checks enabled, no need to define a max age:
        # if the connection was closed on the database side, the check will detect it
        "CONN_MAX_AGE": None,
        "CONN_HEALTH_CHECKS": True,
        "OPTIONS": {
            "connect_timeout": 5,
        },
    },
}


# Password validation
# https://docs.djangoproject.com/en/4.1/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
        "OPTIONS": {"min_length": 12},
    },
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

STORAGES = {
    "staticfiles": {
        "BACKEND": "django.contrib.staticfiles.storage.ManifestStaticFilesStorage",
    },
}

STATICFILES_FINDERS = (
    "django.contrib.staticfiles.finders.FileSystemFinder",
    "django.contrib.staticfiles.finders.AppDirectoriesFinder",
)

STATICFILES_DIRS = (os.path.join(BASE_DIR, "static"),)

# Session
CSRF_USE_SESSIONS = True
CSRF_FAILURE_VIEW = "inclusion_connect.views.csrf_failure"

SECURE_CONTENT_TYPE_NOSNIFF = True

SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True

SESSION_COOKIE_HTTPONLY = True

SESSION_COOKIE_SECURE = True

# Don't interfer with other local django apps
SESSION_COOKIE_NAME = "INCLUSION_CONNECT"

# Force browser to end session when closing.
SESSION_EXPIRE_AT_BROWSER_CLOSE = True

# Set django session ligespan to 30 minute by default
SESSION_COOKIE_AGE = int(60 * 60 * float(os.getenv("SESSION_DURATION", "0.5")))

SESSION_COOKIE_SAMESITE = "None"

X_FRAME_OPTIONS = "DENY"

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "handlers": {
        "console": {"class": "logging.StreamHandler"},
        "null": {"class": "logging.NullHandler"},
        "json_handler": {
            "class": "logging.StreamHandler",
            "formatter": "json_formatter",
        },
    },
    "formatters": {
        "json_formatter": {
            "()": "inclusion_connect.logging.JsonFormatter",
            "json_encoder": DjangoJSONEncoder,
            "timestamp": "@timestamp",
        }
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
            "handlers": ["json_handler"],
            "level": os.getenv("IC_LOG_LEVEL", "INFO"),
        },
    },
}
# In the form https://user:password@hostname-elasticsearch.clever-cloud.com/
if elasticsearch_url := os.getenv("ES_ADDON_URI"):
    # The Elasticsearch client expects the port to be specified,
    # and does not offer an option to infer it from the scheme.
    parsed = urlparse(elasticsearch_url)
    if parsed.port is None and parsed.scheme == "https":
        parsed = parsed._replace(netloc=f"{parsed.netloc}:443")
    elasticsearch_url = urlunparse(parsed)

    environment_name = os.environ["IC_ENVIRONMENT"].lower()
    index_name = f"inclusion-connect-{environment_name}"
    LOGGING["handlers"]["elasticsearch"] = {
        "class": "inclusion_connect.logging.ElasticSearchHandler",
        "formatter": "json_formatter",
        # Align buffer capacity on the default chunk_size for ElasticSearch.bulk.
        "capacity": 500,
        "host": elasticsearch_url,
        "index_name": index_name,
    }
    LOGGING["loggers"]["inclusion_connect"]["handlers"].append("elasticsearch")

AUTH_USER_MODEL = "users.User"

AUTHENTICATION_BACKENDS = (
    "inclusion_connect.auth.backends.EmailAuthenticationBackend",
    "inclusion_connect.oidc_federation.peama.OIDCAuthenticationBackend",
)

DEFAULT_AUTH_BACKEND = AUTHENTICATION_BACKENDS[0]


PASSWORD_RESET_TIMEOUT = 24 * 60 * 60  # 1 day in seconds

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

LOGIN_URL = "/accounts/login/"

BOOTSTRAP5 = {
    "required_css_class": "form-group-required",
}

SECURE_CONTENT_TYPE_NOSNIFF = True

# Inclusion Connect settings
# --------------------------

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
PASSWORD_RESET_TIMEOUT = EMAIL_LINKS_VALIDITY_DAYS * 60 * 60 * 24

FAQ_URL = "https://plateforme-inclusion.notion.site/Questions-fr-quentes-74a872c96637484f8a7dbfa6b44eeb08"
PRIVACY_POLICY_PATH = "terms/Politique_de_confidentialite_v7.pdf"
TERMS_PATH = "terms/CGU_v5.pdf"
LEGAL_NOTICES_PATH = "terms/Mentions légales_20230302.pdf"

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
    "OIDC_ISS_ENDPOINT": os.getenv("OIDC_ISS_ENDPOINT"),
    "OIDC_RSA_PRIVATE_KEY": oidc_rsa_private_key,
    "SCOPES": {
        "openid": "OpenID Connect scope",
        "profile": "Profil utilisateur",
        "email": "Email de l'utilisateur",
    },
    "PKCE_REQUIRED": False,
    "OAUTH2_VALIDATOR_CLASS": "inclusion_connect.oidc_overrides.validators.CustomOAuth2Validator",
    "ACCESS_TOKEN_EXPIRE_SECONDS": SESSION_COOKIE_AGE,
    "REFRESH_TOKEN_EXPIRE_SECONDS": SESSION_COOKIE_AGE,
    "OIDC_RP_INITIATED_LOGOUT_ENABLED": True,
    "OIDC_RP_INITIATED_LOGOUT_ALWAYS_PROMPT": False,
}

OAUTH2_PROVIDER_APPLICATION_MODEL = "oidc_overrides.Application"

ALLOW_ALL_REDIRECT_URIS = os.getenv("ALLOW_ALL_REDIRECT_URIS") == "True"

# Keycloak Compatibility
# ----------------------

PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.PBKDF2PasswordHasher",
    "inclusion_connect.keycloak_compat.hashers.KeycloakPasswordHasher",
]


# MATOMO
# ------

MATOMO_BASE_URL = os.getenv("MATOMO_BASE_URL")
MATOMO_SITE_ID = os.getenv("MATOMO_SITE_ID")

# Content Security Policy
# -----------------------

# Beware, some browser extensions may prevent the reports to be sent to sentry with CORS errors.
CSP_BASE_URI = ["'none'"]  # We don't use any <base> element in our code, so let's forbid it
CSP_DEFAULT_SRC = ["'self'"]
CSP_IMG_SRC = [
    "'self'",
    "data:",  # Because of bootstrap
]
CSP_STYLE_SRC = [
    "'self'",
]
CSP_FONT_SRC = ["'self'"]
CSP_SCRIPT_SRC = [
    "'self'",
    # https://docs.sentry.io/platforms/javascript/install/loader/#content-security-policy
    "https://browser.sentry-cdn.com",
    "https://js-de.sentry-cdn.com",
]
CSP_CONNECT_SRC = ["'self'", "*.sentry.io"]
CSP_OBJECT_SRC = ["'none'"]
CSP_INCLUDE_NONCE_IN = ["script-src"]
CSP_REPORT_URI = os.getenv("CSP_REPORT_URI", None)
CSP_FRAME_ANCESTORS = os.getenv("CSP_FRAME_ANCESTORS", "").split(",")

# CORS
if MATOMO_BASE_URL:
    CSP_IMG_SRC.append(MATOMO_BASE_URL)
    CSP_SCRIPT_SRC.append(MATOMO_BASE_URL)
    CSP_CONNECT_SRC.append(MATOMO_BASE_URL)
# ----

CORS_ALLOW_ALL_ORIGINS = os.getenv("CORS_ALLOW_ALL_ORIGINS") == "True"

cors_allowed_origins = os.getenv("CORS_ALLOWED_ORIGINS")
if cors_allowed_origins and not CORS_ALLOW_ALL_ORIGINS:
    CORS_ALLOWED_ORIGINS = cors_allowed_origins.split(",")


# OIDC Federation
# ---------------

PEAMA_CLIENT_ID = os.getenv("PEAMA_CLIENT_ID")
PEAMA_ENABLED = os.getenv("PEAMA_ENABLED") == "True"
PEAMA_STAGING = os.getenv("PEAMA_STAGING") == "True"
PEAMA_CLIENT_SECRET = os.getenv("PEAMA_CLIENT_SECRET")
PEAMA_AUTH_ENDPOINT = os.getenv("PEAMA_AUTH_ENDPOINT")
PEAMA_TOKEN_ENDPOINT = os.getenv("PEAMA_TOKEN_ENDPOINT")
PEAMA_USER_ENDPOINT = os.getenv("PEAMA_USER_ENDPOINT")
PEAMA_SCOPES = os.getenv("PEAMA_SCOPES")
PEAMA_JWKS_ENDPOINT = os.getenv("PEAMA_JWKS_ENDPOINT")
PEAMA_LOGOUT_ENDPOINT = os.getenv("PEAMA_LOGOUT_ENDPOINT")

# ProConect mirgation
# -------------------

FREEZE_ACCOUNTS = os.getenv("FREEZE_ACCOUNTS")
MIGRATION_PAGE_URL = "https://gip-inclusion.notion.site/5cfeffaf5d634a1a8275cdcf757be2f8"
