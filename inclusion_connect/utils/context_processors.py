from django.conf import settings


def expose_settings(*args):
    settings_to_expose = {
        key: getattr(settings, key)
        for key in [
            "FAQ_URL",
            "MIGRATION_PAGE_URL",
            "PRIVACY_POLICY_PATH",
            "TERMS_PATH",
            "LEGAL_NOTICES_PATH",
            "PEAMA_STAGING",
            "PEAMA_ENABLED",
        ]
    }

    global_constants_settings_to_expose = {
        "MATOMO_SITE_ID": settings.MATOMO_SITE_ID,
        "MATOMO_BASE_URL": settings.MATOMO_BASE_URL,
    }
    return {**settings_to_expose, **global_constants_settings_to_expose}
