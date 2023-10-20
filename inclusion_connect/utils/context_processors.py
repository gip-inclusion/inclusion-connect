from django.conf import settings


def expose_settings(*args):
    return {
        key: getattr(settings, key)
        for key in [
            "FAQ_URL",
            "PRIVACY_POLICY_PATH",
            "TERMS_PATH",
            "LEGAL_NOTICES_PATH",
            "PEAMA_STAGING",
        ]
    }
