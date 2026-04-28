from django.conf import settings


def expose_settings(*args):
    settings_to_expose = {
        key: getattr(settings, key)
        for key in [
            "FAQ_URL",
            "PRIVACY_POLICY_PATH",
            "TERMS_PATH",
            "LEGAL_NOTICES_PATH",
        ]
    }

    return {**settings_to_expose}
