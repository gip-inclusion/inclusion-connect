from django.conf import settings

from inclusion_connect.oidc_federation.enums import Federation

from . import base


CONFIG = {
    "OIDC_RP_CLIENT_ID": settings.PEAMA_CLIENT_ID,
    "OIDC_RP_CLIENT_SECRET": settings.PEAMA_CLIENT_SECRET,
    "OIDC_OP_AUTHORIZATION_ENDPOINT": settings.PEAMA_AUTH_ENDPOINT,
    "OIDC_OP_TOKEN_ENDPOINT": settings.PEAMA_TOKEN_ENDPOINT,
    "OIDC_OP_USER_ENDPOINT": settings.PEAMA_USER_ENDPOINT,
    "OIDC_AUTHENTICATION_CALLBACK_URL": "oidc_federation:peama:callback",
    "OIDC_RP_SCOPES": settings.PEAMA_SCOPES,
    "OIDC_RP_SIGN_ALGO": "RS256" if settings.PEAMA_ENABLED else "",  # Don't crash if not configured
    "OIDC_OP_JWKS_ENDPOINT": settings.PEAMA_JWKS_ENDPOINT,
}


class OIDCAuthenticationCallbackView(base.OIDCAuthenticationCallbackView):
    config = CONFIG


class OIDCAuthenticationRequestView(base.OIDCAuthenticationRequestView):
    config = CONFIG


class OIDCAuthenticationBackend(base.OIDCAuthenticationBackend):
    config = CONFIG
    name = Federation.PEAMA
    additionnal_claims = ["structure_pe", "site_pe"]

    def get_userinfo(self, access_token, id_token, payload):
        user_info = super().get_userinfo(access_token, id_token, payload)
        return user_info | {
            "structure_pe": payload["structureTravail"],
            "site_pe": payload["siteTravail"],
        }
