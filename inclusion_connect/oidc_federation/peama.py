import logging
from functools import partial

import requests
from django.conf import settings
from django.db import transaction

from inclusion_connect.logging import log_data
from inclusion_connect.oidc_federation.enums import Federation
from inclusion_connect.users.models import EmailAddress
from inclusion_connect.utils.urls import add_url_params

from . import base


logger = logging.getLogger("inclusion_connect.auth.oidc_federation")


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

    def get_extra_params(self, request):
        return {"realm": "/agent"}


class OIDCAuthenticationBackend(base.OIDCAuthenticationBackend):
    config = CONFIG
    name = Federation.PEAMA
    additionnal_claims = ["structure_pe", "site_pe"]

    def filter_users_by_claims(self, claims):
        users = super().filter_users_by_claims(claims)

        if not users and claims["email"].endswith("@francetravail.fr"):
            try:
                # If we find an existing @pole-emploi.fr address, it's the same user who migrated to
                # @francetravail.fr email, return it
                email_address = EmailAddress.objects.select_related("user").get(
                    email__iexact=claims["email"][: -len("francetravail.fr")] + "pole-emploi.fr"
                )

                # Check if this email is not already used by another federation
                self.check_federation(email_address.user, claims["email"])

                return [email_address.user]

            except EmailAddress.DoesNotExist:
                pass

        return users

    def get_userinfo(self, access_token, id_token, payload):
        user_info = super().get_userinfo(access_token, id_token, payload)
        return user_info | {
            "structure_pe": payload["structureTravail"],
            "site_pe": payload["siteTravail"],
        }


def logout(request, user, application):
    url = add_url_params(settings.PEAMA_LOGOUT_ENDPOINT, {"id_token_hint": user.federation_id_token_hint})
    response = requests.get(url)

    log = log_data(request)
    log["user"] = user.pk
    log["federation"] = Federation.PEAMA
    if application:
        log["application"] = application.client_id
    if response.status_code == 204:
        log["event"] = "logout_peama"
    else:
        log["event"] = "logout_peama_error"
        log["error"] = {"status_code": response.status_code, "msg": response.content.decode()}
    log["id_token_hint"] = user.federation_id_token_hint
    transaction.on_commit(partial(logger.info, log))
