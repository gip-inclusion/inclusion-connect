import logging
from functools import partial

from django.conf import settings
from django.contrib import messages
from django.db import transaction
from django.db.models import Q
from django.http import HttpResponseRedirect
from django.urls import reverse
from django.utils.html import format_html
from mozilla_django_oidc import auth, views

from inclusion_connect.accounts.views import LoginView
from inclusion_connect.logging import log_data
from inclusion_connect.utils.oidc import get_next_url


logger = logging.getLogger("inclusion_connect.auth.oidc_federation")

CONFIG = {}


class ConfigMixin:
    @classmethod
    def get_settings(cls, attr, *args):
        return cls.config.get(attr, *args)


class OIDCAuthenticationCallbackView(ConfigMixin, views.OIDCAuthenticationCallbackView):
    config = CONFIG

    @property
    def success_url(self):
        return get_next_url(self.request)

    def login_failure(self):
        # Don't add message if there's already the "no register" message
        if not self.request._messages._queued_messages:
            messages.error(self.request, "La connexion n'a pas fonctionné.")
        return HttpResponseRedirect(reverse("accounts:login"))


class OIDCAuthenticationRequestView(ConfigMixin, views.OIDCAuthenticationRequestView):
    config = CONFIG


class OIDCLogoutView(ConfigMixin, views.OIDCLogoutView):
    config = CONFIG


class OIDCAuthenticationBackend(ConfigMixin, auth.OIDCAuthenticationBackend):
    config = CONFIG
    name = None
    required_claims = ["email", "given_name", "family_name", "sub"]
    additionnal_claims = []

    def authenticate(self, request, **kwargs):
        self.request = request
        return super().authenticate(request, **kwargs)

    def get_additional_data(self, claims):
        return {k: v for k, v in sorted(claims.items()) if k in self.additionnal_claims}

    def email_lookup_q(self, email):
        return Q(email__iexact=email)

    def filter_users_by_claims(self, claims):
        return self.UserModel.objects.filter(federation_sub=claims["sub"], federation=self.name)

    def get_userinfo(self, access_token, id_token, payload):
        return super().get_userinfo(access_token, id_token, payload) | {"id_token": id_token}

    def create_user(self, claims):
        log = log_data(self.request)
        log["email"] = claims["email"]
        log["event"] = "register_error"
        log["federation"] = self.name
        transaction.on_commit(partial(logger.info, log))

        messages.error(
            self.request,
            format_html(
                "La création de votre compte a échoué. Depuis le 1er octobre 2024, date du passage à ProConnect, "
                "vous ne pouvez plus créer de compte Inclusion Connect. "
                "Veuillez vous rapprocher de votre fournisseur de service pour plus d’informations sur la mise à "
                "disposition de ProConnect, qui doit intervenir dans les meilleurs délais. "
                '<a href="{}" target="_blank" rel="noopener">'
                "Besoin d’aide</a> ?",
                settings.MIGRATION_PAGE_URL,
            ),
        )

        # No user creation

    def update_user(self, user, claims):
        log = log_data(self.request)
        log["email"] = user.email
        log["user"] = user.pk
        log["event"] = LoginView.EVENT_NAME
        log["federation"] = self.name

        transaction.on_commit(partial(logger.info, log))

        # Only store id_token_hint and update federation_data
        user.federation_id_token_hint = claims["id_token"]
        user.federation_data = self.get_additional_data(claims)
        user.save()

        # No more user update either
        return user

    def verify_claims(self, claims):
        if super().verify_claims(claims):
            # Additional claims are not mandatory
            return all(field in claims for field in self.required_claims)
