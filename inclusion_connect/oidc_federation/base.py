import logging
from functools import partial

from django.contrib import messages
from django.core.exceptions import SuspiciousOperation
from django.db import transaction
from django.forms.models import model_to_dict
from django.http import HttpResponseRedirect
from django.urls import reverse
from mozilla_django_oidc import auth, views

from inclusion_connect.accounts.views import EditUserInfoView, LoginView, RegisterView
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
        messages.error(self.request, "La connexion n'a pas fonctionné.")
        return HttpResponseRedirect(reverse("accounts:login"))


class OIDCAuthenticationRequestView(ConfigMixin, views.OIDCAuthenticationRequestView):
    config = CONFIG

    def get_extra_params(self, request):
        return {"realm": "/agent"}


class OIDCLogoutView(ConfigMixin, views.OIDCLogoutView):
    config = CONFIG


class OIDCAuthenticationBackend(ConfigMixin, auth.OIDCAuthenticationBackend):
    config = CONFIG
    name = None
    required_claims = ["email", "given_name", "family_name", "sub"]
    additionnal_claims = []

    def get_additional_data(self, claims):
        return {k: v for k, v in sorted(claims.items()) if k in self.additionnal_claims}

    def filter_users_by_claims(self, claims):
        sub_users = self.UserModel.objects.filter(federation_sub=claims["sub"], federation=self.name)
        if sub_users:
            return sub_users

        email_users = super().filter_users_by_claims(claims)

        if email_users:
            user = email_users.exclude(federation=None).first()
            if user:
                log = log_data(self.request)
                log["email"] = user.email
                log["user"] = user.pk
                log["event"] = f"{LoginView.EVENT_NAME}_error"
                log["federation"] = self.name
                transaction.on_commit(partial(logger.info, log))
                raise SuspiciousOperation(
                    f"email={claims['email']} from federation={self.name} is already used by {user.federation}"
                )

        return email_users

    def get_userinfo(self, access_token, id_token, payload):
        return super().get_userinfo(access_token, id_token, payload) | {"id_token": id_token}

    def create_user(self, claims):
        user = self.UserModel.objects.create(
            email=claims["email"],
            first_name=claims["given_name"],
            last_name=claims["family_name"],
            federation_sub=claims["sub"],
            federation=self.name,
            federation_data=self.get_additional_data(claims),
            federation_id_token_hint=claims["id_token"],
        )
        log = log_data(self.request)
        log["email"] = user.email
        log["user"] = user.pk
        log["event"] = RegisterView.EVENT_NAME
        log["federation"] = self.name
        transaction.on_commit(partial(logger.info, log))

        return user

    def update_user(self, user, claims):
        old_user_data = model_to_dict(user)
        user.email = claims["email"]
        user.first_name = claims["given_name"]
        user.last_name = claims["family_name"]
        user.federation_sub = claims["sub"]
        user.federation = self.name
        user.federation_data = self.get_additional_data(claims)
        user.federation_id_token_hint = claims["id_token"]
        new_user_data = model_to_dict(user)
        user.save()

        log = log_data(self.request)
        log["email"] = user.email
        log["user"] = user.pk
        log["event"] = LoginView.EVENT_NAME
        log["federation"] = self.name
        transaction.on_commit(partial(logger.info, log))

        log = log_data(self.request)
        log["event"] = EditUserInfoView.EVENT_NAME
        log["user"] = user.pk
        for key in old_user_data.keys():
            if old_user_data[key] != new_user_data[key]:
                log[f"old_{key}"] = old_user_data[key]
                log[f"new_{key}"] = new_user_data[key]
        transaction.on_commit(partial(logger.info, log))

        return user

    def verify_claims(self, claims):
        if super().verify_claims(claims):
            return all(field in claims for field in self.required_claims + self.additionnal_claims)
