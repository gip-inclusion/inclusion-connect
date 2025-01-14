import logging
from functools import partial

from django.conf import settings
from django.contrib import messages
from django.core.exceptions import SuspiciousOperation
from django.db import transaction
from django.db.models import Q
from django.forms.models import model_to_dict
from django.http import HttpResponseRedirect
from django.urls import reverse
from django.utils.html import format_html
from mozilla_django_oidc import auth, views

from inclusion_connect.accounts.views import EditUserInfoView, LoginView, RegisterView
from inclusion_connect.logging import log_data
from inclusion_connect.users.models import EmailAddress
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

    def get_additional_data(self, claims):
        return {k: v for k, v in sorted(claims.items()) if k in self.additionnal_claims}

    def email_lookup_q(self, email):
        return Q(email__iexact=email)

    def filter_users_by_claims(self, claims):
        sub_users = self.UserModel.objects.filter(federation_sub=claims["sub"], federation=self.name)
        if sub_users or settings.FREEZE_ACCOUNTS:
            return sub_users

        email_q = self.email_lookup_q(claims["email"])
        try:
            user = EmailAddress.objects.select_related("user").get(email_q).user
        except EmailAddress.DoesNotExist:
            return []
        if user.federation is not None:
            log = log_data(self.request)
            log["email"] = user.email
            log["user"] = user.pk
            log["event"] = f"{LoginView.EVENT_NAME}_error"
            log["federation"] = self.name
            transaction.on_commit(partial(logger.info, log))
            raise SuspiciousOperation(
                f"email={claims['email']} from federation={self.name} is already used by {user.federation}"
            )
        return [user]

    def get_userinfo(self, access_token, id_token, payload):
        return super().get_userinfo(access_token, id_token, payload) | {"id_token": id_token}

    def create_user(self, claims):
        if settings.FREEZE_ACCOUNTS:
            log = log_data(self.request)
            log["email"] = claims["email"]
            log["event"] = "register_error"
            log["federation"] = self.name
            transaction.on_commit(partial(logger.info, log))

            messages.error(
                self.request,
                format_html(
                    "La création de votre compte a échoué. Depuis le 28 octobre 2024, date du passage à ProConnect, "
                    "vous ne pouvez plus créer de compte Inclusion Connect. "
                    "Veuillez vous rapprocher de votre fournisseur de service pour plus d’informations sur la mise à "
                    "disposition de ProConnect, qui doit intervenir dans les meilleurs délais. "
                    '<a href="{}" target="_blank" rel="noopener">'
                    "Besoin d’aide</a> ?",
                    settings.MIGRATION_PAGE_URL,
                ),
            )
            return

        user = self.UserModel.objects.create(
            email=claims["email"],
            first_name=claims["given_name"],
            last_name=claims["family_name"],
            federation_sub=claims["sub"],
            federation=self.name,
            federation_data=self.get_additional_data(claims),
            federation_id_token_hint=claims["id_token"],
        )
        email_address = EmailAddress(user=user, email=user.email)
        email_address.verify()
        log = log_data(self.request)
        log["email"] = user.email
        log["user"] = user.pk
        log["event"] = RegisterView.EVENT_NAME
        log["federation"] = self.name
        transaction.on_commit(partial(logger.info, log))

        return user

    def update_user(self, user, claims):
        if settings.FREEZE_ACCOUNTS:
            log = log_data(self.request)
            log["email"] = user.email
            log["user"] = user.pk
            log["event"] = LoginView.EVENT_NAME
            log["federation"] = self.name
            transaction.on_commit(partial(logger.info, log))

            user.federation_id_token_hint = claims["id_token"]
            user.federation_data = self.get_additional_data(claims)
            user.save()
            # No more user update either
            return user

        if (
            user.federation
            and user.email != claims["email"]
            and EmailAddress.objects.filter(email=claims["email"]).exists()
        ):
            # Updating the email will crash because it"s already used. Don't update for now
            user.new_email_already_used = claims["email"]
            user.save()
        else:
            old_user_data = model_to_dict(user)
            user.email = claims["email"]
            user.first_name = claims["given_name"]
            user.last_name = claims["family_name"]
            user.federation_sub = claims["sub"]
            user.federation = self.name
            user.federation_data = self.get_additional_data(claims)
            user.federation_id_token_hint = claims["id_token"]
            user.save()
            new_user_data = model_to_dict(user)

            if old_user_data["email"] == "":
                user.email_addresses.filter(email=claims["email"]).get().verify()
            elif old_user_data["email"] != new_user_data["email"]:
                email_address = EmailAddress(user=user, email=user.email)
                email_address.verify()

        log = log_data(self.request)
        log["email"] = user.email
        log["user"] = user.pk
        log["event"] = LoginView.EVENT_NAME
        log["federation"] = self.name
        transaction.on_commit(partial(logger.info, log))

        if user.new_email_already_used:
            log = log_data(self.request)
            log["event"] = f"{EditUserInfoView.EVENT_NAME}_error"
            log["user"] = user.pk
            log["errors"] = {"already_used_email": user.new_email_already_used}
            transaction.on_commit(partial(logger.info, log))
        else:
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
            # Additional claims are not mandatory
            return all(field in claims for field in self.required_claims)
