from django.contrib import messages
from django.core.exceptions import SuspiciousOperation
from django.http import HttpResponseRedirect
from django.urls import reverse
from mozilla_django_oidc import auth, views

from inclusion_connect.utils.oidc import get_next_url


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
        return {k: v for k, v in claims.items() if k in self.additionnal_claims}

    def filter_users_by_claims(self, claims):
        sub_users = self.UserModel.objects.filter(federation_sub=claims["sub"], federation=self.name)
        if sub_users:
            return sub_users

        email_users = super().filter_users_by_claims(claims)

        if email_users:
            other_federation = email_users.exclude(federation=None).values_list("federation", flat=True).first()
            if other_federation:
                raise SuspiciousOperation(
                    f"email={claims['email']} from federation={self.name} is already used by {other_federation}"
                )

        return email_users

    def create_user(self, claims):
        user = self.UserModel.objects.create(
            email=claims["email"],
            first_name=claims["given_name"],
            last_name=claims["family_name"],
            federation_sub=claims["sub"],
            federation=self.name,
            federation_data=self.get_additional_data(claims),
        )
        # TODO: Log
        return user

    def update_user(self, user, claims):
        # TODO: Log
        user.email = claims["email"]
        user.first_name = claims["given_name"]
        user.last_name = claims["family_name"]
        user.federation_sub = claims["sub"]
        user.federation = self.name
        user.federation_data = self.get_additional_data(claims)
        user.save()
        return user

    def verify_claims(self, claims):
        if super().verify_claims(claims):
            return all(field in claims for field in self.required_claims + self.additionnal_claims)
