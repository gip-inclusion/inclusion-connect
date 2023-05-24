import json

from django.contrib.auth import logout
from django.contrib.sessions.models import Session
from django.http import HttpResponseRedirect
from django.urls import reverse_lazy
from django.utils import timezone
from django.views.generic import View
from jwcrypto import jwt
from oauth2_provider import views as oauth2_views
from oauth2_provider.exceptions import OAuthToolkitError
from oauth2_provider.http import OAuth2ResponseRedirect
from oauth2_provider.models import get_access_token_model, get_id_token_model, get_refresh_token_model
from oauth2_provider.settings import oauth2_settings

from inclusion_connect.oidc_overrides.models import Application
from inclusion_connect.oidc_overrides.validators import CustomOAuth2Validator
from inclusion_connect.users.models import User, UserApplicationLink
from inclusion_connect.utils.oidc import OIDC_SESSION_KEY, get_next_url, initial_from_login_hint


class OIDCSessionMixin:
    def save_session(self):
        self.request.session[OIDC_SESSION_KEY] = dict(self.request.GET.items())
        self.request.session["next_url"] = self.request.get_full_path()

    def get_initial(self):
        initial = super().get_initial()
        initial.update(initial_from_login_hint(self.request))
        return initial

    def get_success_url(self):
        return get_next_url(self.request)

    def setup(self, request, *args, **kwargs):
        next_url = request.GET.get("next")
        if next_url:
            request.session["next_url"] = next_url
        return super().setup(request, *args, **kwargs)


class BaseAuthorizationView(OIDCSessionMixin, oauth2_views.base.AuthorizationView):
    """Base View that improves the dispatch workflow:

    First step is to validate authorization params
    This will allow us to display an error before having to login / create an account

    Then check if user is authenticated. If not store auth params so that we can retrieve cleanly in
    the registration pages
    """

    template_name = "oidc_authorize.html"

    def dispatch(self, request, *args, **kwargs):
        try:
            self.validate_authorization_request(request)
        except OAuthToolkitError as error:
            # Application is not available at this time.
            return self.error_response(error, application=None)

        return super().dispatch(request, *args, **kwargs)

    def handle_no_permission(self):
        self.save_session()
        return HttpResponseRedirect(self.login_url)

    def create_authorization_response(self, request, scopes, credentials, allow):
        response = super().create_authorization_response(request, scopes, credentials, allow)

        # Only link if authorization response was created
        UserApplicationLink.objects.update_or_create(
            user=self.request.user,
            application=Application.objects.get(client_id=credentials["client_id"]),
            defaults={"last_login": timezone.now()},
        )
        return response


class AuthorizationView(BaseAuthorizationView):
    login_url = reverse_lazy("accounts:login")


class RegistrationView(BaseAuthorizationView):
    login_url = reverse_lazy("accounts:register")


class ActivationView(BaseAuthorizationView):
    login_url = reverse_lazy("accounts:activate")


class LogoutView(View):
    # We should probably just cope/paste from https://github.com/jazzband/django-oauth-toolkit/pull/1244
    # until it's merged
    def get(self, request, *args, **kwargs):
        post_logout_redirect_uri = request.GET.get("post_logout_redirect_uri")
        id_token_hint = request.GET.get("id_token_hint")

        try:
            id_token = self._clean_token(id_token_hint)

            user = User.objects.get(username=id_token.user_id)
            request.user = user

            # FIXME: the call may come from the relying part instead of the user browser.
            # Therefore the request user and sessions may not be the one we want to clear.
            # We can get the user, but it will not help us clear the django session from
            # the login flow. Delete the user sessions manually
            [
                s.delete()
                for s in Session.objects.filter(expire_date__gte=timezone.now())
                if s.get_decoded().get("_auth_user_id") == str(id_token.user_id)
            ]
        except Exception:
            pass

        logout(request)

        if post_logout_redirect_uri:
            return OAuth2ResponseRedirect(post_logout_redirect_uri, oauth2_settings.ALLOWED_REDIRECT_URI_SCHEMES)
        # FIXME: Add a 'you are logged out' page
        return OAuth2ResponseRedirect(
            self.request.build_absolute_uri("/"), oauth2_settings.ALLOWED_REDIRECT_URI_SCHEMES
        )

    def _clean_token(self, id_token_hint):
        key = CustomOAuth2Validator()._get_key_for_token(id_token_hint)
        jwt_token = jwt.JWT(key=key, jwt=id_token_hint)
        claims = json.loads(jwt_token.claims)

        IDToken = get_id_token_model()
        id_token = IDToken.objects.get(jti=claims["jti"])
        self.request.user = id_token.user

        # Remove tokens
        AccessToken = get_access_token_model()
        RefreshToken = get_refresh_token_model()
        access_tokens_to_delete = AccessToken.objects.filter(user=self.request.user)
        refresh_tokens_to_delete = list(RefreshToken.objects.filter(access_token__in=access_tokens_to_delete))
        for token in access_tokens_to_delete:
            # Delete the token and its corresponding refresh and IDTokens.
            if token.id_token:
                token.id_token.revoke()
            token.revoke()
        for refresh_token in refresh_tokens_to_delete:
            refresh_token.revoke()

        return id_token

    def post(self, *args, **kwargs):
        return self.get(*args, **kwargs)
