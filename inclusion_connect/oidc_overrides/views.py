from django.http import HttpResponseRedirect
from django.urls import reverse_lazy
from django.utils import timezone
from oauth2_provider import views as oauth2_views
from oauth2_provider.exceptions import OAuthToolkitError

from inclusion_connect.oidc_overrides.models import Application
from inclusion_connect.oidc_overrides.temporary_logout import RPInitiatedLogoutView
from inclusion_connect.users.models import UserApplicationLink
from inclusion_connect.utils.oidc import OIDC_SESSION_KEY, get_next_url, initial_from_login_hint
from inclusion_connect.utils.urls import is_inclusion_connect_url


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
        if next_url and is_inclusion_connect_url(request, next_url):
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


class LogoutView(RPInitiatedLogoutView):
    def must_prompt(self, token_user):
        prompt = super().must_prompt(token_user)

        if (
            token_user  # We found a user with the token
            and prompt
            and self.request.user.is_authenticated is False  # But the user is already logged out
            and not any(
                [
                    token_user.oauth2_provider_accesstoken.filter(expires__gt=timezone.now()).exists(),
                    token_user.oauth2_provider_grant.filter(expires__gt=timezone.now()).exists(),
                    token_user.oauth2_provider_idtoken.filter(expires__gt=timezone.now()).exists(),
                    # confidential clients refresh tokens cannot be used with logging in again, we can ignore them
                    token_user.oauth2_provider_refreshtoken.filter(revoked=None)
                    .exclude(application__client_type="confidential")
                    .exists(),
                ]
            )  # And all tokens expired
        ):
            return False  # Nothing to do : don't prompt the user

        return prompt
