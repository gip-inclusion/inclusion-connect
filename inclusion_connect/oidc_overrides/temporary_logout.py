# FIXME: Remove whole file when bumping django-oauth-toolkit

import json
from urllib.parse import urlparse

from django import forms
from django.contrib.auth import logout
from django.urls import reverse
from django.views.generic import FormView
from jwcrypto import jwt
from jwcrypto.common import JWException
from jwcrypto.jws import InvalidJWSObject
from jwcrypto.jwt import JWTExpired
from oauth2_provider import views as oauth2_views
from oauth2_provider.http import OAuth2ResponseRedirect
from oauth2_provider.models import (
    get_access_token_model,
    get_application_model,
    get_id_token_model,
    get_refresh_token_model,
)
from oauth2_provider.settings import oauth2_settings
from oauthlib.common import add_params_to_uri


setattr(oauth2_settings, "OIDC_RP_INITIATED_LOGOUT_ENABLED", True)
setattr(oauth2_settings, "OIDC_RP_INITIATED_LOGOUT_ALWAYS_PROMPT", False)
setattr(oauth2_settings, "OIDC_RP_INITIATED_LOGOUT_STRICT_REDIRECT_URIS", False)
setattr(oauth2_settings, "OIDC_RP_INITIATED_LOGOUT_ACCEPT_EXPIRED_TOKENS", True)
setattr(oauth2_settings, "OIDC_RP_INITIATED_LOGOUT_DELETE_TOKENS", True)


class OIDCError(Exception):
    """
    General class to derive from for all OIDC related errors.
    """

    status_code = 400
    error = None

    def __init__(self, description=None):
        if description is not None:
            self.description = description

        message = "({}) {}".format(self.error, self.description)
        super().__init__(message)


class InvalidRequestFatalError(OIDCError):
    """
    For fatal errors. These are requests with invalid parameter values, missing parameters or otherwise
    incorrect requests.
    """

    error = "invalid_request"


class ClientIdMissmatch(InvalidRequestFatalError):
    description = "Mismatch between the Client ID of the ID Token and the Client ID that was provided."


class InvalidOIDCClientError(InvalidRequestFatalError):
    description = "The client is unknown or no client has been included."


class InvalidOIDCRedirectURIError(InvalidRequestFatalError):
    description = "Invalid post logout redirect URI."


class InvalidIDTokenError(InvalidRequestFatalError):
    description = "The ID Token is expired, revoked, malformed, or otherwise invalid."


class LogoutDenied(OIDCError):
    error = "logout_denied"
    description = "Logout has been refused by the user."


class ConfirmLogoutForm(forms.Form):
    allow = forms.BooleanField(required=False)
    id_token_hint = forms.CharField(required=False, widget=forms.HiddenInput())
    logout_hint = forms.CharField(required=False, widget=forms.HiddenInput())
    client_id = forms.CharField(required=False, widget=forms.HiddenInput())
    post_logout_redirect_uri = forms.CharField(required=False, widget=forms.HiddenInput())
    state = forms.CharField(required=False, widget=forms.HiddenInput())
    ui_locales = forms.CharField(required=False, widget=forms.HiddenInput())

    def __init__(self, *args, **kwargs):
        self.request = kwargs.pop("request", None)
        super(ConfirmLogoutForm, self).__init__(*args, **kwargs)


Application = get_application_model()


class ConnectDiscoveryInfoView(oauth2_views.ConnectDiscoveryInfoView):
    def get(self, request, *args, **kwargs):
        response = super().get(request, *args, **kwargs)
        issuer_url = oauth2_settings.OIDC_ISS_ENDPOINT
        if not issuer_url:
            end_session_endpoint = request.build_absolute_uri(reverse("oauth2_provider:rp-initiated-logout"))
        else:
            parsed_url = urlparse(oauth2_settings.OIDC_ISS_ENDPOINT)
            host = parsed_url.scheme + "://" + parsed_url.netloc
            end_session_endpoint = "{}{}".format(host, reverse("oauth2_provider:rp-initiated-logout"))
        # FIXME
        response.data["end_session_endpoint"] = end_session_endpoint
        return response


def _load_id_token(token):
    """
    Loads an IDToken given its string representation for use with RP-Initiated Logout.
    A tuple (IDToken, claims) is returned. Depending on the configuration expired tokens may be loaded.
    If loading failed (None, None) is returned.
    """
    IDToken = get_id_token_model()
    validator = oauth2_settings.OAUTH2_VALIDATOR_CLASS()

    try:
        key = validator._get_key_for_token(token)
    except InvalidJWSObject:
        # Failed to deserialize the key.
        return None, None

    # Could not identify key from the ID Token.
    if not key:
        return None, None

    try:
        if oauth2_settings.OIDC_RP_INITIATED_LOGOUT_ACCEPT_EXPIRED_TOKENS:
            # Only check the following while loading the JWT
            # - claims are dict
            # - the Claims defined in RFC7519 if present have the correct type (string, integer, etc.)
            # The claim contents are not validated. `exp` and `nbf` in particular are not validated.
            check_claims = {}
        else:
            # Also validate the `exp` (expiration time) and `nbf` (not before) claims.
            check_claims = None
        jwt_token = jwt.JWT(key=key, jwt=token, check_claims=check_claims)
        claims = json.loads(jwt_token.claims)

        # Assumption: the `sub` claim and `user` property of the corresponding IDToken Object point to the
        # same user.
        # To verify that the IDToken was intended for the user it is therefore sufficient to check the `user`
        # attribute on the IDToken Object later on.

        return IDToken.objects.get(jti=claims["jti"]), claims

    except (JWException, JWTExpired, IDToken.DoesNotExist):
        return None, None


def _validate_claims(request, claims):
    """
    Validates the claims of an IDToken for use with OIDC RP-Initiated Logout.
    """
    validator = oauth2_settings.OAUTH2_VALIDATOR_CLASS()

    # Verification of `iss` claim is mandated by OIDC RP-Initiated Logout specs.
    if "iss" not in claims or claims["iss"] != validator.get_oidc_issuer_endpoint(request):
        # IDToken was not issued by this OP, or it can not be verified.
        return False

    return True


def validate_logout_request(request, id_token_hint, client_id, post_logout_redirect_uri):
    """
    Validate an OIDC RP-Initiated Logout Request.
    `(application, token_user)` is returned.

    If it is set `application` will also be set to the Application that is requesting the logout.
    `token_user` is the id_token user, which will used to revoke the tokens if found.

    The `id_token_hint` will be validated if given. If both `client_id` and `id_token_hint` are given they
    will be validated against each other.
    """

    id_token = None
    if id_token_hint:
        # Only basic validation has been done on the IDToken at this point.
        id_token, claims = _load_id_token(id_token_hint)

        if not id_token or not _validate_claims(request, claims):
            raise InvalidIDTokenError()

        # If both id_token_hint and client_id are given it must be verified that they match.
        if client_id:
            if id_token.application.client_id != client_id:
                raise ClientIdMissmatch()

    application = None
    # Determine the application that is requesting the logout.
    if client_id:
        application = get_application_model().objects.get(client_id=client_id)
    elif id_token:
        application = id_token.application

    # Validate `post_logout_redirect_uri`
    if post_logout_redirect_uri:
        if not application:
            raise InvalidOIDCClientError()
        scheme = urlparse(post_logout_redirect_uri)[0]
        if not scheme:
            raise InvalidOIDCRedirectURIError("A Scheme is required for the redirect URI.")
        if oauth2_settings.OIDC_RP_INITIATED_LOGOUT_STRICT_REDIRECT_URIS and (
            scheme == "http" and application.client_type != "confidential"
        ):
            raise InvalidOIDCRedirectURIError("http is only allowed with confidential clients.")
        if scheme not in application.get_allowed_schemes():
            raise InvalidOIDCRedirectURIError(f'Redirect to scheme "{scheme}" is not permitted.')
        if not application.post_logout_redirect_uri_allowed(post_logout_redirect_uri):
            raise InvalidOIDCRedirectURIError("This client does not have this redirect uri registered.")

    return application, id_token.user if id_token else None


class RPInitiatedLogoutView(FormView):
    template_name = "oauth2_provider/logout_confirm.html"
    form_class = ConfirmLogoutForm
    # Only delete tokens for Application whose client type and authorization
    # grant type are in the respective lists.
    token_deletion_client_types = [
        Application.CLIENT_PUBLIC,
        Application.CLIENT_CONFIDENTIAL,
    ]
    token_deletion_grant_types = [
        Application.GRANT_AUTHORIZATION_CODE,
        Application.GRANT_IMPLICIT,
        Application.GRANT_PASSWORD,
        Application.GRANT_CLIENT_CREDENTIALS,
        Application.GRANT_OPENID_HYBRID,
    ]

    def get_initial(self):
        return {
            "id_token_hint": self.oidc_data.get("id_token_hint", None),
            "logout_hint": self.oidc_data.get("logout_hint", None),
            "client_id": self.oidc_data.get("client_id", None),
            "post_logout_redirect_uri": self.oidc_data.get("post_logout_redirect_uri", None),
            "state": self.oidc_data.get("state", None),
            "ui_locales": self.oidc_data.get("ui_locales", None),
        }

    def dispatch(self, request, *args, **kwargs):
        self.oidc_data = {}
        return super().dispatch(request, *args, **kwargs)

    def get(self, request, *args, **kwargs):
        id_token_hint = request.GET.get("id_token_hint")
        client_id = request.GET.get("client_id")
        post_logout_redirect_uri = request.GET.get("post_logout_redirect_uri")
        state = request.GET.get("state")

        try:
            application, token_user = validate_logout_request(
                request=request,
                id_token_hint=id_token_hint,
                client_id=client_id,
                post_logout_redirect_uri=post_logout_redirect_uri,
            )
        except OIDCError as error:
            return self.error_response(error)

        if not self.must_prompt(token_user):
            return self.do_logout(application, post_logout_redirect_uri, state, token_user)

        self.oidc_data = {
            "id_token_hint": id_token_hint,
            "client_id": client_id,
            "post_logout_redirect_uri": post_logout_redirect_uri,
            "state": state,
        }
        form = self.get_form(self.get_form_class())
        kwargs["form"] = form
        if application:
            kwargs["application"] = application

        return self.render_to_response(self.get_context_data(**kwargs))

    def form_valid(self, form):
        id_token_hint = form.cleaned_data.get("id_token_hint")
        client_id = form.cleaned_data.get("client_id")
        post_logout_redirect_uri = form.cleaned_data.get("post_logout_redirect_uri")
        state = form.cleaned_data.get("state")

        try:
            application, token_user = validate_logout_request(
                request=self.request,
                id_token_hint=id_token_hint,
                client_id=client_id,
                post_logout_redirect_uri=post_logout_redirect_uri,
            )

            if not self.must_prompt(token_user) or form.cleaned_data.get("allow"):
                return self.do_logout(application, post_logout_redirect_uri, state, token_user)
            else:
                raise LogoutDenied()

        except OIDCError as error:
            return self.error_response(error)

    def must_prompt(self, token_user):
        """Indicate whether the logout has to be confirmed by the user. This happens if the
        specifications force a confirmation, or it is enabled by `OIDC_RP_INITIATED_LOGOUT_ALWAYS_PROMPT`.

        A logout without user interaction (i.e. no prompt) is only allowed
        if an ID Token is provided that matches the current user.
        """
        return (
            oauth2_settings.OIDC_RP_INITIATED_LOGOUT_ALWAYS_PROMPT
            or token_user is None
            or token_user != self.request.user
        )

    def do_logout(self, application=None, post_logout_redirect_uri=None, state=None, token_user=None):
        # Delete Access Tokens
        if oauth2_settings.OIDC_RP_INITIATED_LOGOUT_DELETE_TOKENS:
            AccessToken = get_access_token_model()
            RefreshToken = get_refresh_token_model()
            access_tokens_to_delete = AccessToken.objects.filter(
                user=token_user or self.request.user,
                application__client_type__in=self.token_deletion_client_types,
                application__authorization_grant_type__in=self.token_deletion_grant_types,
            )
            # This queryset has to be evaluated eagerly. The queryset would be empty with lazy evaluation
            # because `access_tokens_to_delete` represents an empty queryset once `refresh_tokens_to_delete`
            # is evaluated as all AccessTokens have been deleted.
            refresh_tokens_to_delete = list(RefreshToken.objects.filter(access_token__in=access_tokens_to_delete))
            for token in access_tokens_to_delete:
                # Delete the token and its corresponding refresh and IDTokens.
                if token.id_token:
                    token.id_token.revoke()
                token.revoke()
            for refresh_token in refresh_tokens_to_delete:
                refresh_token.revoke()
        # Logout in Django
        logout(self.request)
        # Redirect
        if post_logout_redirect_uri:
            if state:
                return OAuth2ResponseRedirect(
                    add_params_to_uri(post_logout_redirect_uri, [("state", state)]),
                    application.get_allowed_schemes(),
                )
            else:
                return OAuth2ResponseRedirect(post_logout_redirect_uri, application.get_allowed_schemes())
        else:
            return OAuth2ResponseRedirect(
                self.request.build_absolute_uri("/"),
                oauth2_settings.ALLOWED_REDIRECT_URI_SCHEMES,
            )

    def error_response(self, error):
        error_response = {"error": error}
        return self.render_to_response(error_response, status=error.status_code)
