import json

from django.contrib.auth import logout
from django.contrib.sessions.models import Session
from django.views.generic import View
from jwcrypto import jwt
from oauth2_provider.http import OAuth2ResponseRedirect
from oauth2_provider.models import get_access_token_model, get_id_token_model, get_refresh_token_model

from inclusion_connect.oidc_overrides.validators import CustomOAuth2Validator


class LogoutView(View):
    # We should probably just cope/paste from https://github.com/jazzband/django-oauth-toolkit/pull/1244
    # until it's merged
    def get(self, request, *args, **kwargs):
        post_logout_redirect_uri = request.GET.get("post_logout_redirect_uri")
        id_token_hint = request.GET.get("id_token_hint")

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

        logout(request)

        # Why isn't it done in logout ?
        # Force remove user sessions
        [s.delete() for s in Session.objects.all() if s.get_decoded().get("_auth_user_id") == str(id_token.user_id)]

        if post_logout_redirect_uri:
            return OAuth2ResponseRedirect(post_logout_redirect_uri)
        return OAuth2ResponseRedirect(self.request.build_absolute_uri("/"), ["http", "https"])
