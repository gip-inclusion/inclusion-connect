from django.conf import settings
from oauth2_provider.oauth2_validators import OAuth2Validator


class CustomOAuth2Validator(OAuth2Validator):
    # Extend the standard scopes to add a new "permissions" scope
    # which returns a "permissions" claim:
    oidc_claim_scope = OAuth2Validator.oidc_claim_scope
    oidc_claim_scope.update({"permissions": "permissions"})

    def get_additional_claims(self):
        return {
            "given_name": lambda request: request.user.first_name,
            "family_name": lambda request: request.user.last_name,
            "email": lambda request: request.user.email,
        }

    def is_origin_allowed(self, client_id, origin, request, *args, **kwargs):
        if settings.ALLOW_ALL_REDIRECT_URIS:
            return True

        return super().is_origin_allowed(client_id, origin, request, *args, **kwargs)
