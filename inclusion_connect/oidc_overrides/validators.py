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
