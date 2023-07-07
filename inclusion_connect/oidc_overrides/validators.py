from oauth2_provider.oauth2_validators import OAuth2Validator


class CustomOAuth2Validator(OAuth2Validator):
    # Extend the standard scopes to add a new "permissions" scope
    # which returns a "permissions" claim:
    oidc_claim_scope = OAuth2Validator.oidc_claim_scope
    oidc_claim_scope.update(
        {
            "permissions": "permissions",
            "site_pe": "profile",
            "structure_pe": "profile",
        }
    )

    def get_additional_claims(self, request):
        """Add data to the Id Token"""

        return {
            "given_name": request.user.first_name,
            "family_name": request.user.last_name,
            "email": request.user.email,
        } | (request.user.federation_data or {})
