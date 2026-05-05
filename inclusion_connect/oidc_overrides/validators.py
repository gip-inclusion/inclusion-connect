from django.conf import settings
from oauth2_provider.oauth2_validators import OAuth2Validator


class CustomOAuth2Validator(OAuth2Validator):
    oidc_claim_scope = OAuth2Validator.oidc_claim_scope
    oidc_claim_scope.update(
        {
            "siret": "siret",
            "siren": "siren",
            "usual_name": "usual_name",
            "uid": "uid",
        }
    )

    def get_claim_dict(self, request):
        return super().get_claim_dict(request) | {
            "email": request.user.email,
            "given_name": request.user.first_name,
            "family_name": request.user.last_name,
            "usual_name": request.user.last_name,
            "uid": str(request.user.pk),
            "siret": settings.SIRET,
            "siren": settings.SIRET[:9],
        }

    def get_oidc_claims(self, token, token_handler, request):
        claims = super().get_oidc_claims(token, token_handler, request)
        # Proconnect asks for "given_name" by adding it to the scopes
        # where it's expected to be in the "profile" scope (see OAuth2Validator.oidc_claim_scope)
        data = self.get_claim_dict(request)
        for k, v in data.items():
            if k in request.scopes and k not in claims:
                claims[k] = v
        return claims
