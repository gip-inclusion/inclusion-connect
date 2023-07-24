import jwt
from django.http import Http404
from django.shortcuts import get_object_or_404
from django.utils import http
from django.views.generic import View

from inclusion_connect.accounts.views import handle_email_confirmation, handle_signature_expired
from inclusion_connect.keycloak_compat.models import JWTHashSecret
from inclusion_connect.keycloak_compat.utils import realm_from_request


class ActionToken(View):
    # This view is transitional, will only live for less than a week in production.
    def get(self, request):
        try:
            request_jwt = request.GET["key"]
        except KeyError as e:
            raise Http404 from e
        realm = realm_from_request(request)
        jwt_hash_secret = get_object_or_404(JWTHashSecret, realm_id=realm)
        secret = http.urlsafe_base64_decode(jwt_hash_secret.secret)
        audience = request.build_absolute_uri(f"/realms/{realm}")
        try:
            try:
                decoded = jwt.decode(request_jwt, secret, algorithms=["HS256"], audience=audience)
            except jwt.exceptions.ExpiredSignatureError as e:
                decoded = jwt.decode(
                    request_jwt, secret, algorithms=["HS256"], audience=audience, options={"verify_exp": False}
                )
                try:
                    email = decoded["eml"]
                except KeyError as err:
                    raise e from err
                else:
                    return handle_signature_expired(request, email)
        except jwt.exceptions.InvalidTokenError as e:
            raise Http404 from e
        if decoded["typ"] == "verify-email":
            return handle_email_confirmation(request, decoded["sub"], decoded["eml"])
        raise Http404
