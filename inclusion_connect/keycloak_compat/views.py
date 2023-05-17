import jwt
from django.contrib import messages
from django.contrib.auth import login
from django.http import Http404, HttpResponseRedirect
from django.shortcuts import get_object_or_404
from django.urls import reverse
from django.utils import http
from django.views.generic import View

from inclusion_connect.accounts.views import EMAIL_CONFIRM_KEY
from inclusion_connect.keycloak_compat.models import JWTHashSecret
from inclusion_connect.keycloak_compat.utils import realm_from_request
from inclusion_connect.oidc_overrides.views import OIDCSessionMixin
from inclusion_connect.users.models import EmailAddress


class ActionToken(OIDCSessionMixin, View):
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
                    request.session[EMAIL_CONFIRM_KEY] = decoded["eml"]
                except KeyError:
                    raise e
                else:
                    messages.error(request, "Le lien de vérification d’adresse e-mail a expiré.")
                    return HttpResponseRedirect(reverse("accounts:confirm-email"))
        except jwt.exceptions.InvalidTokenError as e:
            raise Http404 from e
        if decoded["typ"] == "verify-email":
            uid = decoded["sub"]
            email = decoded["eml"]
            email_address = get_object_or_404(EmailAddress.objects.select_related("user"), user_id=uid, email=email)
            if email_address.verified_at:
                messages.info(request, "Cette adresse e-mail est déjà vérifiée.")
                if request.user.is_authenticated:
                    url = reverse("accounts:edit_user_info")
                else:
                    url = reverse("accounts:login")
                return HttpResponseRedirect(url)
            email_address.verify()
            login(request, email_address.user)
            return HttpResponseRedirect(self.get_success_url())
        raise Http404
