from django.urls import reverse

from inclusion_connect.utils.urls import get_url_params


OIDC_SESSION_KEY = "oidc_params"


def oidc_params(request, next_url=None):
    session_params = request.session.get(OIDC_SESSION_KEY, {})
    if not session_params and next_url:
        if next_url.startswith(reverse("oauth2_provider:authorize")):
            return get_url_params(next_url)
    return session_params


def initial_from_login_hint(request):
    login_hint = oidc_params(request).get("login_hint")
    if login_hint:
        return {"email": login_hint}
    if next_url := request.GET.get("next"):
        if login_hint := get_url_params(next_url).get("login_hint"):
            return {"email": login_hint}
    return {}
