from functools import lru_cache

from django.urls import reverse

from inclusion_connect.accounts.middleware import required_action_url
from inclusion_connect.utils.urls import get_url_params


OIDC_SESSION_KEY = "oidc_params"


def oidc_params(request, next_url=None):
    session_params = request.session.get(OIDC_SESSION_KEY, {})
    if not session_params and next_url:
        if any(
            next_url.startswith(path)
            for path in [
                reverse("oauth2_provider:authorize"),
                reverse("oauth2_provider:register"),
                reverse("oauth2_provider:activate"),
            ]
        ):
            return get_url_params(next_url)
    return session_params


def initial_from_login_hint(request):
    login_hint = oidc_params(request).get("login_hint")
    if login_hint:
        return {"email": login_hint}
    return {}


@lru_cache
def get_next_url(request):
    if not request.user.is_authenticated:
        return None
    next_url = required_action_url(request.user)
    if next_url:
        return next_url
    session_next_url = request.session.pop("next_url", None)
    user_next_url = request.user.pop_next_redirect_uri()
    return session_next_url or user_next_url or reverse("accounts:edit_user_info")
