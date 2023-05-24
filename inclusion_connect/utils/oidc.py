from django.urls import reverse

from inclusion_connect.accounts.middleware import required_action_url


OIDC_SESSION_KEY = "oidc_params"


def oidc_params(request):
    return request.session.get(OIDC_SESSION_KEY, {})


def initial_from_login_hint(request):
    try:
        return {"email": oidc_params(request)["login_hint"]}
    except KeyError:
        return {}


def get_next_url(request):
    next_url = required_action_url(request.user)
    if next_url:
        return next_url
    return request.session.pop("next_url", reverse("accounts:edit_user_info"))
