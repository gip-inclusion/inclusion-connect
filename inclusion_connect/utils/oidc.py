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
    if not next_url:
        try:
            return request.session["next_url"]
        except KeyError:
            return reverse("accounts:edit_user_info")
    return next_url
