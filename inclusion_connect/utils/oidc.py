OIDC_SESSION_KEY = "oidc_params"


def oidc_params(request):
    return request.session.get(OIDC_SESSION_KEY, {})


def initial_from_login_hint(request):
    try:
        return {"email": oidc_params(request)["login_hint"]}
    except KeyError:
        return {}
