from django.conf import settings
from django.contrib import auth
from django.urls import reverse


LOGGER_NAME = "inclusion_connect.auth"


def login(request, user, backend=settings.DEFAULT_AUTH_BACKEND):
    """
    Log the user and preserve the next url (as login again flushes the session)
    """
    next_url = request.session.get("next_url")
    auth.login(request, user, backend=backend)
    if next_url:
        request.session["next_url"] = next_url


def get_next_url(request, fallback_url=None):
    if not request.user.is_authenticated:
        return None
    session_next_url = request.session.pop("next_url", None)
    return session_next_url or fallback_url or reverse("accounts:home")
