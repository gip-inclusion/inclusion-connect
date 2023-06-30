from django.conf import settings
from django.contrib import auth


def login(request, user, backend=settings.DEFAULT_AUTH_BACKEND):
    """
    Log the user and preserve the next url (as login again flushes the session)
    """
    next_url = request.session.get("next_url")
    auth.login(request, user, backend=backend)
    if next_url:
        request.session["next_url"] = next_url
