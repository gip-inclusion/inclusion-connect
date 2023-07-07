from django.conf import settings
from django.contrib import auth


def login(request, user, preserve_url=True, backend=settings.DEFAULT_AUTH_BACKEND):
    """
    Log the user and preserve the next url if required (as login again flushes the session)
    """
    next_url = request.session.get("next_url")
    auth.login(request, user, backend=backend)
    if next_url and preserve_url:
        request.session["next_url"] = next_url
