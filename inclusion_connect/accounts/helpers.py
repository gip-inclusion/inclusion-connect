from django.contrib import auth


def login(request, user, preserve_url=True):
    """
    Log the user and preserve the next url if required (as login again flushes the session)
    """
    next_url = request.session.get("next_url")
    auth.login(request, user)
    if next_url and preserve_url:
        request.session["next_url"] = next_url
