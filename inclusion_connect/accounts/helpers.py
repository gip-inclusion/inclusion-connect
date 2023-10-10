from django.contrib import auth


def login(request, user):
    """
    Log the user and preserve the next url (as login again flushes the session)
    """
    next_url = request.session.get("next_url")
    auth.login(request, user)
    if next_url:
        request.session["next_url"] = next_url
