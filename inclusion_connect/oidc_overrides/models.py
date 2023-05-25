from urllib.parse import urlparse

from django.conf import settings
from django.db import models
from oauth2_provider.models import AbstractApplication, redirect_to_uri_allowed


def check_uri(allowed_uris, uri):
    for allowed_uri in allowed_uris:
        if allowed_uri == "*":
            continue
        path = urlparse(allowed_uri).path
        if path and path[-1] == "*" and uri.startswith(allowed_uri[:-1]):
            return True
    return False


class Application(AbstractApplication):
    skip_authorization = True

    # FIXME: Remove when bumping django-oauth-toolkit
    post_logout_redirect_uris = models.TextField(
        blank=True,
        help_text="Allowed Post Logout URIs list, space separated",
    )

    def redirect_uri_allowed(self, uri):
        """
        Checks if given url is one of the items in :attr:`redirect_uris` string

        :param uri: Url to check
        """

        if settings.ALLOW_ALL_REDIRECT_URIS:
            return True

        # Else check default implementation
        if super().redirect_uri_allowed(uri):
            return True

        # Check if path ends with wildcard
        return check_uri(self.redirect_uris.split(), uri)

    def post_logout_redirect_uri_allowed(self, uri):
        """
        Checks if given url is one of the items in :attr:`redirect_uris` string

        :param uri: Url to check
        """

        if settings.ALLOW_ALL_REDIRECT_URIS:
            return True

        # Else check default implementation
        # FIXME use super when bumping django-oauth-toolkit
        # if super().post_logout_redirect_uri_allowed(uri):
        if redirect_to_uri_allowed(uri, self.post_logout_redirect_uris.split()):
            return True

        # Check if path ends with wildcard
        return check_uri(self.post_logout_redirect_uris.split(), uri)
