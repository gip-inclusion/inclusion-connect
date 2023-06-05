from urllib.parse import urlparse

from django.conf import settings
from oauth2_provider.models import AbstractApplication


def check_uri(allowed_uris, uri):
    for allowed_uri in allowed_uris:
        if allowed_uri == "*":
            continue
        allowed_path = urlparse(allowed_uri).path
        if allowed_path and allowed_path[-1] == "*" and uri.startswith(allowed_uri[:-1]):
            return True
    return False


class Application(AbstractApplication):
    skip_authorization = True

    def redirect_uri_allowed(self, uri):
        if settings.ALLOW_ALL_REDIRECT_URIS:
            return True

        # Else check default implementation
        if super().redirect_uri_allowed(uri):
            return True

        # Check if path ends with wildcard
        return check_uri(self.redirect_uris.split(), uri)

    def post_logout_redirect_uri_allowed(self, uri):
        if settings.ALLOW_ALL_REDIRECT_URIS:
            return True

        # Else check default implementation
        if super().post_logout_redirect_uri_allowed(uri):
            return True

        # Check if path ends with wildcard
        return check_uri(self.post_logout_redirect_uris.split(), uri)
