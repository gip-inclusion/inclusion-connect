from urllib.parse import urlparse

from django.conf import settings
from oauth2_provider.models import AbstractApplication


class Application(AbstractApplication):
    skip_authorization = True

    def check_uri(self, allowed_uris, uri, method_name):
        parsed_uri = urlparse(uri)
        for allowed_uri in allowed_uris:
            # Is there a wildcard in the hostname ?
            parsed_allowed_uri = urlparse(allowed_uri)
            if "*" not in parsed_allowed_uri.hostname:
                continue  # No

            prefix, postfix = parsed_allowed_uri.hostname.split("*")
            if not parsed_uri.hostname.startswith(prefix):
                continue
            if not parsed_uri.hostname.endswith(postfix):
                continue
            if len(prefix) + len(postfix) > len(parsed_uri.hostname):
                # Part of the subdomain is in both prefix and postfix, it means it's not the correct allowed uri
                continue

            # Build parsed_uri with the wildcard in it
            middle_value = parsed_uri.hostname[len(prefix) : -len(postfix)]
            # Is the wildcard in the subdomain ?
            if "." in prefix or "." in middle_value:
                continue

            wild_uri = uri.replace(middle_value, "*")
            # Check if the uri in witch we replaced the subdomain with
            # # the one with a wildcard is allowed
            if getattr(super(), method_name)(wild_uri):
                return True
        return False

    def redirect_uri_allowed(self, uri):
        if settings.ALLOW_ALL_REDIRECT_URIS:
            return True

        # Else check default implementation
        if super().redirect_uri_allowed(uri):
            return True

        # Check if path ends with wildcard
        return self.check_uri(self.redirect_uris.split(), uri, "redirect_uri_allowed")

    def post_logout_redirect_uri_allowed(self, uri):
        if settings.ALLOW_ALL_REDIRECT_URIS:
            return True

        # Else check default implementation
        if super().post_logout_redirect_uri_allowed(uri):
            return True

        # Check if path ends with wildcard
        return self.check_uri(self.post_logout_redirect_uris.split(), uri, "post_logout_redirect_uri_allowed")
