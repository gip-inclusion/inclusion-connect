from oauth2_provider.models import AbstractApplication


class Application(AbstractApplication):
    skip_authorization = True

    def redirect_uri_allowed(self, uri):
        """
        Checks if given url is one of the items in :attr:`redirect_uris` string

        :param uri: Url to check
        """

        # Enable full wildcard
        if "*" in self.redirect_uris.split():
            return True

        # Else check default implementation
        if super().redirect_uri_allowed(uri):
            return True

        # Check if path ends with wildcard
        for allowed_uri in self.redirect_uris.split():
            if allowed_uri[-1] == "*" and uri.startswith(allowed_uri[:-1]):
                return True
        return False
