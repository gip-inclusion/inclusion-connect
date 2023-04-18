from oauth2_provider.models import AbstractApplication


class Application(AbstractApplication):
    skip_authorization = True
