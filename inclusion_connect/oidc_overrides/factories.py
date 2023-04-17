import factory
from oauth2_provider.models import Application

from inclusion_connect.users.factories import default_password


class ApplicationFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = Application

    redirect_uris = "http://localhost/callback"  # FIXME
    client_type = Application.CLIENT_CONFIDENTIAL
    authorization_grant_type = Application.GRANT_AUTHORIZATION_CODE
    name = factory.Faker("company", locale="fr_FR")
    skip_authorization = True
    algorithm = Application.HS256_ALGORITHM
    client_secret = default_password()
