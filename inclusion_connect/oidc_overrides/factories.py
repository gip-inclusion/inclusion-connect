import factory

from inclusion_connect.oidc_overrides.models import Application
from inclusion_connect.users.factories import default_password


class ApplicationFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = Application

    redirect_uris = "http://localhost/*"
    client_type = Application.CLIENT_CONFIDENTIAL
    authorization_grant_type = Application.GRANT_AUTHORIZATION_CODE
    name = factory.Faker("company", locale="fr_FR")
    algorithm = Application.HS256_ALGORITHM
    client_secret = default_password()
