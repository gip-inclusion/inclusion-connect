import factory

from inclusion_connect.oidc_overrides.models import Application


class ApplicationFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = Application

    redirect_uris = "http://testserver/callback"
    post_logout_redirect_uris = "http://testserver/logout_callback"
    client_type = Application.CLIENT_CONFIDENTIAL
    authorization_grant_type = Application.GRANT_AUTHORIZATION_CODE
    name = factory.Faker("company", locale="fr_FR")
    algorithm = Application.HS256_ALGORITHM
    client_id = factory.Sequence("client_#{}".format)
    hash_client_secret = False
