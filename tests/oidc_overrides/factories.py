import functools

import factory
from django.contrib.auth.hashers import make_password

from inclusion_connect.oidc_overrides.models import Application


DEFAULT_CLIENT_SECRET = "S3cr3t_KeY"


@functools.cache
def default_client_secret():
    return make_password(DEFAULT_CLIENT_SECRET)


class ApplicationFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = Application
        django_get_or_create = ("client_id",)

    redirect_uris = "http://localhost/*"
    post_logout_redirect_uris = "http://callback/"
    client_type = Application.CLIENT_CONFIDENTIAL
    authorization_grant_type = Application.GRANT_AUTHORIZATION_CODE
    name = factory.Faker("company", locale="fr_FR")
    algorithm = Application.HS256_ALGORITHM
    client_secret = default_client_secret()
    client_id = factory.Sequence("client_#{}".format)
