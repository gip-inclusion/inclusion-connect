import factory
from django.contrib.auth.hashers import make_password

from inclusion_connect.users.models import User


UNUSABLE_PASSWORD = make_password(None)


class UserFactory(factory.django.DjangoModelFactory):
    """Generates User() objects for unit tests."""

    class Meta:
        model = User
        skip_postgeneration_save = True

    first_name = factory.Faker("first_name")
    last_name = factory.Faker("last_name")
    email = factory.Sequence("email{}@inclusion.gouv.fr".format)
    password = UNUSABLE_PASSWORD
