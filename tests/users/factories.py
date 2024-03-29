import functools

import factory
from django.contrib.auth.hashers import make_password
from django.utils import timezone

from inclusion_connect.users.models import EmailAddress, User


DEFAULT_PASSWORD = "P4ssw0rd!***"


@functools.cache
def default_password():
    return make_password(DEFAULT_PASSWORD)


class EmailAddressFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = EmailAddress

    user = factory.SubFactory(
        "tests.users.factories.UserFactory",
        email_address=False,
        email=factory.Maybe(
            decider=factory.SelfAttribute("..verified_at"),
            yes_declaration=factory.SelfAttribute("..email"),
            no_declaration="",
        ),
    )
    email = factory.Sequence("email{}@domain.com".format)


class UserFactory(factory.django.DjangoModelFactory):
    """Generates User() objects for unit tests."""

    class Meta:
        model = User
        skip_postgeneration_save = True

    first_name = factory.Faker("first_name")
    last_name = factory.Faker("last_name")
    email = factory.Sequence("email{}@domain.com".format)
    password = factory.LazyFunction(default_password)
    terms_accepted_at = factory.LazyFunction(timezone.now)

    @factory.post_generation
    def email_address(obj, create, extracted, **kwargs):
        if create and extracted is None and obj.email:
            EmailAddressFactory(user=obj, email=obj.email, verified_at=timezone.now(), **kwargs)
