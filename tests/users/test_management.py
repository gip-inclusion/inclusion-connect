import pytest
from django.core.management import call_command

from inclusion_connect.users.models import User


@pytest.mark.django_db
def test_createsuperuser_generates_uuid_username():
    call_command("createsuperuser", "--noinput", email="admin@example.com")
    user = User.objects.get(email="admin@example.com")
    assert user.is_superuser
    assert user.username is not None
