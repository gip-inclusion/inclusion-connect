from django.contrib.auth import get_user
from django.urls import reverse

from inclusion_connect.auth.backends import EmailAuthenticationBackend
from tests.users.factories import DEFAULT_PASSWORD, UserFactory


def test_admin_login(client):
    user = UserFactory(is_superuser=True, is_staff=True)
    admin_login_url = reverse("admin:login")
    response = client.get(admin_login_url)
    # Admin login form uses username
    assert "username" in response.context["form"].fields

    response = client.post(admin_login_url, data={"username": user.email, "password": DEFAULT_PASSWORD})
    assert get_user(client).is_authenticated is True


def test_authentication_backend_with_username():
    # We still use the email, but we accept it as username kwarg
    user = UserFactory()
    assert EmailAuthenticationBackend().authenticate(request=None, username=user.email, password=DEFAULT_PASSWORD)


def test_authentication_backend_with_email():
    user = UserFactory()
    assert EmailAuthenticationBackend().authenticate(request=None, email=user.email, password=DEFAULT_PASSWORD)
