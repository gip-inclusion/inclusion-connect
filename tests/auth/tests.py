from django.contrib.auth import get_user
from django.urls import reverse
from pytest_django.asserts import assertRedirects, assertTemplateUsed

from inclusion_connect.auth.backends import EmailAuthenticationBackend
from tests.users.factories import DEFAULT_PASSWORD, UserFactory


def test_admin_login(client):
    admin_login_url = reverse("admin_login")
    response = client.get(reverse("admin:index"), follow=True)
    assertRedirects(response, admin_login_url + "?next=/admin/")
    assertTemplateUsed(response, "login.html")

    user = UserFactory(is_superuser=True, is_staff=True)
    response = client.post(admin_login_url, data={"email": user.email, "password": DEFAULT_PASSWORD})
    assert get_user(client).is_authenticated is True


def test_authentication_backend_with_username():
    # We still use the email, but we accept it as username kwarg
    user = UserFactory()
    assert EmailAuthenticationBackend().authenticate(request=None, username=user.email, password=DEFAULT_PASSWORD)


def test_authentication_backend_with_email():
    user = UserFactory()
    assert EmailAuthenticationBackend().authenticate(request=None, email=user.email, password=DEFAULT_PASSWORD)
