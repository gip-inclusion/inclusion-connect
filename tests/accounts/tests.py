import logging

import pytest
from django.contrib.auth import get_user
from django.urls import reverse
from pytest_django.asserts import (
    assertContains,
    assertRedirects,
    assertTemplateUsed,
)

from inclusion_connect.utils.oidc import OIDC_SESSION_KEY
from inclusion_connect.utils.urls import add_url_params
from tests.asserts import assertRecords
from tests.helpers import parse_response_to_soup, pretty_indented
from tests.users.factories import UserFactory


class TestLoginView:
    @pytest.mark.parametrize("is_active", [True, False])
    def test_login(self, caplog, client, is_active):
        redirect_url = reverse("accounts:home")
        login_url = add_url_params(reverse("accounts:login"), {"next": redirect_url})
        user = UserFactory(is_active=is_active)

        response = client.get(login_url)
        response = client.post(login_url, data={"email": user.email}, follow=True)

        assertRedirects(response, redirect_url)
        assert get_user(client).is_authenticated is True
        assertRecords(
            caplog,
            [
                (
                    "inclusion_connect.auth",
                    logging.INFO,
                    {"user": user.email, "event": "login"},
                ),
            ],
        )

    def test_failed_bad_email(self, caplog, client):
        url = add_url_params(reverse("accounts:login"), {"next": "anything"})

        response = client.post(url, data={"email": "bad@email.com"})
        assertTemplateUsed(response, "login.html")
        assertContains(response, "Adresse e-mail invalide.")
        assert not get_user(client).is_authenticated
        assertRecords(
            caplog,
            [
                (
                    "inclusion_connect.auth",
                    logging.INFO,
                    {
                        "email": "bad@email.com",
                        "event": "login_error",
                        "errors": {
                            "__all__": [
                                {
                                    "message": "Adresse e-mail invalide.",
                                    "code": "invalid_login",
                                }
                            ]
                        },
                    },
                )
            ],
        )

    def test_login_hint(self, caplog, client, snapshot):
        redirect_url = reverse("accounts:home")
        url = add_url_params(reverse("accounts:login"), {"next": redirect_url})
        user = UserFactory(email="me@mailinator.com")
        client_session = client.session
        client_session[OIDC_SESSION_KEY] = {
            "login_hint": user.email,
            "firstname": user.first_name,
            "lastname": user.last_name,
        }
        client_session.save()

        response = client.get(url)
        assert pretty_indented(parse_response_to_soup(response, "#main")) == snapshot

    def test_empty_login_hint(self, client, snapshot):
        url = add_url_params(reverse("accounts:login"), {"login_hint": ""})

        response = client.get(url)
        assert pretty_indented(parse_response_to_soup(response, "#main")) == snapshot


class TestLogout:
    def test_logout(self, client):
        user = UserFactory()
        client.force_login(user)
        url = reverse("accounts:logout")

        assert get_user(client).is_authenticated is True

        response = client.get(url)
        assert response.status_code == 405
        assert get_user(client).is_authenticated is True

        response = client.post(url)
        assertRedirects(response, reverse("accounts:login"))
        assert get_user(client).is_authenticated is False
