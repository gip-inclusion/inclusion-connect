# Functional tests for all documented customer processes
import re

import pytest
from django.contrib import messages
from django.contrib.auth import get_user
from django.core import mail
from django.urls import reverse
from pytest_django.asserts import assertContains, assertRedirects

from inclusion_connect.oidc_overrides.factories import ApplicationFactory
from inclusion_connect.test import OIDC_PARAMS, oidc_flow_followup, token_are_revoked
from inclusion_connect.users.factories import DEFAULT_PASSWORD, UserFactory
from inclusion_connect.users.models import User
from inclusion_connect.utils.urls import add_url_params, get_url_params


def test_registration_endpoint(client):
    ApplicationFactory(client_id=OIDC_PARAMS["client_id"])
    user = UserFactory.build()

    auth_url = reverse("oidc_overrides:registrations")
    auth_complete_url = add_url_params(auth_url, OIDC_PARAMS)
    response = client.get(auth_complete_url)
    assertRedirects(response, reverse("accounts:registration"))

    response = client.post(
        response.url,
        data={
            "email": user.email,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "password1": DEFAULT_PASSWORD,
            "password2": DEFAULT_PASSWORD,
            "terms_accepted": "on",
        },
    )
    assertRedirects(response, auth_complete_url, fetch_redirect_response=False)
    assert get_user(client).is_authenticated is True
    user = User.objects.get(email=user.email)
    assert user.linked_applications.count() == 0

    response = client.get(auth_complete_url)
    assert response.status_code == 302
    assert response.url.startswith(OIDC_PARAMS["redirect_uri"])
    auth_response_params = get_url_params(response.url)
    assert user.linked_applications.count() == 1

    oidc_flow_followup(client, auth_response_params, user)


def test_activation_endpoint(client):
    ApplicationFactory(client_id=OIDC_PARAMS["client_id"])
    user = UserFactory.build()

    auth_url = reverse("oidc_overrides:activation")
    auth_complete_url = add_url_params(auth_url, OIDC_PARAMS)
    response = client.get(auth_complete_url, follow=True)
    assert response.status_code == 400

    auth_url = reverse("oidc_overrides:activation")
    auth_params = OIDC_PARAMS | {"email": "email", "firstname": "firstname", "lastname": "lastname"}
    auth_complete_url = add_url_params(auth_url, auth_params)
    response = client.get(auth_complete_url)
    assertRedirects(response, reverse("accounts:activation"))

    response = client.post(
        response.url,
        data={
            "email": user.email,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "password1": DEFAULT_PASSWORD,
            "password2": DEFAULT_PASSWORD,
            "terms_accepted": "on",
        },
    )
    assertRedirects(response, auth_complete_url, fetch_redirect_response=False)
    assert get_user(client).is_authenticated is True
    user = User.objects.get(email=user.email)
    assert user.linked_applications.count() == 0

    response = client.get(auth_complete_url)
    assert response.status_code == 302
    assert response.url.startswith(OIDC_PARAMS["redirect_uri"])
    auth_response_params = get_url_params(response.url)
    assert user.linked_applications.count() == 1

    oidc_flow_followup(client, auth_response_params, user)


def test_login_endpoint(client):
    ApplicationFactory(client_id=OIDC_PARAMS["client_id"])
    user = UserFactory()

    auth_url = reverse("oidc_overrides:authorize")
    auth_complete_url = add_url_params(auth_url, OIDC_PARAMS)
    response = client.get(auth_complete_url)
    assertRedirects(response, reverse("accounts:login"))

    response = client.post(
        response.url,
        data={
            "email": user.email,
            "password": DEFAULT_PASSWORD,
        },
    )
    assertRedirects(response, auth_complete_url, fetch_redirect_response=False)
    assert get_user(client).is_authenticated is True
    user = User.objects.get(email=user.email)
    assert user.linked_applications.count() == 0

    response = client.get(auth_complete_url)
    assert response.status_code == 302
    assert response.url.startswith(OIDC_PARAMS["redirect_uri"])
    auth_response_params = get_url_params(response.url)
    assert user.linked_applications.count() == 1

    oidc_flow_followup(client, auth_response_params, user)


def test_login_after_password_reset(client):
    ApplicationFactory(client_id=OIDC_PARAMS["client_id"])
    user = UserFactory()

    auth_url = reverse("oidc_overrides:authorize")
    auth_complete_url = add_url_params(auth_url, OIDC_PARAMS)
    response = client.get(auth_complete_url)
    assertRedirects(response, reverse("accounts:login"))

    response = client.get(response.url)
    assertContains(response, reverse("accounts:password_reset"))

    response = client.post(reverse("accounts:password_reset"), data={"email": user.email})
    assertRedirects(response, reverse("accounts:login"))

    assert list(messages.get_messages(response.wsgi_request)) == [
        messages.storage.base.Message(
            messages.SUCCESS,
            "Si un compte existe avec cette adresse e-mail, "
            "vous recevrez un e-mail contenant des instructions pour réinitialiser votre mot de passe.",
        ),
    ]

    reset_url_regex = reverse("accounts:password_reset_confirm", args=("string", "string")).replace("string", "[^/]*")
    reset_url = re.search(reset_url_regex, mail.outbox[0].body)[0]
    response = client.get(reset_url)  # retrieve the modified url
    response = client.post(response.url, data={"new_password1": "password", "new_password2": "password"})
    assertRedirects(response, auth_complete_url, fetch_redirect_response=False)
    assert get_user(client).is_authenticated is True

    response = client.get(auth_complete_url)
    assert response.status_code == 302
    assert response.url.startswith(OIDC_PARAMS["redirect_uri"])
    auth_response_params = get_url_params(response.url)

    oidc_flow_followup(client, auth_response_params, user)


@pytest.mark.parametrize("method", ["get", "post"])
def test_logout_no_confirmation(client, method):
    """Logout without confirmation requires the id_token"""

    user = UserFactory()
    ApplicationFactory(client_id=OIDC_PARAMS["client_id"])

    auth_url = reverse("oidc_overrides:authorize")
    auth_complete_url = add_url_params(auth_url, OIDC_PARAMS)
    response = client.get(auth_complete_url)
    assertRedirects(response, reverse("accounts:login"))

    response = client.post(response.url, data={"email": user.email, "password": DEFAULT_PASSWORD})
    assert get_user(client).is_authenticated is True
    response = client.get(response.url)
    auth_response_params = get_url_params(response.url)
    id_token = oidc_flow_followup(client, auth_response_params, user)

    assert get_user(client).is_authenticated is True
    logout_params = {"id_token_hint": id_token}
    logout_method = getattr(client, method)
    response = logout_method(add_url_params(reverse("oidc_overrides:logout"), logout_params))
    assert not get_user(client).is_authenticated
    assert token_are_revoked(user)

    response = client.get(auth_complete_url)
    assertRedirects(response, reverse("accounts:login"))


def test_logout_with_confirmation(client):
    # FIXME: currently not working
    pass
