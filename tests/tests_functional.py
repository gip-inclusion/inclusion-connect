# Functional tests for all documented customer processes
import re

import pytest
from django.contrib import messages
from django.contrib.auth import get_user
from django.core import mail
from django.urls import reverse
from pytest_django.asserts import assertContains, assertRedirects

from inclusion_connect.users.models import User
from inclusion_connect.utils.urls import add_url_params, get_url_params
from tests.asserts import assertMessages
from tests.helpers import OIDC_PARAMS, oidc_flow_followup, token_are_revoked
from tests.oidc_overrides.factories import ApplicationFactory
from tests.users.factories import DEFAULT_PASSWORD, UserFactory


def test_registration_endpoint(client):
    ApplicationFactory(client_id=OIDC_PARAMS["client_id"])
    user = UserFactory.build()

    auth_url = reverse("oidc_overrides:registrations")
    auth_complete_url = add_url_params(auth_url, OIDC_PARAMS)
    response = client.get(auth_complete_url)
    assertRedirects(response, reverse("accounts:register"))

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
    assertRedirects(response, reverse("accounts:activate"))

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

    assertMessages(
        response,
        [
            (
                messages.SUCCESS,
                "Si un compte existe avec cette adresse e-mail, "
                "vous recevrez un e-mail contenant des instructions pour réinitialiser votre mot de passe.",
            )
        ],
    )

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


def test_edit_user_info_and_password(client):
    user = UserFactory()
    referrer_uri = "https://go/back/there"
    edit_user_info_url = add_url_params(reverse("accounts:edit_user_info"), {"referrer_uri": referrer_uri})
    change_password_url = add_url_params(reverse("accounts:change_password"), {"referrer_uri": referrer_uri})

    # User is redirected to login
    response = client.get(edit_user_info_url)
    assertRedirects(response, add_url_params(reverse("accounts:login"), {"next": edit_user_info_url}))
    response = client.post(response.url, data={"email": user.email, "password": DEFAULT_PASSWORD}, follow=True)
    assertRedirects(response, edit_user_info_url)
    assertContains(response, "<h1>\n                Informations générales\n            </h1>")

    # Page contains return to referrer link
    assertContains(response, "Retour")
    assertContains(response, referrer_uri)

    # Edit user info
    response = client.post(
        edit_user_info_url,
        data={"last_name": "Doe", "first_name": "John", "email": "my@email.com"},
    )
    user.refresh_from_db()
    assert user.first_name == "John"
    assert user.last_name == "Doe"
    assert user.email == "my@email.com"
    assertRedirects(response, edit_user_info_url)

    # Go change password
    response = client.get(change_password_url)
    assertContains(response, "<h1>\n                Changer mon mot de passe\n            </h1>")
    response = client.post(
        change_password_url,
        data={"old_password": DEFAULT_PASSWORD, "new_password1": "toto", "new_password2": "toto"},
    )
    assert get_user(client).is_authenticated is True

    client.logout()
    assert get_user(client).is_authenticated is False

    # User may login with new password
    response = client.post(reverse("accounts:login"), data={"email": user.email, "password": "toto"}, follow=True)
    assert get_user(client).is_authenticated is True
