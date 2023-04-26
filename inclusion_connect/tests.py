# Functional tests for all documented customer processes
import re
import uuid

import jwt
from django.contrib import messages
from django.contrib.auth import get_user
from django.core import mail
from django.urls import reverse
from oauth2_provider.models import get_access_token_model, get_id_token_model, get_refresh_token_model
from pytest_django.asserts import assertContains, assertRedirects

from inclusion_connect.oidc_overrides.factories import DEFAULT_CLIENT_SECRET, ApplicationFactory, default_client_secret
from inclusion_connect.users.factories import DEFAULT_PASSWORD, UserFactory
from inclusion_connect.users.models import User
from inclusion_connect.utils.urls import add_url_params, get_url_params


OIDC_PARAMS = {
    "response_type": "code",
    "client_id": "my_application",
    "redirect_uri": "http://localhost/callback",
    "scope": "openid profile email",
    "state": "state",
    "nonce": "nonce",
}


def oidc_flow_followup(client, auth_response_params, user):
    # Call TOKEN endpoint
    # FIXME it's recommanded to use basic auth here, maybe update our documentation ?
    token_data = {
        "client_id": OIDC_PARAMS["client_id"],
        "client_secret": DEFAULT_CLIENT_SECRET,
        "code": auth_response_params["code"],
        "grant_type": "authorization_code",
        "redirect_uri": OIDC_PARAMS["redirect_uri"],
    }
    response = client.post(reverse("oauth2_provider:token"), data=token_data)

    token_json = response.json()
    id_token = token_json["id_token"]
    decoded_id_token = jwt.decode(
        id_token,
        key=default_client_secret(),
        algorithms=["HS256"],
        audience=OIDC_PARAMS["client_id"],
    )
    assert decoded_id_token["nonce"] == OIDC_PARAMS["nonce"]
    assert decoded_id_token["sub"] == str(user.pk)
    assert uuid.UUID(decoded_id_token["sub"]), "Sub should be an uuid"
    assert decoded_id_token["given_name"] == user.first_name
    assert decoded_id_token["family_name"] == user.last_name
    assert decoded_id_token["email"] == user.email

    # Call USER INFO endpoint
    response = client.get(
        reverse("oauth2_provider:user-info"),
        HTTP_AUTHORIZATION=f"Bearer {token_json['access_token']}",
    )
    assert response.json() == {
        "sub": str(user.pk),
        "given_name": user.first_name,
        "family_name": user.last_name,
        "email": user.email,
    }

    return token_json["id_token"]


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


def test_logout_no_confirmation_get(client):
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
    response = client.get(add_url_params(reverse("oidc_overrides:logout"), logout_params))
    assert not get_user(client).is_authenticated
    assert get_id_token_model().objects.count() == 0
    assert get_access_token_model().objects.count() == 0
    assert get_refresh_token_model().objects.get().revoked is not None


def test_logout_no_confirmation_post(client):
    # FIXME: currently not working
    pass


def test_logout_with_confirmation(client):
    # FIXME: currently not working
    pass
