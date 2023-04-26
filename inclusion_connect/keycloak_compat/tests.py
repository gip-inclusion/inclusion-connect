import uuid

import jwt
import pytest
from django.contrib.auth import get_user
from django.contrib.auth.hashers import PBKDF2PasswordHasher
from django.urls import reverse
from oauth2_provider.models import get_access_token_model, get_id_token_model, get_refresh_token_model
from pytest_django.asserts import assertRedirects

from inclusion_connect.keycloak_compat.hashers import KeycloakPasswordHasher
from inclusion_connect.oidc_overrides.factories import DEFAULT_CLIENT_SECRET, ApplicationFactory, default_client_secret
from inclusion_connect.users.factories import UserFactory
from inclusion_connect.utils.urls import add_url_params, get_url_params


@pytest.mark.parametrize("realm", ["local", "Review_apps", "Demo", "inclusion-connect"])
def test_login(client, realm):
    application = ApplicationFactory()
    user = UserFactory()

    # Test AUTH endpoint when not authenticated
    auth_url = reverse(f"keycloak_compat_{realm}:authorize")
    auth_params = {
        "response_type": "code",
        "client_id": application.client_id,
        "redirect_uri": "http://localhost/callback",
        "scope": "openid profile email",
        "state": "state",
        "nonce": "nonce",
    }
    auth_complete_url = add_url_params(auth_url, auth_params)
    response = client.get(auth_complete_url)
    assertRedirects(response, reverse("accounts:login"))
    assert client.session["next_url"] == auth_complete_url

    # Test AUTH endpoint when not authenticated and with bad params
    bad_auth_params = auth_params.copy()
    bad_auth_params["client_id"] = "toto"
    bad_auth_complete_url = add_url_params(auth_url, bad_auth_params)
    response = client.get(bad_auth_complete_url)
    # FIXME update the template
    assert response.status_code == 400

    # Test AUTH endpoint when authenticated
    client.force_login(user)
    response = client.get(auth_complete_url)
    assert response.status_code == 302
    assert response.url.startswith(auth_params["redirect_uri"])
    auth_response_params = get_url_params(response.url)

    # Test TOKEN endpoint
    # FIXME it's recommanded to use basic auth here, maybe update our documentation ?
    token_data = {
        "client_id": application.client_id,
        "client_secret": DEFAULT_CLIENT_SECRET,
        "code": auth_response_params["code"],
        "grant_type": "authorization_code",
        "redirect_uri": "http://localhost/callback",
    }
    response = client.post(
        reverse(f"keycloak_compat_{realm}:token"),
        data=token_data,
    )
    token_json = response.json()
    id_token = token_json["id_token"]
    decoded_id_token = jwt.decode(
        id_token,
        key=default_client_secret(),
        algorithms=["HS256"],
        audience=application.client_id,
    )
    assert decoded_id_token["nonce"] == auth_params["nonce"]
    assert decoded_id_token["sub"] == str(user.pk)
    assert uuid.UUID(decoded_id_token["sub"]), "Sub should be an uuid"
    assert decoded_id_token["given_name"] == user.first_name
    assert decoded_id_token["family_name"] == user.last_name
    assert decoded_id_token["email"] == user.email

    # Test USER INFO endpoint
    response = client.get(
        reverse(f"keycloak_compat_{realm}:user-info"),
        HTTP_AUTHORIZATION=f"Bearer {token_json['access_token']}",
    )
    assert response.json() == {
        "sub": str(user.pk),
        "given_name": user.first_name,
        "family_name": user.last_name,
        "email": user.email,
    }

    # Test LOGOUT endpoint
    assert get_user(client).is_authenticated
    logout_params = {"id_token_hint": id_token}
    response = client.get(add_url_params(reverse(f"keycloak_compat_{realm}:logout"), logout_params))
    assert not get_user(client).is_authenticated
    assert get_id_token_model().objects.count() == 0
    assert get_access_token_model().objects.count() == 0
    assert get_refresh_token_model().objects.get().revoked is not None


@pytest.mark.parametrize("realm", ["local", "Review_apps", "Demo", "inclusion-connect"])
def test_registration(client, realm):
    application = ApplicationFactory()
    user = UserFactory()

    # Test REGISTRATIONS endpoint when not authenticated
    auth_url = reverse(f"keycloak_compat_{realm}:registrations")
    auth_params = {
        "response_type": "code",
        "client_id": application.client_id,
        "redirect_uri": "http://localhost/callback",
        "scope": "openid profile email",
        "state": "state",
        "nonce": "nonce",
    }
    auth_complete_url = add_url_params(auth_url, auth_params)
    response = client.get(auth_complete_url)
    assertRedirects(response, reverse("accounts:registration"))
    assert client.session["next_url"] == auth_complete_url

    # Test REGISTRATIONS endpoint when not authenticated and with bad oidc params
    bad_auth_params = auth_params.copy()
    bad_auth_params["client_id"] = "toto"
    bad_auth_complete_url = add_url_params(auth_url, bad_auth_params)
    response = client.get(bad_auth_complete_url)
    # FIXME update the template
    assert response.status_code == 400

    # Test REGISTRATIONS endpoint when not authenticated with activation params
    activation_params = auth_params | {
        "login_hint": "email",
        "firstname": "John",
        "lastname": "Doe",
    }
    auth_complete_url = add_url_params(auth_url, activation_params)
    response = client.get(auth_complete_url, follow=True)
    assertRedirects(response, reverse("accounts:activation"))
    assert client.session["next_url"] == auth_complete_url

    # Test REGISTRATIONS endpoint when authenticated
    client.force_login(user)
    response = client.get(auth_complete_url)
    assert response.status_code == 302
    assert response.url.startswith(auth_params["redirect_uri"])
    auth_response_params = get_url_params(response.url)

    # Test TOKEN endpoint
    # FIXME it's recommanded to use basic auth here, maybe update our documentation ?
    token_data = {
        "client_id": application.client_id,
        "client_secret": DEFAULT_CLIENT_SECRET,
        "code": auth_response_params["code"],
        "grant_type": "authorization_code",
        "redirect_uri": "http://localhost/callback",
    }
    response = client.post(
        reverse(f"keycloak_compat_{realm}:token"),
        data=token_data,
    )
    token_json = response.json()
    id_token = token_json["id_token"]
    decoded_id_token = jwt.decode(
        id_token,
        key=default_client_secret(),
        algorithms=["HS256"],
        audience=application.client_id,
    )
    assert decoded_id_token["nonce"] == auth_params["nonce"]
    assert decoded_id_token["sub"] == str(user.pk)
    assert uuid.UUID(decoded_id_token["sub"]), "Sub should be an uuid"
    assert decoded_id_token["given_name"] == user.first_name
    assert decoded_id_token["family_name"] == user.last_name
    assert decoded_id_token["email"] == user.email

    # Test USER INFO endpoint
    response = client.get(
        reverse(f"keycloak_compat_{realm}:user-info"),
        HTTP_AUTHORIZATION=f"Bearer {token_json['access_token']}",
    )
    assert response.json() == {
        "sub": str(user.pk),
        "given_name": user.first_name,
        "family_name": user.last_name,
        "email": user.email,
    }

    # Test LOGOUT endpoint
    assert get_user(client).is_authenticated
    logout_params = {"id_token_hint": id_token}
    response = client.get(add_url_params(reverse(f"keycloak_compat_{realm}:logout"), logout_params))
    assert not get_user(client).is_authenticated
    assert get_id_token_model().objects.count() == 0
    assert get_access_token_model().objects.count() == 0
    assert get_refresh_token_model().objects.get().revoked is not None


def test_password_hasher(client):
    password = "RdaRfqP7Y89vy2"
    hashed_password = "$".join(
        [
            "keycloak-pbkdf2-sha256",
            "27500",
            "Td6XuopYK6JNfUnIlqYMOQ==",
            "ZXVC08Hf4jBOoYzVoNWYjQijsMC2oc/OUa9LciiIJ/1XHPF/qPiY1DqwLLDN2hYFmf/1kApkveD8/Pr7GVqjgw==",
        ]
    )
    user = UserFactory(password=hashed_password)
    assert user.password == hashed_password

    assert KeycloakPasswordHasher().verify(password=password, encoded=hashed_password)

    client.login(email=user.email, password=password)

    user.refresh_from_db()
    assert user.password != hashed_password
    assert PBKDF2PasswordHasher().verify(password, encoded=user.password)
