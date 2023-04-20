import uuid

import jwt
import pytest
from django.contrib.auth import get_user
from django.contrib.auth.hashers import PBKDF2PasswordHasher
from django.urls import reverse
from oauth2_provider.models import get_access_token_model, get_id_token_model, get_refresh_token_model
from pytest_django.asserts import assertRedirects

from inclusion_connect.keycloak_compat.hashers import KeycloakPasswordHasher
from inclusion_connect.oidc_overrides.factories import ApplicationFactory
from inclusion_connect.users.factories import DEFAULT_PASSWORD, UserFactory
from inclusion_connect.utils.urls import add_url_params, get_url_params


@pytest.mark.parametrize("realm", ["local", "Review_apps", "Demo", "inclusion-connect"])
def test_keycloak_urls_compat(client, realm):
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
    assertRedirects(response, add_url_params(reverse("accounts:login"), {"next": auth_complete_url}))

    # Test AUTH endpoint when not authenticated and with bad params
    bad_auth_params = auth_params.copy()
    bad_auth_params["client_id"] = "toto"
    bad_auth_complete_url = add_url_params(auth_url, bad_auth_params)
    response = client.get(bad_auth_complete_url)
    # FIXME update the template
    assert response.status_code == 400

    # Test AUTH endpoint when loggin
    client.force_login(user)
    response = client.get(auth_complete_url)
    assert response.status_code == 302
    assert response.url.startswith(auth_params["redirect_uri"])
    auth_response_params = get_url_params(response.url)

    # Test TOKEN endpoint
    # FIXME it's recommanded to use basic auth here, maybe update our documentation ?
    token_data = {
        "client_id": application.client_id,
        "client_secret": DEFAULT_PASSWORD,
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
    decoded_id_token = jwt.decode(id_token, algorithms=["RS256"], options={"verify_signature": False})
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
    assert get_refresh_token_model().objects.get().revoked


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
