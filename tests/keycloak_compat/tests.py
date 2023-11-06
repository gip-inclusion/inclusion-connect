import datetime
import logging
import uuid

import jwt
import pytest
from django.contrib import messages
from django.contrib.auth import get_user
from django.contrib.auth.hashers import PBKDF2PasswordHasher
from django.urls import reverse
from django.utils import http, timezone
from freezegun import freeze_time
from pytest_django.asserts import assertContains, assertRedirects

from inclusion_connect.accounts.views import EMAIL_CONFIRM_KEY
from inclusion_connect.keycloak_compat.hashers import KeycloakPasswordHasher
from inclusion_connect.keycloak_compat.models import JWTHashSecret
from inclusion_connect.users.models import EmailAddress
from inclusion_connect.utils.urls import add_url_params, get_url_params
from tests.asserts import assertMessages, assertRecords
from tests.helpers import token_are_revoked
from tests.oidc_overrides.factories import DEFAULT_CLIENT_SECRET, ApplicationFactory, default_client_secret
from tests.users.factories import DEFAULT_PASSWORD, UserFactory


@pytest.mark.parametrize("realm", ["local", "Review_apps", "Demo", "inclusion-connect"])
def test_login(client, realm, caplog):
    application = ApplicationFactory()
    user = UserFactory()

    # Test AUTH endpoint when not authenticated
    auth_url = f"/realms/{realm}/protocol/openid-connect/auth"
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

    assertRecords(
        caplog,
        [
            (
                "keycloak_compat",
                logging.WARNING,
                {"application": application.client_id, "url": f"/realms/{realm}/protocol/openid-connect/auth"},
            ),
        ],
    )

    # Test AUTH endpoint when not authenticated and with bad params
    bad_auth_params = auth_params.copy()
    bad_auth_params["client_id"] = "toto"
    bad_auth_complete_url = add_url_params(auth_url, bad_auth_params)
    response = client.get(bad_auth_complete_url)
    assert response.status_code == 400

    assertRecords(
        caplog,
        [
            (
                "keycloak_compat",
                logging.WARNING,
                {"application": application.client_id, "url": f"/realms/{realm}/protocol/openid-connect/auth"},
            ),
            ("django.request", logging.WARNING, f"Bad Request: /realms/{realm}/protocol/openid-connect/auth"),
            (
                "inclusion_connect.oidc",
                logging.INFO,
                {
                    "application": application.client_id,
                    "event": "oidc_params_error",
                    "oidc_params": {
                        "response_type": "code",
                        "client_id": "toto",
                        "redirect_uri": "http://localhost/callback",
                        "scope": "openid profile email",
                        "state": "state",
                        "nonce": "nonce",
                    },
                },
            ),
        ],
    )

    # Test AUTH endpoint when authenticated
    client.force_login(user)
    response = client.get(auth_complete_url)
    assert response.status_code == 302
    assert response.url.startswith(auth_params["redirect_uri"])
    auth_response_params = get_url_params(response.url)

    assertRecords(
        caplog,
        [
            (
                "keycloak_compat",
                logging.WARNING,
                {"application": application.client_id, "url": f"/realms/{realm}/protocol/openid-connect/auth"},
            ),
            (
                "inclusion_connect.oidc",
                logging.INFO,
                {
                    "application": application.client_id,
                    "event": "redirect",
                    "user": user.username,
                    "url": f"http://localhost/callback?code={auth_response_params['code']}&state=state",
                },
            ),
        ],
    )

    # Test TOKEN endpoint
    token_data = {
        "client_id": application.client_id,
        "client_secret": DEFAULT_CLIENT_SECRET,
        "code": auth_response_params["code"],
        "grant_type": "authorization_code",
        "redirect_uri": "http://localhost/callback",
    }
    response = client.post(
        f"/realms/{realm}/protocol/openid-connect/token",
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
        f"/realms/{realm}/protocol/openid-connect/userinfo",
        headers={"Authorization": f"Bearer {token_json['access_token']}"},
    )
    assert response.json() == {
        "sub": str(user.pk),
        "given_name": user.first_name,
        "family_name": user.last_name,
        "email": user.email,
    }

    # Test LOGOUT endpoint
    assert get_user(client).is_authenticated is True
    logout_params = {"id_token_hint": id_token}
    response = client.get(add_url_params(f"/realms/{realm}/protocol/openid-connect/logout", logout_params))
    assert not get_user(client).is_authenticated
    assert token_are_revoked(user)


@pytest.mark.parametrize("realm", ["local", "Review_apps", "Demo", "inclusion-connect"])
def test_registration(client, realm):
    application = ApplicationFactory()
    user = UserFactory()

    # Test REGISTRATIONS endpoint when not authenticated
    auth_url = f"/realms/{realm}/protocol/openid-connect/registrations"
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
    assertRedirects(response, reverse("accounts:register"))
    assert client.session["next_url"] == auth_complete_url

    # Test REGISTRATIONS endpoint when not authenticated and with bad oidc params
    bad_auth_params = auth_params.copy()
    bad_auth_params["client_id"] = "toto"
    bad_auth_complete_url = add_url_params(auth_url, bad_auth_params)
    response = client.get(bad_auth_complete_url)
    assert response.status_code == 400

    # Test REGISTRATIONS endpoint when not authenticated with activation params
    activation_params = auth_params | {
        "login_hint": "email",
        "firstname": "John",
        "lastname": "Doe",
    }
    auth_complete_url = add_url_params(auth_url, activation_params)
    response = client.get(auth_complete_url, follow=True)
    assertRedirects(response, reverse("accounts:activate"))
    assert client.session["next_url"] == auth_complete_url

    # Test REGISTRATIONS endpoint when authenticated
    client.force_login(user)
    response = client.get(auth_complete_url)
    assert response.status_code == 302
    assert response.url.startswith(auth_params["redirect_uri"])
    auth_response_params = get_url_params(response.url)

    # Test TOKEN endpoint
    token_data = {
        "client_id": application.client_id,
        "client_secret": DEFAULT_CLIENT_SECRET,
        "code": auth_response_params["code"],
        "grant_type": "authorization_code",
        "redirect_uri": "http://localhost/callback",
    }
    response = client.post(
        f"/realms/{realm}/protocol/openid-connect/token",
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
        f"/realms/{realm}/protocol/openid-connect/userinfo",
        headers={"Authorization": f"Bearer {token_json['access_token']}"},
    )
    assert response.json() == {
        "sub": str(user.pk),
        "given_name": user.first_name,
        "family_name": user.last_name,
        "email": user.email,
    }

    # Test LOGOUT endpoint
    assert get_user(client).is_authenticated is True
    logout_params = {"id_token_hint": id_token}
    response = client.get(add_url_params(f"/realms/{realm}/protocol/openid-connect/logout", logout_params))
    assert not get_user(client).is_authenticated
    assert token_are_revoked(user)


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


@pytest.mark.parametrize("realm", ["local", "Review_apps", "Demo", "inclusion-connect"])
def test_user_account(client, realm):
    application = ApplicationFactory()
    user = UserFactory()

    params = {
        "referrer": application.client_id,
        "referrer_uri": "http://localhost/callback",
    }
    account_url = add_url_params(f"/realms/{realm}/account", params)
    response = client.get(account_url)
    assertRedirects(response, add_url_params(reverse("accounts:login"), {"next": account_url}))

    response = client.post(response.url, {"email": user.email, "password": DEFAULT_PASSWORD}, follow=True)
    assert get_user(client).is_authenticated is True
    assertRedirects(response, account_url)
    assertContains(response, "Retour")
    # The redirect cleans `next_url` from the session.
    assert "next_url" not in client.session


class TestActionToken:
    @freeze_time("2023-04-26 11:11:11")
    def test_verify_email(self, caplog, client):
        secret = "secret"
        JWTHashSecret.objects.create(
            realm_id="local",
            secret=http.urlsafe_base64_encode(secret.encode()),
        )
        user = UserFactory(email="")
        email = "me@mailinator.com"
        address = EmailAddress.objects.create(email=email, user=user)
        now = timezone.now()
        token = jwt.encode(
            {
                "typ": "verify-email",
                "sub": str(user.pk),
                "eml": "me@mailinator.com",
                "aud": "http://testserver/realms/local",
                "exp": (now + datetime.timedelta(hours=6)).timestamp(),
            },
            secret,
            algorithm="HS256",
        )
        response = client.get(reverse("keycloak_compat_local:action-token"), data={"key": token})
        assertRedirects(response, reverse("accounts:edit_user_info"))
        address.refresh_from_db()
        assert address.verified_at == now
        user.refresh_from_db()
        assert user.email == email
        assertRecords(
            caplog,
            [
                (
                    "keycloak_compat",
                    logging.WARNING,
                    {"url": "/realms/local/login-actions/action-token"},
                ),
                (
                    "inclusion_connect.auth",
                    logging.INFO,
                    {"email": "me@mailinator.com", "user": user.pk, "event": "confirm_email_address"},
                ),
                (
                    "inclusion_connect.auth",
                    logging.INFO,
                    {"email": "me@mailinator.com", "user": user.pk, "event": "login"},
                ),
            ],
        )

        # Validating again fails.
        with freeze_time("2023-04-26 11:11:12"):
            response = client.get(reverse("keycloak_compat_local:action-token"), data={"key": token})
        assertMessages(response, [(messages.INFO, "Cette adresse e-mail est déjà vérifiée.")])
        assertRedirects(response, reverse("accounts:edit_user_info"))
        address.refresh_from_db()
        assert address.email == email
        assert address.verified_at == now
        user.refresh_from_db()
        assert user.email == email
        assertRecords(
            caplog,
            [
                (
                    "keycloak_compat",
                    logging.WARNING,
                    {"url": "/realms/local/login-actions/action-token"},
                ),
                (
                    "inclusion_connect.auth",
                    logging.INFO,
                    {
                        "email": "me@mailinator.com",
                        "user": user.pk,
                        "event": "confirm_email_address_error",
                        "error": "already verified",
                    },
                ),
            ],
        )

    def test_verify_bad_signature(self, caplog, client):
        secret = "secret"
        JWTHashSecret.objects.create(
            realm_id="local",
            secret=http.urlsafe_base64_encode(b"invalid"),
        )
        user = UserFactory(email="")
        email = "me@mailinator.com"
        address = EmailAddress.objects.create(email=email, user=user)
        token = jwt.encode(
            {
                "typ": "verify-email",
                "sub": str(user.pk),
                "eml": "me@mailinator.com",
                "aud": "http://testserver/realms/local",
            },
            secret,
            algorithm="HS256",
        )
        response = client.get(reverse("keycloak_compat_local:action-token"), data={"key": token})
        assert response.status_code == 404
        address.refresh_from_db()
        assert address.verified_at is None
        user.refresh_from_db()
        assert user.email == ""
        assertRecords(
            caplog,
            [
                (
                    "keycloak_compat",
                    logging.WARNING,
                    {"url": "/realms/local/login-actions/action-token"},
                ),
                ("django.request", logging.WARNING, "Not Found: /realms/local/login-actions/action-token"),
            ],
        )

    def test_verify_invalid_audience(self, caplog, client):
        secret = "secret"
        JWTHashSecret.objects.create(
            realm_id="local",
            secret=http.urlsafe_base64_encode(secret.encode()),
        )
        user = UserFactory(email="")
        email = "me@mailinator.com"
        address = EmailAddress.objects.create(email=email, user=user)
        token = jwt.encode(
            {
                "typ": "verify-email",
                "sub": str(user.pk),
                "eml": "me@mailinator.com",
                "aud": "http://otherserver/realms/local",
            },
            secret,
            algorithm="HS256",
        )
        response = client.get(reverse("keycloak_compat_local:action-token"), data={"key": token})
        assert response.status_code == 404
        address.refresh_from_db()
        assert address.verified_at is None
        user.refresh_from_db()
        assert user.email == ""
        assertRecords(
            caplog,
            [
                (
                    "keycloak_compat",
                    logging.WARNING,
                    {"url": "/realms/local/login-actions/action-token"},
                ),
                ("django.request", logging.WARNING, "Not Found: /realms/local/login-actions/action-token"),
            ],
        )

    def test_verify_email_token_too_old(self, caplog, client):
        secret = "secret"
        JWTHashSecret.objects.create(
            realm_id="local",
            secret=http.urlsafe_base64_encode(secret.encode()),
        )
        user = UserFactory(email="")
        email = "me@mailinator.com"
        address = EmailAddress.objects.create(email=email, user=user)
        validity_end = timezone.now()
        token = jwt.encode(
            {
                "typ": "verify-email",
                "sub": str(user.pk),
                "eml": "me@mailinator.com",
                "aud": "http://testserver/realms/local",
                "exp": validity_end.timestamp(),
            },
            secret,
            algorithm="HS256",
        )
        response = client.get(reverse("keycloak_compat_local:action-token"), data={"key": token})
        assertMessages(response, [(messages.ERROR, "Le lien de vérification d’adresse e-mail a expiré.")])
        assertRedirects(response, reverse("accounts:confirm-email"))
        assert client.session[EMAIL_CONFIRM_KEY] == "me@mailinator.com"
        address.refresh_from_db()
        assert address.verified_at is None
        user.refresh_from_db()
        assert user.email == ""
        assertRecords(
            caplog,
            [
                (
                    "keycloak_compat",
                    logging.WARNING,
                    {"url": "/realms/local/login-actions/action-token"},
                ),
                (
                    "inclusion_connect.auth",
                    logging.INFO,
                    {
                        "event": "confirm_email_address_error",
                        "error": "link expired",
                        "email": "me@mailinator.com",
                        "user": user.pk,
                    },
                ),
            ],
        )

    def test_unknown_action(self, caplog, client):
        secret = "secret"
        JWTHashSecret.objects.create(
            realm_id="local",
            secret=http.urlsafe_base64_encode(secret.encode()),
        )
        user = UserFactory(email="")
        email = "me@mailinator.com"
        address = EmailAddress.objects.create(email=email, user=user)
        token = jwt.encode(
            {
                "typ": "invalid",
                "sub": str(user.pk),
                "eml": "me@mailinator.com",
                "aud": "http://otherserver/realms/local",
            },
            secret,
            algorithm="HS256",
        )
        response = client.get(reverse("keycloak_compat_local:action-token"), data={"key": token})
        assert response.status_code == 404
        address.refresh_from_db()
        assert address.verified_at is None
        user.refresh_from_db()
        assert user.email == ""
        assertRecords(
            caplog,
            [
                (
                    "keycloak_compat",
                    logging.WARNING,
                    {"url": "/realms/local/login-actions/action-token"},
                ),
                ("django.request", logging.WARNING, "Not Found: /realms/local/login-actions/action-token"),
            ],
        )

    def test_no_jwt(self, caplog, client):
        response = client.get(reverse("keycloak_compat_local:action-token"))
        assert response.status_code == 404
        assertRecords(
            caplog,
            [
                (
                    "keycloak_compat",
                    logging.WARNING,
                    {"url": "/realms/local/login-actions/action-token"},
                ),
                ("django.request", logging.WARNING, "Not Found: /realms/local/login-actions/action-token"),
            ],
        )

    @freeze_time("2023-05-05 17:17:17")
    def test_token_from_keycloak(self, caplog, client):
        JWTHashSecret.objects.create(
            realm_id="local",
            secret="9vWa5WDqm9-Ai7a_Ke39g_lCNy_uisUjDaFsnZZDlhB_TLpgP5zeMqPOfghwpPZxb2cCi5remrm71ZzRKDXWjQ",
        )
        path_from_keycloak = "/realms/local/login-actions/action-token?key=eyJhbGciOiJIUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJkMWM0NzExZS04OTJiLTRkODktODZkNy03MjkxYjVlZjIwNzQifQ.eyJleHAiOjE2ODMzNzM4MzcsImlhdCI6MTY4MzI4NzQzNywianRpIjoiYzBjMDJkNTgtYTJjNy00OWUyLTkzN2EtOTg4MjM2Y2I2NDE3IiwiaXNzIjoiaHR0cDovLzAuMC4wLjA6ODA4MC9yZWFsbXMvbG9jYWwiLCJhdWQiOiJodHRwOi8vMC4wLjAuMDo4MDgwL3JlYWxtcy9sb2NhbCIsInN1YiI6IjhmMzk1OWY1LTM1OTItNDM5ZS04MzJkLTI2MDliZDE0MjQ1MCIsInR5cCI6InZlcmlmeS1lbWFpbCIsImF6cCI6ImxvY2FsX2luY2x1c2lvbl9jb25uZWN0Iiwibm9uY2UiOiJjMGMwMmQ1OC1hMmM3LTQ5ZTItOTM3YS05ODgyMzZjYjY0MTciLCJlbWwiOiJtZUBtYWlsaW5hdG9yLmNvbSIsImFzaWQiOiIzNGNhMjQ1YS1hMWY3LTRhNjctYjE5OS03OWE0MDFiNGEwZjQuNDVVR0FuWjk5T2cuMzM4Y2JhODgtMjMwMi00NzA5LTg5ZGQtOTM2ZGViZWRkMjk5IiwiYXNpZCI6IjM0Y2EyNDVhLWExZjctNGE2Ny1iMTk5LTc5YTQwMWI0YTBmNC40NVVHQW5aOTlPZy4zMzhjYmE4OC0yMzAyLTQ3MDktODlkZC05MzZkZWJlZGQyOTkifQ.z_734YWuJIrfxYP-noCPzSOrMYgLfoHs01zu_9Ildsk&client_id=local_inclusion_connect&tab_id=45UGAnZ99Og"  # noqa: E501
        user = UserFactory(email="", username="8f3959f5-3592-439e-832d-2609bd142450")
        email = "me@mailinator.com"
        address = EmailAddress.objects.create(email=email, user=user)
        now = timezone.now()
        response = client.get(path_from_keycloak, SERVER_NAME="0.0.0.0:8080")
        assertRedirects(response, reverse("accounts:edit_user_info"))
        address.refresh_from_db()
        assert address.verified_at == now
        user.refresh_from_db()
        assert user.email == email
        assertRecords(
            caplog,
            [
                (
                    "keycloak_compat",
                    logging.WARNING,
                    {"application": "local_inclusion_connect", "url": "/realms/local/login-actions/action-token"},
                ),
                (
                    "inclusion_connect.auth",
                    logging.INFO,
                    {"email": "me@mailinator.com", "user": user.pk, "event": "confirm_email_address"},
                ),
                (
                    "inclusion_connect.auth",
                    logging.INFO,
                    {"email": "me@mailinator.com", "user": user.pk, "event": "login"},
                ),
            ],
        )


@pytest.mark.parametrize("realm", ["local", "Review_apps", "Demo", "inclusion-connect"])
def test_discovery(client, realm):
    response = client.get(f"/realms/{realm}/.well-known/openid-configuration/")
    assert response.status_code == 200
