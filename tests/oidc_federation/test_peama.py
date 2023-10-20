import logging
from types import SimpleNamespace

import jwt
from django.conf import settings
from django.contrib.auth import get_user
from django.test import override_settings
from django.urls import reverse
from jwcrypto import jwk
from pytest_django.asserts import assertContains, assertRedirects

from inclusion_connect.oidc_federation.enums import Federation
from inclusion_connect.users.models import User
from inclusion_connect.utils.urls import get_url_params
from tests.asserts import assertRecords
from tests.users.factories import DEFAULT_PASSWORD, UserFactory


PEAMA_SUB = "RANDOM_STRING"
PEAMA_ADDITIONAL_DATA = {
    "structureTravail": 59194,
    "siteTravail": "DRHAUTS-DE-FRANCE/PFPPLATEFORMESERVICESADISTANCE(HDF0262005733)",
}


def generate_peama_data(nonce):
    key_kid = "random_kid"

    key = jwk.JWK.generate(kty="RSA", size=2048, alg="RS256", use="sig", kid=key_kid)
    private_key = key.export_to_pem(private_key=True, password=None)
    jwk_key = key.export_public(as_dict=True)

    user_info = {
        "given_name": "Michel",
        "family_name": "AUDIARD",
        "email": "michel@pole-emploi.fr",
        "sub": PEAMA_SUB,
    }

    id_token_data = user_info | {"nonce": nonce} | PEAMA_ADDITIONAL_DATA
    id_token = jwt.encode(payload=id_token_data, key=private_key, algorithm="RS256", headers={"kid": key_kid})

    access_token = {
        "access_token": "00000000-0000-0000-0000-000000000000",
        "refresh_token": "11111111-1111-1111-1111-111111111111",
        "scope": settings.PEAMA_SCOPES,
        "id_token": id_token,
        "token_type": "Bearer",
        "expires_in": 1499,
    }

    jwks = {"keys": [jwk_key]}

    return SimpleNamespace(
        access_token=access_token,
        user_info=user_info,
        jwks=jwks,
    )


def mock_peama_oauth_dance(client, requests_mock, auth_complete_url):
    assert auth_complete_url.startswith(settings.PEAMA_AUTH_ENDPOINT)
    state = get_url_params(auth_complete_url)["state"]
    nonce = get_url_params(auth_complete_url)["nonce"]
    callback_url = reverse("oidc_federation:peama:callback")

    peama_data = generate_peama_data(nonce)
    requests_mock.post(settings.PEAMA_TOKEN_ENDPOINT, json=peama_data.access_token)
    requests_mock.get(settings.PEAMA_USER_ENDPOINT, json=peama_data.user_info)
    requests_mock.get(settings.PEAMA_JWKS_ENDPOINT, json=peama_data.jwks)

    return client.get(callback_url, data={"code": "123", "state": state}), peama_data


class TestFederation:
    def test_init_view(self, client):
        auth_url = reverse("oidc_federation:peama:init")
        response = client.get(auth_url)
        assert response.url.startswith(settings.PEAMA_AUTH_ENDPOINT)

        params = get_url_params(response.url)
        assert params["response_type"] == "code"
        assert params["scope"] == settings.PEAMA_SCOPES
        assert params["client_id"] == settings.PEAMA_CLIENT_ID
        assert params["redirect_uri"] == "http://testserver/federation/peama/callback/"
        assert params["realm"] == "/agent"
        assert list(params.keys()) == [
            "response_type",
            "scope",
            "client_id",
            "redirect_uri",
            "state",
            "realm",
            "nonce",
        ]

    def test_new_user(self, client, requests_mock, caplog):
        response = client.get(reverse("oidc_federation:peama:init"))
        response, peama_data = mock_peama_oauth_dance(client, requests_mock, response.url)
        user = User.objects.get()
        assert not user.email_addresses.exists()
        assert user.email == peama_data.user_info["email"]
        assert user.first_name == peama_data.user_info["given_name"]
        assert user.last_name == peama_data.user_info["family_name"]
        assert user.federation_sub == peama_data.user_info["sub"]
        assert user.federation == Federation.PEAMA
        assert user.federation_data == {
            "structure_pe": PEAMA_ADDITIONAL_DATA["structureTravail"],
            "site_pe": PEAMA_ADDITIONAL_DATA["siteTravail"],
        }
        assertRedirects(response, reverse("accounts:accept_terms"))
        assertRecords(
            caplog,
            [
                (
                    "inclusion_connect.auth.oidc_federation",
                    logging.INFO,
                    {"email": user.email, "user": user.pk, "event": "register", "federation": Federation.PEAMA},
                )
            ],
        )

    def test_update_existing_pe_user(self, client, requests_mock, caplog):
        user = UserFactory(
            email="old_email",
            first_name="old_first_name",
            last_name="old_last_name",
            federation_sub=PEAMA_SUB,
            federation=Federation.PEAMA,
        )
        response = client.get(reverse("oidc_federation:peama:init"))
        response, peama_data = mock_peama_oauth_dance(client, requests_mock, response.url)
        user = User.objects.get()
        assert user.email == peama_data.user_info["email"]
        assert user.first_name == peama_data.user_info["given_name"]
        assert user.last_name == peama_data.user_info["family_name"]
        assert user.federation_sub == peama_data.user_info["sub"]
        assert user.federation == Federation.PEAMA
        assert user.federation_data == {
            "site_pe": PEAMA_ADDITIONAL_DATA["siteTravail"],
            "structure_pe": PEAMA_ADDITIONAL_DATA["structureTravail"],
        }
        assertRedirects(response, reverse("accounts:edit_user_info"))
        assertRecords(
            caplog,
            [
                (
                    "inclusion_connect.auth.oidc_federation",
                    logging.INFO,
                    {"email": user.email, "user": user.pk, "event": "login", "federation": Federation.PEAMA},
                ),
                (
                    "inclusion_connect.auth.oidc_federation",
                    logging.INFO,
                    {
                        "event": "edit_user_info",
                        "user": user.pk,
                        "old_first_name": "old_first_name",
                        "new_first_name": peama_data.user_info["given_name"],
                        "old_last_name": "old_last_name",
                        "new_last_name": peama_data.user_info["family_name"],
                        "old_email": "old_email",
                        "new_email": peama_data.user_info["email"],
                        "old_federation_data": None,
                        "new_federation_data": user.federation_data,
                        "old_federation_id_token_hint": None,
                        "new_federation_id_token_hint": peama_data.access_token["id_token"],
                    },
                ),
            ],
        )

    def test_convert_existing_ic_user(self, client, requests_mock, caplog):
        UserFactory(
            email="michel@pole-emploi.fr",
            first_name="old_first_name",
            last_name="old_last_name",
        )
        response = client.get(reverse("oidc_federation:peama:init"))
        response, peama_data = mock_peama_oauth_dance(client, requests_mock, response.url)
        user = User.objects.get()
        assert user.email == peama_data.user_info["email"]
        assert user.first_name == peama_data.user_info["given_name"]
        assert user.last_name == peama_data.user_info["family_name"]
        assert user.federation_sub == peama_data.user_info["sub"]
        assert user.federation == Federation.PEAMA
        assert user.federation_data == {
            "structure_pe": PEAMA_ADDITIONAL_DATA["structureTravail"],
            "site_pe": PEAMA_ADDITIONAL_DATA["siteTravail"],
        }
        assertRedirects(response, reverse("accounts:edit_user_info"))
        assertRecords(
            caplog,
            [
                (
                    "inclusion_connect.auth.oidc_federation",
                    logging.INFO,
                    {"email": user.email, "user": user.pk, "event": "login", "federation": Federation.PEAMA},
                ),
                (
                    "inclusion_connect.auth.oidc_federation",
                    logging.INFO,
                    {
                        "event": "edit_user_info",
                        "user": user.pk,
                        "old_first_name": "old_first_name",
                        "new_first_name": peama_data.user_info["given_name"],
                        "old_last_name": "old_last_name",
                        "new_last_name": peama_data.user_info["family_name"],
                        "old_federation_sub": None,
                        "new_federation_sub": peama_data.user_info["sub"],
                        "old_federation": None,
                        "new_federation": Federation.PEAMA,
                        "old_federation_data": None,
                        "new_federation_data": user.federation_data,
                        "old_federation_id_token_hint": None,
                        "new_federation_id_token_hint": peama_data.access_token["id_token"],
                    },
                ),
            ],
        )

    def test_block_user_from_another_federation(self, client, requests_mock, caplog):
        user = UserFactory(
            email="michel@pole-emploi.fr",
            first_name="old_first_name",
            last_name="old_last_name",
            federation="other",
            federation_sub="sub",
        )
        response = client.get(reverse("oidc_federation:peama:init"))
        response, peama_data = mock_peama_oauth_dance(client, requests_mock, response.url)
        assertRedirects(response, reverse("accounts:login"))
        assert get_user(client).is_authenticated is False
        user = User.objects.get()
        assert user.email == peama_data.user_info["email"]
        assert user.first_name != peama_data.user_info["given_name"]
        assert user.last_name != peama_data.user_info["family_name"]
        assert user.federation_sub != peama_data.user_info["sub"]
        assert user.federation == "other"
        assert user.federation_data is None
        assertRecords(
            caplog,
            [
                (
                    "mozilla_django_oidc.auth",
                    logging.WARNING,
                    "failed to get or create user: email=michel@pole-emploi.fr from federation=peama is already used "
                    "by other",
                ),
                (
                    "inclusion_connect.auth.oidc_federation",
                    logging.INFO,
                    {"email": user.email, "user": user.pk, "event": "login_error", "federation": Federation.PEAMA},
                ),
            ],
        )

    def test_block_user_from_another_federation_same_sub(self, client, requests_mock, caplog):
        # This shouldn"t happen often since subs should be long random keys, but we never know
        UserFactory(
            email="michel@pole-emploi.fr",
            first_name="old_first_name",
            last_name="old_last_name",
            federation="other",
            federation_sub=PEAMA_SUB,
        )
        response = client.get(reverse("oidc_federation:peama:init"))
        response, peama_data = mock_peama_oauth_dance(client, requests_mock, response.url)
        assertRedirects(response, reverse("accounts:login"))
        assert get_user(client).is_authenticated is False
        user = User.objects.get()
        assert user.email == peama_data.user_info["email"]
        assert user.first_name != peama_data.user_info["given_name"]
        assert user.last_name != peama_data.user_info["family_name"]
        assert user.federation_sub == peama_data.user_info["sub"]
        assert user.federation == "other"
        assert user.federation_data is None
        assertRecords(
            caplog,
            [
                (
                    "mozilla_django_oidc.auth",
                    logging.WARNING,
                    "failed to get or create user: email=michel@pole-emploi.fr from federation=peama is already used "
                    "by other",
                ),
                (
                    "inclusion_connect.auth.oidc_federation",
                    logging.INFO,
                    {"email": user.email, "user": user.pk, "event": "login_error", "federation": Federation.PEAMA},
                ),
            ],
        )


@override_settings(PEAMA_ENABLED=None, PEAMA_CLIENT_ID=None, PEAMA_JWKS_ENDPOINT=None)
def test_dont_crash_if_not_configured(client):
    user = UserFactory()
    url = reverse("accounts:login")
    response = client.get(url)
    assertContains(response, "Connexion")
    assertContains(response, "Adresse e-mail")  # Ask for email, not username
    assertContains(response, reverse("accounts:register"))  # Link to register page

    response = client.post(url, data={"email": user.email, "password": DEFAULT_PASSWORD})
    assertRedirects(response, reverse("accounts:edit_user_info"), fetch_redirect_response=False)
