from django.contrib.auth import get_user
from django.urls import reverse
from pytest_django.asserts import assertRedirects

from inclusion_connect.oidc_overrides.factories import ApplicationFactory
from inclusion_connect.users.factories import UserFactory
from inclusion_connect.utils.urls import add_url_params


def test_allow_wildcard_in_redirect_uris():
    application = ApplicationFactory(redirect_uris="http://localhost/*")
    assert application.redirect_uri_allowed("http://localhost/callback")

    application = ApplicationFactory(redirect_uris="*")
    assert application.redirect_uri_allowed("http://localhost/callback")

    # We do not handle wildcard in domains
    application = ApplicationFactory(redirect_uris="http://*.mydomain.com/callback")
    assert not application.redirect_uri_allowed("http://site1.mydomain.com/callback")


def test_logout(client):
    auth_url = reverse("oidc_overrides:authorize")
    user = UserFactory()
    client.force_login(user)
    response = client.get(auth_url)
    assert response.status_code == 400  # auth_url is missing all the arguments
    # TODO: Add a method to quickly to the oidc dance.

    assert get_user(client).is_authenticated
    logout_params = {"id_token_hint": 111}  # bad token
    # TODO: also try with existing token but expired
    response = client.get(add_url_params(reverse("oidc_overrides:logout"), logout_params))
    assertRedirects(response, "http://testserver/", fetch_redirect_response=False)
    assert not get_user(client).is_authenticated


def test_authorize_bad_params(client):
    auth_url = reverse("oidc_overrides:authorize")
    auth_params = {
        "response_type": "code",
        "client_id": "unknown_client_id",
        "redirect_uri": "http://localhost/callback",
        "scope": "openid profile email",
        "state": "state",
        "nonce": "nonce",
    }
    auth_complete_url = add_url_params(auth_url, auth_params)
    response = client.get(auth_complete_url)
    # FIXME update the template
    assert response.status_code == 400


def test_authorize_not_authenticated(client):
    application = ApplicationFactory()
    auth_url = reverse("oidc_overrides:authorize")
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
