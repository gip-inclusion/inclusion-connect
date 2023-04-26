from django.contrib.auth import get_user
from django.urls import reverse
from pytest_django.asserts import assertRedirects

from inclusion_connect.oidc_overrides.factories import ApplicationFactory
from inclusion_connect.oidc_overrides.views import OIDCSessionMixin
from inclusion_connect.users.factories import UserFactory
from inclusion_connect.utils.urls import add_url_params


OIDC_PARAMS = {
    "response_type": "code",
    "client_id": "my_application",
    "redirect_uri": "http://localhost/callback",
    "scope": "openid profile email",
    "state": "state",
    "nonce": "nonce",
}


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


def test_authorize_bad_oidc_params(client):
    # Application does not exist
    auth_url = reverse("oidc_overrides:authorize")
    auth_complete_url = add_url_params(auth_url, OIDC_PARAMS)
    response = client.get(auth_complete_url)
    # FIXME update the template
    assert response.status_code == 400


def test_authorize_not_authenticated(client):
    ApplicationFactory(client_id=OIDC_PARAMS["client_id"])
    auth_url = reverse("oidc_overrides:authorize")
    auth_complete_url = add_url_params(auth_url, OIDC_PARAMS)
    response = client.get(auth_complete_url)
    assertRedirects(response, reverse("accounts:login"))
    assert client.session["next_url"] == auth_complete_url
    assert client.session[OIDCSessionMixin.OIDC_SESSION_KEY] == OIDC_PARAMS


def test_registrations_bad_oidc_params(client):
    # Application does not exist
    auth_url = reverse("oidc_overrides:registrations")
    auth_complete_url = add_url_params(auth_url, OIDC_PARAMS)
    response = client.get(auth_complete_url)
    # FIXME update the template
    assert response.status_code == 400


def test_registrations_not_authenticated(client):
    ApplicationFactory(client_id=OIDC_PARAMS["client_id"])
    auth_url = reverse("oidc_overrides:registrations")
    auth_complete_url = add_url_params(auth_url, OIDC_PARAMS)
    response = client.get(auth_complete_url)
    assertRedirects(response, reverse("accounts:registration"))
    assert client.session["next_url"] == auth_complete_url
    assert client.session[OIDCSessionMixin.OIDC_SESSION_KEY] == OIDC_PARAMS


def test_activation_bad_oidc_params(client):
    auth_url = reverse("oidc_overrides:activation")
    auth_complete_url = add_url_params(auth_url, OIDC_PARAMS)
    response = client.get(auth_complete_url)
    # FIXME update the template
    assert response.status_code == 400


def test_activation_missing_user_info(client):
    ApplicationFactory(client_id=OIDC_PARAMS["client_id"])
    auth_url = reverse("oidc_overrides:activation")
    # Missing: email, firstname and lastname.
    auth_complete_url = add_url_params(auth_url, OIDC_PARAMS)
    response = client.get(auth_complete_url)
    # The user is redirected to the activation view as the oidc parameters are valid
    assertRedirects(response, reverse("accounts:activation"), fetch_redirect_response=False)
    assert client.session["next_url"] == auth_complete_url
    assert client.session[OIDCSessionMixin.OIDC_SESSION_KEY] == OIDC_PARAMS

    response = client.get(response.url)
    # FIXME update the template
    assert response.status_code == 400


def test_activation_not_authenticated(client):
    ApplicationFactory(client_id=OIDC_PARAMS["client_id"])
    auth_params = OIDC_PARAMS | {"email": "email", "firstname": "firstname", "lastname": "lastname"}
    auth_url = reverse("oidc_overrides:activation")
    auth_complete_url = add_url_params(auth_url, auth_params)
    response = client.get(auth_complete_url)
    assertRedirects(response, reverse("accounts:activation"))
    assert client.session["next_url"] == auth_complete_url
    assert client.session[OIDCSessionMixin.OIDC_SESSION_KEY] == auth_params
