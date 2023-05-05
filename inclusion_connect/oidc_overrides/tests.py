import pytest
from django.contrib.auth import get_user
from django.test.client import Client
from django.urls import reverse
from django.utils import timezone
from freezegun import freeze_time
from pytest_django.asserts import assertRedirects

from inclusion_connect.oidc_overrides.factories import ApplicationFactory
from inclusion_connect.oidc_overrides.views import OIDCSessionMixin
from inclusion_connect.test import OIDC_PARAMS, has_ongoing_sessions, oidc_complete_flow, token_are_revoked
from inclusion_connect.users.factories import UserFactory
from inclusion_connect.users.models import UserApplicationLink
from inclusion_connect.utils.urls import add_url_params


def test_allow_wildcard_in_redirect_uris():
    application = ApplicationFactory(redirect_uris="http://localhost/*")
    assert application.redirect_uri_allowed("http://localhost/callback")

    application = ApplicationFactory(redirect_uris="*")
    assert application.redirect_uri_allowed("http://localhost/callback")

    # We do not handle wildcard in domains
    application = ApplicationFactory(redirect_uris="http://*.mydomain.com/callback")
    assert not application.redirect_uri_allowed("http://site1.mydomain.com/callback")


@pytest.mark.parametrize(
    "method,other_client",
    [("get", True), ("get", False), ("post", True), ("post", False)],
)
def test_logout(client, method, other_client):
    """This test simulates a GET or POST on logout endpoint from RP backend or the user browser"""
    user = UserFactory()
    id_token = oidc_complete_flow(client, user)

    assert get_user(client).is_authenticated is True
    logout_params = {"id_token_hint": id_token}

    logout_client = Client() if other_client else client
    logout_method = getattr(logout_client, method)

    response = logout_method(add_url_params(reverse("oidc_overrides:logout"), logout_params))
    assertRedirects(response, "http://testserver/", fetch_redirect_response=False)

    assert get_user(logout_client).is_authenticated is False
    assert get_user(client).is_authenticated is False
    assert has_ongoing_sessions(user) is False
    assert token_are_revoked(user) is True


@pytest.mark.parametrize(
    "method,other_client",
    [("get", True), ("get", False), ("post", True), ("post", False)],
)
def test_logout_expired_token(client, method, other_client):
    """This test simulates a GET or POST on logout endpoint from RP backend or the user browser"""
    user = UserFactory()
    with freeze_time("2023-05-05 14:29:20"):
        id_token = oidc_complete_flow(client, user)
        assert get_user(client).is_authenticated is True

    logout_params = {"id_token_hint": id_token}

    logout_client = Client() if other_client else client
    logout_method = getattr(logout_client, method)

    with freeze_time("2023-05-05 14:59:21"):
        response = logout_method(add_url_params(reverse("oidc_overrides:logout"), logout_params))
        assertRedirects(response, "http://testserver/", fetch_redirect_response=False)

        assert get_user(client).is_authenticated is False
        assert has_ongoing_sessions(user) is False
        assert token_are_revoked(user) is True


@pytest.mark.parametrize(
    "method,other_client",
    [("get", True), ("get", False), ("post", True), ("post", False)],
)
def test_logout_bad_login_hint(client, method, other_client):
    """This test simulates a GET or POST on logout endpoint from RP backend or the user browser"""
    user = UserFactory()
    oidc_complete_flow(client, user)

    assert get_user(client).is_authenticated is True
    logout_params = {"id_token_hint": 111}  # bad token

    logout_client = Client() if other_client else client
    logout_method = getattr(logout_client, method)

    response = logout_method(add_url_params(reverse("oidc_overrides:logout"), logout_params))
    assertRedirects(response, "http://testserver/", fetch_redirect_response=False)

    assert get_user(logout_client).is_authenticated is False
    assert token_are_revoked(user) is False

    if other_client:  # Django original session was not deleted as we couldn't match a user
        assert get_user(client).is_authenticated is True
        assert has_ongoing_sessions(user) is True
    else:
        assert get_user(client).is_authenticated is False
        assert has_ongoing_sessions(user) is False


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


def test_user_application_link(client):
    application_1 = ApplicationFactory(client_id="ca713487-f4ac-4283-8429-cab7f0386a00")
    application_2 = ApplicationFactory(client_id="05fb7023-ef66-4b24-896e-35f54a6c637f")
    user = UserFactory()
    client.force_login(user)

    def get_user_application_link_values_list():
        return list(
            UserApplicationLink.objects.values_list("application_id", "user_id", "last_login").order_by(
                "application__client_id"
            )
        )

    auth_params_1 = OIDC_PARAMS.copy()
    auth_params_1["client_id"] = application_1.client_id
    auth_url_1 = add_url_params(reverse("oidc_overrides:authorize"), auth_params_1)
    auth_params_2 = OIDC_PARAMS.copy()
    auth_params_2["client_id"] = application_2.client_id
    auth_url_2 = add_url_params(reverse("oidc_overrides:authorize"), auth_params_2)

    assert user.linked_applications.count() == 0

    with freeze_time("2023-04-27 14:06"):
        dt_1 = timezone.now()
        client.get(auth_url_1)

    assert get_user_application_link_values_list() == [(application_1.pk, user.pk, dt_1)]

    with freeze_time("2023-04-27 14:07"):
        dt_2 = timezone.now()
        client.get(auth_url_2)

    assert get_user_application_link_values_list() == [
        (application_2.pk, user.pk, dt_2),
        (application_1.pk, user.pk, dt_1),
    ]

    with freeze_time("2023-04-27 14:08"):
        dt_3 = timezone.now()
        client.get(auth_url_1)

    assert get_user_application_link_values_list() == [
        (application_2.pk, user.pk, dt_2),
        (application_1.pk, user.pk, dt_3),  # last_login was updated
    ]
