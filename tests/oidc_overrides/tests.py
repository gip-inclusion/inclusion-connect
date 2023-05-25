import datetime

import pytest
from django.contrib.auth import get_user
from django.contrib.sessions.models import Session
from django.test import override_settings
from django.urls import reverse
from django.utils import timezone
from freezegun import freeze_time
from pytest_django.asserts import assertRedirects

from inclusion_connect.users.models import UserApplicationLink
from inclusion_connect.utils.oidc import OIDC_SESSION_KEY
from inclusion_connect.utils.urls import add_url_params
from tests.helpers import (
    OIDC_PARAMS,
    call_logout,
    has_ongoing_sessions,
    oidc_complete_flow,
    parse_response_to_soup,
    token_are_revoked,
)
from tests.oidc_overrides.factories import ApplicationFactory
from tests.users.factories import DEFAULT_PASSWORD, UserFactory


class TestRedirectUris:
    @pytest.mark.parametrize("allow_all", [True, False])
    def test_allow_all_settings(self, allow_all):
        with override_settings(ALLOW_ALL_REDIRECT_URIS=allow_all):
            application = ApplicationFactory(redirect_uris="*")
            assert application.redirect_uri_allowed("http://localhost/callback") is allow_all

    def test_allow_wildcard_at_redirect_uris_end(self):
        application = ApplicationFactory(redirect_uris="http://localhost/*")
        assert application.redirect_uri_allowed("http://localhost/callback")

    def test_no_open_redirect_uri(self):
        application = ApplicationFactory(redirect_uris="http://localhost*")
        assert not application.redirect_uri_allowed("http://localhost/callback")


class TestPostLogoutRedirectUris:
    @pytest.mark.parametrize("allow_all", [True, False])
    def test_allow_all_settings(self, allow_all):
        with override_settings(ALLOW_ALL_REDIRECT_URIS=allow_all):
            application = ApplicationFactory(post_logout_redirect_uris="*")
            assert application.post_logout_redirect_uri_allowed("http://localhost/callback") is allow_all

    def test_allow_wildcard_at_redirect_uris_end(self):
        application = ApplicationFactory(post_logout_redirect_uris="http://localhost/*")
        assert application.post_logout_redirect_uri_allowed("http://localhost/callback")

    def test_no_open_redirect_uri(self):
        application = ApplicationFactory(post_logout_redirect_uris="http://localhost*")
        assert not application.post_logout_redirect_uri_allowed("http://localhost/callback")


class TestLogoutView:
    def test_id_token_hint(self, client):
        """This test simulates a call on logout endpoint with id_hint params"""
        user = UserFactory()
        id_token = oidc_complete_flow(client, user)

        assert get_user(client).is_authenticated is True

        response = call_logout(
            client,
            "get",
            {"id_token_hint": id_token, "post_logout_redirect_uri": "http://callback/"},
        )
        assertRedirects(response, "http://callback/", fetch_redirect_response=False)

        assert get_user(client).is_authenticated is False
        assert has_ongoing_sessions(user) is False
        assert token_are_revoked(user) is True

    def test_expired_token_and_session(self, client):
        """This test simulates a call on logout endpoint with expired token and sessions"""
        user = UserFactory()
        with freeze_time("2023-05-05 14:29:20"):
            id_token = oidc_complete_flow(client, user)
            assert get_user(client).is_authenticated is True

        with freeze_time("2023-05-05 14:59:21"):
            params = {"id_token_hint": id_token, "post_logout_redirect_uri": "http://callback/"}
            response = call_logout(client, "get", params)
            assert response.status_code == 200

            params["allow"] = True
            response = call_logout(client, "post", params)
            assertRedirects(response, "http://callback/", fetch_redirect_response=False)

            assert get_user(client).is_authenticated is False
            assert has_ongoing_sessions(user) is False
            assert token_are_revoked(user) is True

    def test_bad_login_hint(self, client):
        """This test simulates a call on logout endpoint with bad login hint"""
        user = UserFactory()
        oidc_complete_flow(client, user)

        assert get_user(client).is_authenticated is True

        response = call_logout(client, "get", {"id_token_hint": 111})
        assert response.status_code == 400

        assert token_are_revoked(user) is False
        assert get_user(client).is_authenticated is True
        assert has_ongoing_sessions(user) is True


class TestAuthorizeView:
    def test_bad_oidc_params(self, client, snapshot):
        # Application does not exist
        auth_url = reverse("oidc_overrides:authorize")
        auth_complete_url = add_url_params(auth_url, OIDC_PARAMS)
        response = client.get(auth_complete_url)
        assert response.status_code == 400
        assert str(parse_response_to_soup(response, selector="main")) == snapshot

    def test_not_authenticated(self, client):
        ApplicationFactory(client_id=OIDC_PARAMS["client_id"])
        auth_url = reverse("oidc_overrides:authorize")
        auth_complete_url = add_url_params(auth_url, OIDC_PARAMS)
        response = client.get(auth_complete_url)
        assertRedirects(response, reverse("accounts:login"))
        assert client.session["next_url"] == auth_complete_url
        assert client.session[OIDC_SESSION_KEY] == OIDC_PARAMS


class TestRegisterView:
    def test_bad_oidc_params(self, client, snapshot):
        # Application does not exist
        auth_url = reverse("oidc_overrides:register")
        auth_complete_url = add_url_params(auth_url, OIDC_PARAMS)
        response = client.get(auth_complete_url)
        assert response.status_code == 400
        assert str(parse_response_to_soup(response, selector="main")) == snapshot

    def test_not_authenticated(self, client):
        ApplicationFactory(client_id=OIDC_PARAMS["client_id"])
        auth_url = reverse("oidc_overrides:register")
        auth_complete_url = add_url_params(auth_url, OIDC_PARAMS)
        response = client.get(auth_complete_url)
        assertRedirects(response, reverse("accounts:register"))
        assert client.session["next_url"] == auth_complete_url
        assert client.session[OIDC_SESSION_KEY] == OIDC_PARAMS


class TestActivateView:
    def test_bad_oidc_params(self, client, snapshot):
        auth_url = reverse("oidc_overrides:activate")
        auth_complete_url = add_url_params(auth_url, OIDC_PARAMS)
        response = client.get(auth_complete_url)
        assert response.status_code == 400
        assert str(parse_response_to_soup(response, selector="main")) == snapshot

    def test_missing_user_info(self, client, snapshot):
        ApplicationFactory(client_id=OIDC_PARAMS["client_id"])
        auth_url = reverse("oidc_overrides:activate")
        # Missing: email, firstname and lastname.
        auth_complete_url = add_url_params(auth_url, OIDC_PARAMS)
        response = client.get(auth_complete_url)
        # The user is redirected to the activation view as the oidc parameters are valid
        assertRedirects(response, reverse("accounts:activate"), fetch_redirect_response=False)
        assert client.session["next_url"] == auth_complete_url
        assert client.session[OIDC_SESSION_KEY] == OIDC_PARAMS

        response = client.get(response.url)
        assert response.status_code == 400
        assert str(parse_response_to_soup(response, selector="main")) == snapshot

    def test_not_authenticated(self, client):
        ApplicationFactory(client_id=OIDC_PARAMS["client_id"])
        auth_params = OIDC_PARAMS | {"login_hint": "email", "firstname": "firstname", "lastname": "lastname"}
        auth_url = reverse("oidc_overrides:activate")
        auth_complete_url = add_url_params(auth_url, auth_params)
        response = client.get(auth_complete_url)
        assertRedirects(response, reverse("accounts:activate"))
        assert client.session["next_url"] == auth_complete_url
        assert client.session[OIDC_SESSION_KEY] == auth_params


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


def test_session_duration(client):
    application_1 = ApplicationFactory()
    application_2 = ApplicationFactory()
    user = UserFactory()

    auth_params = OIDC_PARAMS.copy()
    auth_url = reverse("oidc_overrides:authorize")

    auth_params["client_id"] = application_1.client_id
    auth_complete_url = add_url_params(auth_url, auth_params)
    with freeze_time("2023/05/12 10:39"):
        now = timezone.now()
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

    session = Session.objects.get()
    assert session.expire_date == now + datetime.timedelta(minutes=30)

    # 1O minutes later
    auth_params["client_id"] = application_2.client_id
    auth_complete_url = add_url_params(auth_url, auth_params)
    with freeze_time("2023/05/12 10:49"):
        response = client.get(auth_complete_url)
        assert response.status_code == 302
        assert response.url.startswith(OIDC_PARAMS["redirect_uri"])

    # No change in expire_date
    session = Session.objects.get()
    assert session.expire_date == now + datetime.timedelta(minutes=30)
