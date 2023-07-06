import datetime
import logging

import pytest
from django.contrib.auth import get_user
from django.contrib.sessions.models import Session
from django.test import override_settings
from django.urls import reverse
from django.utils import timezone
from freezegun import freeze_time
from pytest_django.asserts import assertContains, assertRedirects

from inclusion_connect.users.models import UserApplicationLink
from inclusion_connect.utils.oidc import OIDC_SESSION_KEY
from inclusion_connect.utils.urls import add_url_params, get_url_params
from tests.asserts import assertRecords
from tests.conftest import Client
from tests.helpers import (
    call_logout,
    has_ongoing_sessions,
    oidc_complete_flow,
    parse_response_to_soup,
    token_are_revoked,
)
from tests.oidc_overrides.factories import DEFAULT_CLIENT_SECRET, ApplicationFactory
from tests.users.factories import DEFAULT_PASSWORD, UserFactory


class TestRedirectUris:
    @pytest.mark.parametrize("allow_all", [True, False])
    def test_allow_all_settings(self, allow_all):
        with override_settings(ALLOW_ALL_REDIRECT_URIS=allow_all):
            application = ApplicationFactory(redirect_uris="*")
            assert application.redirect_uri_allowed("http://localhost/callback") is allow_all

    def test_allow_wildcard_at_redirect_uris_end(self):
        application = ApplicationFactory(redirect_uris="http://localhost/* http://other_callback/")
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
        application = ApplicationFactory(post_logout_redirect_uris="http://localhost/* http://other_callback/")
        assert application.post_logout_redirect_uri_allowed("http://localhost/callback")

    def test_no_open_redirect_uri(self):
        application = ApplicationFactory(post_logout_redirect_uris="http://localhost*")
        assert not application.post_logout_redirect_uri_allowed("http://localhost/callback")


class TestLogoutView:
    def test_id_token_hint(self, caplog, client, oidc_params):
        """This test simulates a call on logout endpoint with id_hint params"""
        user = UserFactory()
        id_token = oidc_complete_flow(client, user, oidc_params, caplog)

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
        assertRecords(
            caplog,
            "inclusion_connect.oidc",
            [
                {
                    "application": "my_application",
                    "event": "logout",
                    "id_token_hint": id_token,
                    "post_logout_redirect_uri": "http://callback/",
                    "user": user.pk,
                }
            ],
        )

    def test_expired_token_and_session(self, caplog, client, oidc_params):
        """This test simulates a call on logout endpoint with expired token and sessions"""
        user = UserFactory()
        with freeze_time("2023-05-05 14:29:20"):
            id_token = oidc_complete_flow(client, user, oidc_params, caplog)
            assert get_user(client).is_authenticated is True

        with freeze_time("2023-05-05 14:59:21"):
            params = {"id_token_hint": id_token, "post_logout_redirect_uri": "http://callback/"}
            response = call_logout(client, "get", params)
            assert response.status_code == 200
            assert get_user(client).is_authenticated is False  # The session expired
            assert has_ongoing_sessions(user) is False  # The session expired
            assert token_are_revoked(user) is False  # But the refresh tokens are still valid
            assertContains(
                response,
                '<input type="submit" class="btn btn-block btn-primary" name="allow" value="Se déconnecter" />',
            )

            params["allow"] = True
            response = call_logout(client, "post", params)
            assertRedirects(response, "http://callback/", fetch_redirect_response=False)

            assert get_user(client).is_authenticated is False
            assert has_ongoing_sessions(user) is False
            assert token_are_revoked(user) is True
            assertRecords(
                caplog,
                "inclusion_connect.oidc",
                [
                    {
                        "application": "my_application",
                        "event": "logout",
                        "id_token_hint": id_token,
                        "post_logout_redirect_uri": "http://callback/",
                        "user": user.pk,
                    }
                ],
            )

    def test_bad_id_token_hint_with_logged_in_user_fails(self, caplog, client, oidc_params):
        """This test simulates a call on logout endpoint with an unknown id_token_hint"""
        user = UserFactory()
        oidc_complete_flow(client, user, oidc_params, caplog)

        assert get_user(client).is_authenticated is True

        response = call_logout(client, "get", {"id_token_hint": 111})
        assert response.status_code == 400

        assert token_are_revoked(user) is False
        assert get_user(client).is_authenticated is True
        assert has_ongoing_sessions(user) is True
        assert caplog.record_tuples[0] == ("django.request", logging.WARNING, "Bad Request: /auth/logout/")
        assertRecords(
            caplog,
            "inclusion_connect.oidc",
            [
                {
                    "application": "my_application",
                    "event": "logout_error",
                    "id_token_hint": "111",
                    "error": "(invalid_request) The ID Token is expired, revoked, malformed, or otherwise invalid.",
                }
            ],
            i=1,
        )

    def test_bad_id_token_hint_with_no_redirect_uri(self, caplog, client):
        """This test simulates a call on logout endpoint with an unknown id_token_hint"""
        response = call_logout(client, "get", {"id_token_hint": 111})
        assertRedirects(response, "http://testserver/", fetch_redirect_response=False)
        assertRecords(
            caplog,
            "inclusion_connect.oidc",
            [{"event": "logout", "id_token_hint": "111", "user": None}],
        )

    def test_bad_id_token_hint_with_unknown_redirect_uri_fails(self, caplog, client):
        """This test simulates a call on logout endpoint with an unknown id_token_hint"""
        response = call_logout(client, "get", {"id_token_hint": 111, "post_logout_redirect_uri": "http://callback/"})
        assert response.status_code == 400
        assert caplog.record_tuples[0] == ("django.request", logging.WARNING, "Bad Request: /auth/logout/")
        assertRecords(
            caplog,
            "inclusion_connect.oidc",
            [
                {
                    "event": "logout_error",
                    "id_token_hint": "111",
                    "post_logout_redirect_uri": "http://callback/",
                    "error": "(invalid_request) The ID Token is expired, revoked, malformed, or otherwise invalid.",
                }
            ],
            i=1,
        )

    def test_logout_clear_all_clients_sessions(self, caplog, client, oidc_params):
        user = UserFactory()
        application = ApplicationFactory(client_id=oidc_params["client_id"])
        id_token = oidc_complete_flow(client, user, oidc_params, caplog, application=application)
        assert get_user(client).is_authenticated is True

        other_client = Client()
        oidc_complete_flow(other_client, user, oidc_params, caplog, application=application)
        assert get_user(other_client).is_authenticated is True
        assert get_user(client) == get_user(other_client)

        response = call_logout(
            client,
            "get",
            {"id_token_hint": id_token, "post_logout_redirect_uri": "http://callback/"},
        )
        assertRedirects(response, "http://callback/", fetch_redirect_response=False)
        assert get_user(client).is_authenticated is False
        assert get_user(other_client).is_authenticated is False
        assertRecords(
            caplog,
            "inclusion_connect.oidc",
            [
                {
                    "application": "my_application",
                    "event": "logout",
                    "id_token_hint": id_token,
                    "post_logout_redirect_uri": "http://callback/",
                    "user": user.pk,
                }
            ],
        )

    def test_multiple_logout_with_id_token_hint(self, caplog, client, oidc_params):
        user = UserFactory()
        application_1 = ApplicationFactory()
        oidc_params["client_id"] = application_1.client_id
        id_token_1 = oidc_complete_flow(client, user, oidc_params, caplog, application=application_1)
        application_2 = ApplicationFactory()
        oidc_params["client_id"] = application_2.client_id
        id_token_2 = oidc_complete_flow(client, user, oidc_params, caplog, application=application_2)

        assert get_user(client).is_authenticated is True
        assert token_are_revoked(user) is False
        assert has_ongoing_sessions(user) is True

        response = call_logout(
            client,
            "get",
            {"id_token_hint": id_token_1, "post_logout_redirect_uri": "http://callback/"},
        )
        assertRedirects(response, "http://callback/", fetch_redirect_response=False)

        assert get_user(client).is_authenticated is False
        assert has_ongoing_sessions(user) is False
        assert token_are_revoked(user) is True
        assertRecords(
            caplog,
            "inclusion_connect.oidc",
            [
                {
                    "application": application_1.client_id,
                    "event": "logout",
                    "id_token_hint": id_token_1,
                    "post_logout_redirect_uri": "http://callback/",
                    "user": user.pk,
                }
            ],
        )

        response = call_logout(
            client,
            "get",
            {"id_token_hint": id_token_2, "post_logout_redirect_uri": "http://callback/"},
        )
        assertRedirects(response, "http://callback/", fetch_redirect_response=False)

        assert get_user(client).is_authenticated is False
        assert has_ongoing_sessions(user) is False
        assert token_are_revoked(user) is True
        assertRecords(
            caplog,
            "inclusion_connect.oidc",
            [
                {
                    "application": application_2.client_id,
                    "event": "logout",
                    "id_token_hint": id_token_2,
                    "post_logout_redirect_uri": "http://callback/",
                    "user": None,
                }
            ],
        )


class TestAuthorizeView:
    def test_bad_oidc_params(self, client, oidc_params, snapshot):
        # Application does not exist
        auth_url = reverse("oauth2_provider:authorize")
        auth_complete_url = add_url_params(auth_url, oidc_params)
        response = client.get(auth_complete_url)
        assert response.status_code == 400
        assert str(parse_response_to_soup(response, selector="main")) == snapshot

    def test_not_authenticated(self, client, oidc_params):
        ApplicationFactory(client_id=oidc_params["client_id"])
        auth_url = reverse("oauth2_provider:authorize")
        auth_complete_url = add_url_params(auth_url, oidc_params)
        response = client.get(auth_complete_url)
        assertRedirects(response, reverse("accounts:login"))
        assert client.session["next_url"] == auth_complete_url
        assert client.session[OIDC_SESSION_KEY] == oidc_params


class TestRegisterView:
    def test_bad_oidc_params(self, client, oidc_params, snapshot):
        # Application does not exist
        auth_url = reverse("oauth2_provider:register")
        auth_complete_url = add_url_params(auth_url, oidc_params)
        response = client.get(auth_complete_url)
        assert response.status_code == 400
        assert str(parse_response_to_soup(response, selector="main")) == snapshot

    def test_not_authenticated(self, client, oidc_params):
        ApplicationFactory(client_id=oidc_params["client_id"])
        auth_url = reverse("oauth2_provider:register")
        auth_complete_url = add_url_params(auth_url, oidc_params)
        response = client.get(auth_complete_url)
        assertRedirects(response, reverse("accounts:register"))
        assert client.session["next_url"] == auth_complete_url
        assert client.session[OIDC_SESSION_KEY] == oidc_params


class TestActivateView:
    def test_bad_oidc_params(self, client, oidc_params, snapshot):
        auth_url = reverse("oauth2_provider:activate")
        auth_complete_url = add_url_params(auth_url, oidc_params)
        response = client.get(auth_complete_url)
        assert response.status_code == 400
        assert str(parse_response_to_soup(response, selector="main")) == snapshot

    def test_missing_user_info(self, client, oidc_params, snapshot):
        ApplicationFactory(client_id=oidc_params["client_id"])
        auth_url = reverse("oauth2_provider:activate")
        # Missing: email, firstname and lastname.
        auth_complete_url = add_url_params(auth_url, oidc_params)
        response = client.get(auth_complete_url)
        # The user is redirected to the activation view as the oidc parameters are valid
        assertRedirects(response, reverse("accounts:activate"), fetch_redirect_response=False)
        assert client.session["next_url"] == auth_complete_url
        assert client.session[OIDC_SESSION_KEY] == oidc_params

        response = client.get(response.url)
        assert response.status_code == 400
        assert str(parse_response_to_soup(response, selector="main")) == snapshot

    def test_not_authenticated(self, client, oidc_params):
        ApplicationFactory(client_id=oidc_params["client_id"])
        auth_params = oidc_params | {"login_hint": "email", "firstname": "firstname", "lastname": "lastname"}
        auth_url = reverse("oauth2_provider:activate")
        auth_complete_url = add_url_params(auth_url, auth_params)
        response = client.get(auth_complete_url)
        assertRedirects(response, reverse("accounts:activate"))
        assert client.session["next_url"] == auth_complete_url
        assert client.session[OIDC_SESSION_KEY] == auth_params


def test_user_application_link(client, oidc_params):
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

    oidc_params["client_id"] = application_1.client_id
    auth_url_1 = add_url_params(reverse("oauth2_provider:authorize"), oidc_params)
    oidc_params["client_id"] = application_2.client_id
    auth_url_2 = add_url_params(reverse("oauth2_provider:authorize"), oidc_params)

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


def test_session_duration(client, oidc_params):
    application_1 = ApplicationFactory()
    application_2 = ApplicationFactory()
    user = UserFactory()

    auth_url = reverse("oauth2_provider:authorize")

    oidc_params["client_id"] = application_1.client_id
    auth_complete_url = add_url_params(auth_url, oidc_params)
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
    oidc_params["client_id"] = application_2.client_id
    auth_complete_url = add_url_params(auth_url, oidc_params)
    with freeze_time("2023/05/12 10:49"):
        response = client.get(auth_complete_url)
        assert response.status_code == 302
        assert response.url.startswith(oidc_params["redirect_uri"])

    # No change in expire_date
    session = Session.objects.get()
    assert session.expire_date == now + datetime.timedelta(minutes=30)


def test_access_token_lifespan(client, oidc_params):
    ApplicationFactory(client_id=oidc_params["client_id"])
    user = UserFactory()
    client.force_login(user)

    auth_url = reverse("oauth2_provider:authorize")
    auth_complete_url = add_url_params(auth_url, oidc_params)
    with freeze_time("2023-05-05 14:29:20"):
        response = client.get(auth_complete_url)
        params = get_url_params(response.url)

        token_data = {
            "client_id": oidc_params["client_id"],
            "client_secret": DEFAULT_CLIENT_SECRET,
            "code": params["code"],
            "grant_type": "authorization_code",
            "redirect_uri": oidc_params["redirect_uri"],
        }
        response = client.post(reverse("oauth2_provider:token"), data=token_data)
        token_json = response.json()
        assert token_json["expires_in"] == 60 * 30  # 30 minutes

    with freeze_time("2023-05-05 14:59:19"):
        response = client.get(
            reverse("oauth2_provider:user-info"),
            headers={"Authorization": f"Bearer {token_json['access_token']}"},
        )
        assert response.status_code == 200

    with freeze_time("2023-05-05 14:59:20"):
        response = client.get(
            reverse("oauth2_provider:user-info"),
            headers={"Authorization": f"Bearer {token_json['access_token']}"},
        )
        assert response.status_code == 401


def test_discovery_view(client):
    response = client.get(reverse("oauth2_provider:oidc-connect-discovery-info"))
    assert response.status_code == 200
