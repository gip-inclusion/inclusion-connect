# Functional tests for all documented customer processes
import logging
import re

import pytest
from django.contrib import messages
from django.contrib.auth import get_user
from django.contrib.auth.hashers import make_password
from django.core import mail
from django.urls import reverse
from freezegun import freeze_time
from pytest_django.asserts import assertContains, assertRedirects

from inclusion_connect.users.models import User
from inclusion_connect.utils.urls import add_url_params, get_url_params
from tests.asserts import assertMessages, assertRecords
from tests.conftest import Client
from tests.helpers import (
    call_logout,
    oidc_complete_flow,
    oidc_flow_followup,
    parse_response_to_soup,
    pretty_indented,
    token_are_revoked,
)
from tests.oidc_overrides.factories import ApplicationFactory
from tests.users.factories import DEFAULT_PASSWORD, UserFactory


LINK_PATTERN = re.compile(r"^http://testserver(?P<path>.+/)$")


def get_verification_link(body):
    lines = body.split("\n")
    for line in lines:
        if match := LINK_PATTERN.match(line):
            return match.group("path")


@freeze_time("2023-05-05 11:11:11")
@pytest.mark.parametrize(
    "auth_url",
    [
        reverse("oauth2_provider:authorize"),
        # Verify the GET parameter `next` does not override OIDC redirect_uri.
        f"{reverse('oauth2_provider:authorize')}?next=http://evil.com",
    ],
)
def test_login_endpoint(auth_url, caplog, client, oidc_params):
    ApplicationFactory(client_id=oidc_params["client_id"])
    user = UserFactory()

    auth_complete_url = add_url_params(auth_url, oidc_params)
    response = client.get(auth_complete_url)
    assertRedirects(response, reverse("accounts:login"))
    assertRecords(caplog, [])

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
    assertRecords(
        caplog,
        [
            (
                "inclusion_connect.auth",
                logging.INFO,
                {"application": "my_application", "user": user.email, "event": "login"},
            )
        ],
    )

    response = client.get(auth_complete_url)
    assert response.status_code == 302
    assert response.url.startswith(oidc_params["redirect_uri"])
    auth_response_params = get_url_params(response.url)
    assert user.linked_applications.count() == 1
    code = auth_response_params["code"]
    assertRecords(
        caplog,
        [
            (
                "inclusion_connect.oidc",
                logging.INFO,
                {
                    "application": "my_application",
                    "event": "redirect",
                    "user": user.email,
                    "url": f"http://localhost/callback?code={code}&state=state",
                },
            )
        ],
    )

    oidc_flow_followup(client, auth_response_params, user, oidc_params, caplog)


@freeze_time("2023-05-05 11:11:11")
def test_login_after_password_reset(caplog, client, oidc_params):
    ApplicationFactory(client_id=oidc_params["client_id"])
    user = UserFactory()

    auth_url = reverse("oauth2_provider:authorize")
    auth_complete_url = add_url_params(auth_url, oidc_params)
    response = client.get(auth_complete_url)
    assertRedirects(response, reverse("accounts:login"))

    response = client.get(response.url)
    assertContains(response, reverse("accounts:password_reset"))
    assertRecords(caplog, [])

    response = client.post(reverse("accounts:password_reset"), data={"email": user.email})
    assertRedirects(response, reverse("accounts:login"))
    assertRecords(
        caplog,
        [
            (
                "inclusion_connect.auth",
                logging.INFO,
                {
                    "application": "my_application",
                    "event": "forgot_password",
                    "user": user.email,
                },
            )
        ],
    )

    assertMessages(
        response,
        [
            (
                messages.SUCCESS,
                "Si un compte existe avec cette adresse e-mail, "
                "vous recevrez un e-mail contenant des instructions pour réinitialiser votre mot de passe.",
            )
        ],
    )

    reset_url_regex = reverse("accounts:password_reset_confirm", args=("string", "string")).replace("string", "[^/]*")
    reset_url = re.search(reset_url_regex, mail.outbox[0].body)[0]
    response = client.get(reset_url)  # retrieve the modified url
    response = client.post(
        response.url,
        data={"new_password1": "V€r¥--$3©®€7", "new_password2": "V€r¥--$3©®€7"},
    )
    assertRedirects(response, auth_complete_url, fetch_redirect_response=False)
    assert get_user(client).is_authenticated is True
    assertRecords(
        caplog,
        [
            (
                "inclusion_connect.auth",
                logging.INFO,
                {
                    "application": "my_application",
                    "event": "reset_password",
                    "user": user.email,
                },
            ),
            (
                "inclusion_connect.auth",
                logging.INFO,
                {"application": "my_application", "event": "login", "user": user.email},
            ),
        ],
    )

    response = client.get(auth_complete_url)
    assert response.status_code == 302
    assert response.url.startswith(oidc_params["redirect_uri"])
    auth_response_params = get_url_params(response.url)
    code = auth_response_params["code"]
    assertRecords(
        caplog,
        [
            (
                "inclusion_connect.oidc",
                logging.INFO,
                {
                    "application": "my_application",
                    "event": "redirect",
                    "user": user.email,
                    "url": f"http://localhost/callback?code={code}&state=state",
                },
            )
        ],
    )

    oidc_flow_followup(client, auth_response_params, user, oidc_params, caplog)


@freeze_time("2023-05-05 11:11:11")
def test_login_after_password_reset_other_client(caplog, client, oidc_params):
    ApplicationFactory(client_id=oidc_params["client_id"])
    user = UserFactory()

    auth_url = reverse("oauth2_provider:authorize")
    auth_complete_url = add_url_params(auth_url, oidc_params)
    response = client.get(auth_complete_url)
    assertRedirects(response, reverse("accounts:login"))

    response = client.get(response.url)
    assertContains(response, reverse("accounts:password_reset"))
    assertRecords(caplog, [])

    response = client.post(reverse("accounts:password_reset"), data={"email": user.email})
    assertRedirects(response, reverse("accounts:login"))
    assertRecords(
        caplog,
        [
            (
                "inclusion_connect.auth",
                logging.INFO,
                {
                    "application": "my_application",
                    "event": "forgot_password",
                    "user": user.email,
                },
            )
        ],
    )

    assertMessages(
        response,
        [
            (
                messages.SUCCESS,
                "Si un compte existe avec cette adresse e-mail, "
                "vous recevrez un e-mail contenant des instructions pour réinitialiser votre mot de passe.",
            )
        ],
    )

    reset_url_regex = reverse("accounts:password_reset_confirm", args=("string", "string")).replace("string", "[^/]*")
    reset_url = re.search(reset_url_regex, mail.outbox[0].body)[0]

    other_client = Client()
    response = other_client.get(reset_url)  # retrieve the modified url
    response = other_client.post(
        response.url,
        data={"new_password1": "V€r¥--$3©®€7", "new_password2": "V€r¥--$3©®€7"},
    )
    assertRedirects(response, auth_complete_url, fetch_redirect_response=False)
    assert get_user(other_client).is_authenticated is True
    assertRecords(
        caplog,
        [
            (
                "inclusion_connect.auth",
                logging.INFO,
                {
                    "application": "my_application",
                    "event": "reset_password",
                    "user": user.email,
                },
            ),
            (
                "inclusion_connect.auth",
                logging.INFO,
                {"application": "my_application", "event": "login", "user": user.email},
            ),
        ],
    )

    response = other_client.get(auth_complete_url)
    assert response.status_code == 302
    assert response.url.startswith(oidc_params["redirect_uri"])
    auth_response_params = get_url_params(response.url)
    code = auth_response_params["code"]
    assertRecords(
        caplog,
        [
            (
                "inclusion_connect.oidc",
                logging.INFO,
                {
                    "application": "my_application",
                    "event": "redirect",
                    "user": user.email,
                    "url": f"http://localhost/callback?code={code}&state=state",
                },
            )
        ],
    )

    oidc_flow_followup(other_client, auth_response_params, user, oidc_params, caplog)


@freeze_time("2023-05-05 11:11:11")
def test_login_hint_is_preserved(caplog, client, oidc_params, snapshot):
    ApplicationFactory(client_id=oidc_params["client_id"])

    user_email = "email@mailinator.com"
    auth_url = reverse("oauth2_provider:authorize")
    auth_params = oidc_params | {"login_hint": user_email}
    auth_complete_url = add_url_params(auth_url, auth_params)
    response = client.get(auth_complete_url, follow=True)
    assertRedirects(response, reverse("accounts:login"))
    assert pretty_indented(parse_response_to_soup(response, "#id_email")) == snapshot(name="login_email_field")

    response = client.get(reverse("accounts:password_reset"))
    assert pretty_indented(parse_response_to_soup(response, "#id_email")) == snapshot(
        name="password_reset_email_field"
    )
    assertRecords(caplog, [])


def test_logout_no_confirmation(caplog, client, oidc_params):
    user = UserFactory()
    ApplicationFactory(client_id=oidc_params["client_id"])

    auth_url = reverse("oauth2_provider:authorize")
    auth_complete_url = add_url_params(auth_url, oidc_params)
    response = client.get(auth_complete_url)
    assertRedirects(response, reverse("accounts:login"))
    assertRecords(caplog, [])

    response = client.post(response.url, data={"email": user.email, "password": DEFAULT_PASSWORD})
    assert get_user(client).is_authenticated is True
    assertRecords(
        caplog,
        [
            (
                "inclusion_connect.auth",
                logging.INFO,
                {"application": "my_application", "user": user.email, "event": "login"},
            )
        ],
    )

    response = client.get(response.url)
    auth_response_params = get_url_params(response.url)
    code = auth_response_params["code"]
    assertRecords(
        caplog,
        [
            (
                "inclusion_connect.oidc",
                logging.INFO,
                {
                    "application": "my_application",
                    "event": "redirect",
                    "user": user.email,
                    "url": f"http://localhost/callback?code={code}&state=state",
                },
            )
        ],
    )
    id_token = oidc_flow_followup(client, auth_response_params, user, oidc_params, caplog)

    assert get_user(client).is_authenticated is True
    response = call_logout(
        client,
        "get",
        {"id_token_hint": id_token, "post_logout_redirect_uri": "http://callback/"},
    )
    assertRedirects(response, "http://callback/", fetch_redirect_response=False)
    assert not get_user(client).is_authenticated
    assert token_are_revoked(user)
    assertRecords(
        caplog,
        [
            (
                "inclusion_connect.oidc",
                logging.INFO,
                {
                    "application": "my_application",
                    "event": "logout",
                    "id_token_hint": id_token,
                    "post_logout_redirect_uri": "http://callback/",
                    "user": user.email,
                },
            )
        ],
    )

    response = client.get(auth_complete_url)
    assertRedirects(response, reverse("accounts:login"))


def test_logout_no_confirmation_when_session_and_tokens_already_expired_with_id_token_hint(
    caplog, client, oidc_params
):
    user = UserFactory()
    ApplicationFactory(client_id=oidc_params["client_id"])

    with freeze_time("2023-05-25 9:34"):
        auth_url = reverse("oauth2_provider:authorize")
        auth_complete_url = add_url_params(auth_url, oidc_params)
        response = client.get(auth_complete_url)
        assertRedirects(response, reverse("accounts:login"))
        assertRecords(caplog, [])

        response = client.post(response.url, data={"email": user.email, "password": DEFAULT_PASSWORD})
        assert get_user(client).is_authenticated is True
        assertRecords(
            caplog,
            [
                (
                    "inclusion_connect.auth",
                    logging.INFO,
                    {
                        "application": "my_application",
                        "user": user.email,
                        "event": "login",
                    },
                )
            ],
        )

        response = client.get(response.url)
        auth_response_params = get_url_params(response.url)
        code = auth_response_params["code"]
        assertRecords(
            caplog,
            [
                (
                    "inclusion_connect.oidc",
                    logging.INFO,
                    {
                        "application": "my_application",
                        "event": "redirect",
                        "user": user.email,
                        "url": f"http://localhost/callback?code={code}&state=state",
                    },
                )
            ],
        )
        id_token = oidc_flow_followup(client, auth_response_params, user, oidc_params, caplog)
        assert get_user(client).is_authenticated is True
        assertRecords(caplog, [])

    with freeze_time("2023-05-25 20:05"):
        assert get_user(client).is_authenticated is False
        response = call_logout(
            client,
            "get",
            {"id_token_hint": id_token, "post_logout_redirect_uri": "http://callback/"},
        )
        assertRecords(
            caplog,
            [
                (
                    "inclusion_connect.oidc",
                    logging.INFO,
                    {
                        "application": "my_application",
                        "event": "logout",
                        "id_token_hint": id_token,
                        "post_logout_redirect_uri": "http://callback/",
                        "user": user.email,
                    },
                ),
            ],
        )

        assertRedirects(response, "http://callback/", fetch_redirect_response=False)
        assert not get_user(client).is_authenticated
        assert token_are_revoked(user)

        response = client.get(auth_complete_url)
        assertRedirects(response, reverse("accounts:login"))
        assertRecords(caplog, [])


def test_logout_with_confirmation(caplog, client, oidc_params, snapshot):
    user = UserFactory()
    ApplicationFactory(client_id=oidc_params["client_id"])

    auth_url = reverse("oauth2_provider:authorize")
    auth_complete_url = add_url_params(auth_url, oidc_params)
    response = client.get(auth_complete_url)
    assertRedirects(response, reverse("accounts:login"))
    assertRecords(caplog, [])

    response = client.post(response.url, data={"email": user.email, "password": DEFAULT_PASSWORD})
    assert get_user(client).is_authenticated is True
    assertRecords(
        caplog,
        [
            (
                "inclusion_connect.auth",
                logging.INFO,
                {"application": "my_application", "user": user.email, "event": "login"},
            )
        ],
    )

    response = client.get(response.url)
    auth_response_params = get_url_params(response.url)
    code = auth_response_params["code"]
    assertRecords(
        caplog,
        [
            (
                "inclusion_connect.oidc",
                logging.INFO,
                {
                    "application": "my_application",
                    "event": "redirect",
                    "user": user.email,
                    "url": f"http://localhost/callback?code={code}&state=state",
                },
            )
        ],
    )
    oidc_flow_followup(client, auth_response_params, user, oidc_params, caplog)

    assert get_user(client).is_authenticated is True
    response = call_logout(
        client,
        "get",
        {
            "client_id": oidc_params["client_id"],
            "post_logout_redirect_uri": "http://callback/",
        },
    )
    assert response.status_code == 200
    assert pretty_indented(parse_response_to_soup(response, "#main")) == snapshot
    assertRecords(caplog, [])

    response = call_logout(
        client,
        "post",
        {
            "client_id": oidc_params["client_id"],
            "post_logout_redirect_uri": "http://callback/",
            "allow": True,
        },
    )
    assertRedirects(response, "http://callback/", fetch_redirect_response=False)
    assert not get_user(client).is_authenticated
    assert token_are_revoked(user)
    assertRecords(
        caplog,
        [
            (
                "inclusion_connect.oidc",
                logging.INFO,
                {
                    "application": "my_application",
                    "event": "logout",
                    "client_id": "my_application",
                    "post_logout_redirect_uri": "http://callback/",
                    "user": user.email,
                },
            ),
        ],
    )

    response = client.get(auth_complete_url)
    assertRedirects(response, reverse("accounts:login"))
    assertRecords(caplog, [])


def test_logout_with_confirmation_when_session_and_tokens_already_expired_with_client_id(caplog, client, oidc_params):
    user = UserFactory()
    ApplicationFactory(client_id=oidc_params["client_id"])

    with freeze_time("2023-05-25 9:34"):
        auth_url = reverse("oauth2_provider:authorize")
        auth_complete_url = add_url_params(auth_url, oidc_params)
        response = client.get(auth_complete_url)
        assertRedirects(response, reverse("accounts:login"))
        assertRecords(caplog, [])

        response = client.post(response.url, data={"email": user.email, "password": DEFAULT_PASSWORD})
        assert get_user(client).is_authenticated is True
        assertRecords(
            caplog,
            [
                (
                    "inclusion_connect.auth",
                    logging.INFO,
                    {
                        "application": "my_application",
                        "user": user.email,
                        "event": "login",
                    },
                )
            ],
        )
        response = client.get(response.url)
        auth_response_params = get_url_params(response.url)
        code = auth_response_params["code"]
        assertRecords(
            caplog,
            [
                (
                    "inclusion_connect.oidc",
                    logging.INFO,
                    {
                        "application": "my_application",
                        "event": "redirect",
                        "user": user.email,
                        "url": f"http://localhost/callback?code={code}&state=state",
                    },
                )
            ],
        )
        oidc_flow_followup(client, auth_response_params, user, oidc_params, caplog)
        assert get_user(client).is_authenticated is True
        assertRecords(caplog, [])

    with freeze_time("2023-05-25 20:05"):
        assert get_user(client).is_authenticated is False
        response = call_logout(
            client,
            "get",
            {
                "client_id": oidc_params["client_id"],
                "post_logout_redirect_uri": "http://callback/",
            },
        )
        assertRecords(
            caplog,
            [
                (
                    "inclusion_connect.oidc",
                    logging.INFO,
                    {
                        "application": "my_application",
                        "event": "logout",
                        "client_id": "my_application",
                        "post_logout_redirect_uri": "http://callback/",
                        "user": None,  # User is anonymous.
                    },
                )
            ],
        )

        assertRedirects(response, "http://callback/", fetch_redirect_response=False)
        # The user is anonymous, without the `id_token`, the system cannot identify the user.
        # Without the user, their tokens cannot be revoked.
        assert not token_are_revoked(user)

        response = client.get(auth_complete_url)
        assertRedirects(response, reverse("accounts:login"))
        assertRecords(caplog, [])


def test_change_password(caplog, client, snapshot):  # noqa: PLR0915 Too many statements
    user = UserFactory(first_name="Manuel", last_name="Calavera", email="manny.calavera@mailinator.com")
    change_password_url = reverse("accounts:change_password")

    # User is redirected to login
    response = client.get(change_password_url)
    assertRedirects(
        response,
        add_url_params(reverse("accounts:login"), {"next": change_password_url}),
    )
    response = client.post(
        response.url,
        data={"email": user.email, "password": DEFAULT_PASSWORD},
        follow=True,
    )
    assertRedirects(response, change_password_url)
    assert pretty_indented(parse_response_to_soup(response, "#main")) == snapshot

    # The redirect cleans `next_url` from the session.
    assert "next_url" not in client.session
    assertRecords(
        caplog,
        [
            (
                "inclusion_connect.auth",
                logging.INFO,
                {"user": user.email, "event": "login"},
            )
        ],
    )

    response = client.post(
        change_password_url,
        data={
            "old_password": DEFAULT_PASSWORD,
            "new_password1": "V€r¥--$3©®€7",
            "new_password2": "V€r¥--$3©®€7",
        },
    )
    assert get_user(client).is_authenticated is True
    assertRecords(
        caplog,
        [
            (
                "inclusion_connect.auth",
                logging.INFO,
                {
                    "event": "change_password",
                    "user": user.email,
                },
            )
        ],
    )

    client.logout()
    assert get_user(client).is_authenticated is False

    # User may login with new password
    response = client.post(
        reverse("accounts:login"),
        data={"email": user.email, "password": "V€r¥--$3©®€7"},
        follow=True,
    )
    assert get_user(client).is_authenticated is True
    assertRecords(
        caplog,
        [
            (
                "inclusion_connect.auth",
                logging.INFO,
                {"user": user.email, "event": "login"},
            )
        ],
    )


@freeze_time("2023-05-05 11:11:11")
def test_login_with_multiple_applications(client, oidc_params, caplog):
    user = UserFactory()
    application_1 = ApplicationFactory()
    oidc_params["client_id"] = application_1.client_id
    oidc_complete_flow(client, user, oidc_params, caplog, application=application_1)
    application_2 = ApplicationFactory()
    oidc_params["client_id"] = application_2.client_id
    oidc_complete_flow(client, user, oidc_params, caplog, application=application_2)


@freeze_time("2023-05-05 11:11:11")
def test_login_weak_password(caplog, client, oidc_params):
    auth_url = reverse("oauth2_provider:authorize")
    ApplicationFactory(client_id=oidc_params["client_id"])
    user = UserFactory(password=make_password("weak_password"))

    auth_complete_url = add_url_params(auth_url, oidc_params)
    response = client.get(auth_complete_url)
    assertRedirects(response, reverse("accounts:login"))
    assertRecords(caplog, [])

    response = client.post(
        response.url,
        data={
            "email": user.email,
            "password": "weak_password",
        },
    )
    # assert redirects to update weak password page
    assertRedirects(response, reverse("accounts:change_weak_password"))
    assert get_user(client).is_authenticated is True
    user = User.objects.get(email=user.email)
    assert user.linked_applications.count() == 0
    assertRecords(
        caplog,
        [
            (
                "inclusion_connect.auth",
                logging.INFO,
                {"application": "my_application", "user": user.email, "event": "login"},
            )
        ],
    )

    # User can't bypass password update
    response = client.get(auth_complete_url)
    assertRedirects(response, reverse("accounts:change_weak_password"))

    response = client.post(
        reverse("accounts:change_weak_password"),
        data={"new_password1": DEFAULT_PASSWORD, "new_password2": DEFAULT_PASSWORD},
    )
    assertRedirects(response, auth_complete_url, fetch_redirect_response=False)
    assertRecords(
        caplog,
        [
            (
                "inclusion_connect.auth",
                logging.INFO,
                {
                    "event": "change_weak_password",
                    "user": user.email,
                },
            )
        ],
    )

    response = client.get(auth_complete_url)
    assert response.status_code == 302
    assert response.url.startswith(oidc_params["redirect_uri"])
    auth_response_params = get_url_params(response.url)
    assert user.linked_applications.count() == 1
    code = auth_response_params["code"]
    assertRecords(
        caplog,
        [
            (
                "inclusion_connect.oidc",
                logging.INFO,
                {
                    "application": "my_application",
                    "event": "redirect",
                    "user": user.email,
                    "url": f"http://localhost/callback?code={code}&state=state",
                },
            )
        ],
    )

    oidc_flow_followup(client, auth_response_params, user, oidc_params, caplog)


def test_base_url_redirect(client):
    response = client.get(reverse("index"))
    assertRedirects(response, reverse("accounts:login"))

    client.force_login(UserFactory())
    response = client.get(reverse("index"))
    assertRedirects(response, reverse("accounts:home"))
