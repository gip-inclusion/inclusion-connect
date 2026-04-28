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
from tests.helpers import call_logout, oidc_complete_flow, oidc_flow_followup, token_are_revoked
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
                {"application": "my_application", "user": user.pk, "event": "login"},
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
                    "user": user.pk,
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
                    "user": user.pk,
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
                    "user": user.pk,
                },
            ),
            (
                "inclusion_connect.auth",
                logging.INFO,
                {"application": "my_application", "event": "login", "user": user.pk},
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
                    "user": user.pk,
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
                    "user": user.pk,
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
                    "user": user.pk,
                },
            ),
            (
                "inclusion_connect.auth",
                logging.INFO,
                {"application": "my_application", "event": "login", "user": user.pk},
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
                    "user": user.pk,
                    "url": f"http://localhost/callback?code={code}&state=state",
                },
            )
        ],
    )

    oidc_flow_followup(other_client, auth_response_params, user, oidc_params, caplog)


@freeze_time("2023-05-05 11:11:11")
def test_login_hint_is_preserved(caplog, client, oidc_params):
    ApplicationFactory(client_id=oidc_params["client_id"])

    user_email = "email@mailinator.com"
    auth_url = reverse("oauth2_provider:authorize")
    auth_params = oidc_params | {"login_hint": user_email}
    auth_complete_url = add_url_params(auth_url, auth_params)
    response = client.get(auth_complete_url, follow=True)
    assertRedirects(response, reverse("accounts:login"))
    assertContains(
        response,
        # Pre-filled with email address from login_hint.
        '<input type="email" name="email" value="email@mailinator.com" placeholder="nom@domaine.fr" '
        # Disabled, users cannot change data passed by the RP.
        'autocomplete="email" maxlength="320" class="form-control" required disabled id="id_email">',
        count=1,
    )

    response = client.get(reverse("accounts:password_reset"))
    assertContains(
        response,
        # Pre-filled with email address from login_hint.
        # Disabled, users cannot change data passed by the RP.
        '<input type="email" name="email" value="email@mailinator.com" placeholder="nom@domaine.fr" '
        'autocomplete="email" class="form-control" required disabled id="id_email">',
        count=1,
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
                {"application": "my_application", "user": user.pk, "event": "login"},
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
                    "user": user.pk,
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
                    "user": user.pk,
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
                        "user": user.pk,
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
                        "user": user.pk,
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
                        "user": user.pk,
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


def test_logout_with_confirmation(caplog, client, oidc_params):
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
                {"application": "my_application", "user": user.pk, "event": "login"},
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
                    "user": user.pk,
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
    assertContains(
        response,
        '<input type="submit" class="btn btn-block btn-primary" name="allow" value="Se déconnecter" />',
    )
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
                    "user": user.pk,
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
                        "user": user.pk,
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
                        "user": user.pk,
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
        assert response.status_code == 200
        assertContains(
            response,
            '<input type="submit" class="btn btn-block btn-primary" name="allow" value="Se déconnecter" />',
        )
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


def test_change_password(caplog, client, mailoutbox):  # noqa: PLR0915 Too many statements
    application = ApplicationFactory()
    user = UserFactory(first_name="Manuel", last_name="Calavera", email="manny.calavera@mailinator.com")
    referrer_uri = "https://go/back/there"
    params = {"referrer_uri": referrer_uri, "referrer": application.client_id}
    change_password_url = add_url_params(reverse("accounts:change_password"), params)

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
    assertContains(response, "<h1>\n                Changer mon mot de passe\n            </h1>")
    # The redirect cleans `next_url` from the session.
    assert "next_url" not in client.session
    assertRecords(
        caplog,
        [
            (
                "inclusion_connect.auth",
                logging.INFO,
                {"user": user.pk, "event": "login"},
            )
        ],
    )

    # Page contains return to referrer link
    assertContains(response, "Retour")
    assertContains(response, referrer_uri)

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
                    "user": user.pk,
                    "application": application.client_id,
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
                {"user": user.pk, "event": "login"},
            )
        ],
    )


def test_admin_session_doesnt_give_access_to_non_admin_views(client, oidc_params):
    staff_user = UserFactory(is_staff=True)
    response = client.post(
        add_url_params(reverse("admin:login"), {"next": reverse("admin:index")}),
        data={"username": staff_user.email, "password": DEFAULT_PASSWORD},
    )
    assert get_user(client) == staff_user

    # We don't have access to accounts or oidc views with staff_user
    account_url = reverse("accounts:change_password")
    response = client.get(account_url)
    assertContains(
        response,
        "Les comptes administrateurs n'ont pas accès à cette page.",
        status_code=403,
    )
    assertContains(
        response,
        add_url_params(reverse("admin:logout"), {"next": account_url}),
        status_code=403,
    )

    ApplicationFactory(client_id=oidc_params["client_id"])
    auth_complete_url = add_url_params(reverse("oauth2_provider:authorize"), oidc_params)
    response = client.get(auth_complete_url)
    assertContains(
        response,
        "Les comptes administrateurs n'ont pas accès à cette page.",
        status_code=403,
    )
    assertContains(
        response,
        add_url_params(reverse("admin:logout"), {"next": auth_complete_url}),
        status_code=403,
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
                {"application": "my_application", "user": user.pk, "event": "login"},
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
                    "user": user.pk,
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
                    "user": user.pk,
                    "url": f"http://localhost/callback?code={code}&state=state",
                },
            )
        ],
    )

    oidc_flow_followup(client, auth_response_params, user, oidc_params, caplog)
