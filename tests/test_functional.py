# Functional tests for all documented customer processes
import datetime
import logging
import re

import pytest
from django.conf import settings
from django.contrib import messages
from django.contrib.auth import get_user
from django.contrib.auth.hashers import make_password
from django.core import mail
from django.db.models import F
from django.test import override_settings
from django.urls import reverse
from freezegun import freeze_time
from pytest_django.asserts import assertContains, assertQuerySetEqual, assertRedirects

from inclusion_connect.accounts.views import EMAIL_CONFIRM_KEY
from inclusion_connect.oidc_federation.enums import Federation
from inclusion_connect.stats.models import Stats
from inclusion_connect.users.models import EmailAddress, User
from inclusion_connect.utils.urls import add_url_params, get_url_params
from tests.asserts import assertMessages, assertRecords
from tests.conftest import Client
from tests.helpers import call_logout, oidc_complete_flow, oidc_flow_followup, token_are_revoked
from tests.oidc_federation.test_peama import PEAMA_ADDITIONAL_DATA, mock_peama_oauth_dance
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
        reverse("oauth2_provider:register"),
        # Verify the GET parameter `next` does not override OIDC redirect_uri.
        f"{reverse('oauth2_provider:register')}?next=http://evil.com",
    ],
)
def test_register_endpoint(auth_url, caplog, client, oidc_params, mailoutbox):
    application = ApplicationFactory(client_id=oidc_params["client_id"])
    user = UserFactory.build(email="")

    auth_complete_url = add_url_params(auth_url, oidc_params)
    response = client.get(auth_complete_url)
    assertRedirects(response, reverse("accounts:register"))
    assertRecords(caplog, [])

    user_email = "email@mailinator.com"
    response = client.post(
        response.url,
        data={
            "email": user_email,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "password1": DEFAULT_PASSWORD,
            "password2": DEFAULT_PASSWORD,
            "terms_accepted": "on",
        },
    )
    assertRedirects(response, reverse("accounts:confirm-email"))
    assert get_user(client).is_authenticated is False
    user = User.objects.get()
    assert user.linked_applications.count() == 0
    assertRecords(
        caplog,
        [
            (
                "inclusion_connect.auth",
                logging.INFO,
                {
                    "application": "my_application",
                    "email": "email@mailinator.com",
                    "user": user.pk,
                    "event": "register",
                },
            )
        ],
    )

    [email] = mailoutbox
    assert email.subject == "Vérification de l’adresse e-mail"
    assert email.to == [user_email]
    verification_url = get_verification_link(email.body)
    response = client.get(verification_url)
    assertRedirects(response, auth_complete_url, fetch_redirect_response=False)
    assert get_user(client).is_authenticated is True
    user.refresh_from_db()
    assert user.email == user_email
    assertQuerySetEqual(
        EmailAddress.objects.values_list("user_id", "email", "verified_at"),
        [
            (
                user.pk,
                user_email,
                datetime.datetime(2023, 5, 5, 11, 11, 11, tzinfo=datetime.timezone.utc),
            )
        ],
    )
    assert user.linked_applications.count() == 0
    assertRecords(
        caplog,
        [
            (
                "inclusion_connect.auth",
                logging.INFO,
                {
                    "application": "my_application",
                    "email": "email@mailinator.com",
                    "user": user.pk,
                    "event": "confirm_email_address",
                },
            ),
            (
                "inclusion_connect.auth",
                logging.INFO,
                {
                    "application": "my_application",
                    "email": "email@mailinator.com",
                    "user": user.pk,
                    "event": "login",
                },
            ),
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
    assertQuerySetEqual(
        Stats.objects.values_list("date", "user", "application", "action").order_by("action"),
        [
            (datetime.date(2023, 5, 1), user.pk, application.pk, "login"),
            (datetime.date(2023, 5, 1), user.pk, application.pk, "register"),
        ],
    )

    oidc_flow_followup(client, auth_response_params, user, oidc_params, caplog)


@freeze_time("2023-05-05 11:11:11")
def test_register_endpoint_confirm_email_from_other_client(caplog, client, oidc_params, mailoutbox):
    application = ApplicationFactory(client_id=oidc_params["client_id"])
    user = UserFactory.build(email="")

    auth_complete_url = add_url_params(reverse("oauth2_provider:register"), oidc_params)
    response = client.get(auth_complete_url)
    assertRedirects(response, reverse("accounts:register"))
    assertRecords(caplog, [])

    user_email = "email@mailinator.com"
    response = client.post(
        response.url,
        data={
            "email": user_email,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "password1": DEFAULT_PASSWORD,
            "password2": DEFAULT_PASSWORD,
            "terms_accepted": "on",
        },
    )
    assertRedirects(response, reverse("accounts:confirm-email"))
    assert get_user(client).is_authenticated is False
    user = User.objects.get()
    assert user.linked_applications.count() == 0
    assertRecords(
        caplog,
        [
            (
                "inclusion_connect.auth",
                logging.INFO,
                {
                    "application": "my_application",
                    "email": user_email,
                    "user": user.pk,
                    "event": "register",
                },
            )
        ],
    )

    [email] = mailoutbox
    assert email.subject == "Vérification de l’adresse e-mail"
    assert email.to == [user_email]
    verification_url = get_verification_link(email.body)
    other_client = Client()
    response = other_client.get(verification_url)
    assertRedirects(response, auth_complete_url, fetch_redirect_response=False)
    assert get_user(other_client).is_authenticated is True
    user.refresh_from_db()
    assert user.email == user_email
    assertQuerySetEqual(
        EmailAddress.objects.values_list("user_id", "email", "verified_at"),
        [
            (
                user.pk,
                user_email,
                datetime.datetime(2023, 5, 5, 11, 11, 11, tzinfo=datetime.timezone.utc),
            )
        ],
    )
    assert user.linked_applications.count() == 0
    assertRecords(
        caplog,
        [
            (
                "inclusion_connect.auth",
                logging.INFO,
                {
                    "email": user_email,
                    "user": user.pk,
                    "event": "confirm_email_address",
                    "application": "my_application",
                },
            ),
            (
                "inclusion_connect.auth",
                logging.INFO,
                {
                    "email": user_email,
                    "user": user.pk,
                    "event": "login",
                    "application": "my_application",
                },
            ),
        ],
    )

    response = other_client.get(auth_complete_url)
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
    assertQuerySetEqual(
        Stats.objects.values_list("date", "user", "application", "action").order_by("action"),
        [
            (datetime.date(2023, 5, 1), user.pk, application.pk, "login"),
            (datetime.date(2023, 5, 1), user.pk, application.pk, "register"),
        ],
    )

    oidc_flow_followup(other_client, auth_response_params, user, oidc_params, caplog)


@freeze_time("2023-05-05 11:11:11")
@pytest.mark.parametrize("use_other_client", [True, False])
def test_register_endpoint_email_not_received(caplog, client, oidc_params, use_other_client):
    application = ApplicationFactory(client_id=oidc_params["client_id"])
    user = UserFactory.build(email="")

    auth_complete_url = add_url_params(reverse("oauth2_provider:register"), oidc_params)
    response = client.get(auth_complete_url)
    assertRedirects(response, reverse("accounts:register"))
    assertRecords(caplog, [])

    user_email = "email@mailinator.com"
    response = client.post(
        response.url,
        data={
            "email": user_email,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "password1": DEFAULT_PASSWORD,
            "password2": DEFAULT_PASSWORD,
            "terms_accepted": "on",
        },
    )
    assertRedirects(response, reverse("accounts:confirm-email"))
    assert get_user(client).is_authenticated is False
    user = User.objects.get()
    assert user.linked_applications.count() == 0
    assertRecords(
        caplog,
        [
            (
                "inclusion_connect.auth",
                logging.INFO,
                {
                    "application": "my_application",
                    "email": "email@mailinator.com",
                    "user": user.pk,
                    "event": "register",
                },
            )
        ],
    )

    # Support user validates the email in the admin
    admin_client = Client()
    admin_user = UserFactory(is_superuser=True, is_staff=True)
    admin_client.force_login(admin_user)
    url = reverse("admin:users_user_change", kwargs={"object_id": user.pk})
    email_address = user.email_addresses.get()
    response = admin_client.post(
        url,
        data={
            "first_name": user.first_name,
            "last_name": user.last_name,
            "email": user.email,
            "confirm_email": "on",
            "is_active": "on",
            "last_login_0": "11/05/2023",
            "last_login_1": "11:01:25",
            "date_joined_0": "11/05/2023",
            "date_joined_1": "10:59:39",
            "initial-date_joined_0": "11/05/2023",
            "initial-date_joined_1": "10:59:39",
            "email_addresses-TOTAL_FORMS": "1",
            "email_addresses-INITIAL_FORMS": "1",
            "email_addresses-MIN_NUM_FORMS": "0",
            "email_addresses-MAX_NUM_FORMS": "0",
            "email_addresses-0-id": email_address.pk,
            "email_addresses-0-user": user.pk,
            "linked_applications-TOTAL_FORMS": "0",
            "linked_applications-INITIAL_FORMS": "0",
            "linked_applications-MIN_NUM_FORMS": "0",
            "linked_applications-MAX_NUM_FORMS": "0",
            "_continue": "Enregistrer+et+continuer+les+modifications",
        },
    )
    assertRedirects(response, url)
    user.refresh_from_db()
    assert user.email == user_email
    assertRecords(
        caplog,
        [
            (
                "inclusion_connect.auth",
                logging.INFO,
                {
                    "event": "admin_change",
                    "acting_user": admin_user.pk,
                    "user": user.pk,
                    "email_confirmed": "email@mailinator.com",
                },
            )
        ],
    )

    # The user is told to go to IC login page
    other_client = Client() if use_other_client else client
    response = other_client.get(reverse("accounts:login"))
    response = other_client.post(
        reverse("accounts:login"),
        data={"email": user.email, "password": DEFAULT_PASSWORD},
    )
    assertRedirects(response, auth_complete_url, fetch_redirect_response=False)
    if use_other_client:
        assertRecords(
            caplog,
            [
                (
                    "inclusion_connect.auth",
                    logging.INFO,
                    {
                        "user": user.pk,
                        "event": "login",
                        "application": "my_application",
                    },
                )
            ],
        )
    else:
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

    response = other_client.get(auth_complete_url)
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
    assertQuerySetEqual(
        Stats.objects.values_list("date", "user", "application", "action").order_by("action"),
        [
            (datetime.date(2023, 5, 1), user.pk, application.pk, "login"),
            (datetime.date(2023, 5, 1), user.pk, application.pk, "register"),
        ],
    )

    oidc_flow_followup(other_client, auth_response_params, user, oidc_params, caplog)

    user.refresh_from_db()
    assert user.next_redirect_uri is None


@freeze_time("2023-05-05 11:11:11")
@pytest.mark.parametrize(
    "auth_url",
    [
        reverse("oauth2_provider:activate"),
        # Verify the GET parameter `next` does not override OIDC redirect_uri.
        f"{reverse('oauth2_provider:activate')}?next=http://evil.com",
    ],
)
def test_activate_endpoint(auth_url, caplog, client, oidc_params, mailoutbox):
    application = ApplicationFactory(client_id=oidc_params["client_id"])
    user = UserFactory.build(email="")

    auth_complete_url = add_url_params(auth_url, oidc_params)
    response = client.get(auth_complete_url, follow=True)
    assert response.status_code == 400
    assertRecords(
        caplog,
        [("django.request", logging.WARNING, "Bad Request: /accounts/activate/")],
    )

    user_email = "email@mailinator.com"
    auth_url = reverse("oauth2_provider:activate")
    auth_params = oidc_params | {
        "login_hint": user_email,
        "firstname": "firstname",
        "lastname": "lastname",
    }
    auth_complete_url = add_url_params(auth_url, auth_params)
    response = client.get(auth_complete_url)
    assertRedirects(response, reverse("accounts:activate"))
    activation_url = response.url
    response = client.get(activation_url)
    assertContains(response, f"Vous pouvez réutiliser celui de votre compte sur {application.name}")

    response = client.post(
        activation_url,
        data={
            "email": user_email,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "password1": DEFAULT_PASSWORD,
            "password2": DEFAULT_PASSWORD,
            "terms_accepted": "on",
        },
    )
    assertRedirects(response, reverse("accounts:confirm-email"))
    assert get_user(client).is_authenticated is False
    user = User.objects.get()
    assert user.linked_applications.count() == 0
    assertRecords(
        caplog,
        [
            (
                "inclusion_connect.auth",
                logging.INFO,
                {
                    "application": "my_application",
                    "email": "email@mailinator.com",
                    "user": user.pk,
                    "event": "activate",
                },
            )
        ],
    )

    [email] = mailoutbox
    assert email.subject == "Vérification de l’adresse e-mail"
    assert email.to == [user_email]
    verification_url = get_verification_link(email.body)
    response = client.get(verification_url)
    assertRedirects(response, auth_complete_url, fetch_redirect_response=False)
    assert get_user(client).is_authenticated is True
    user.refresh_from_db()
    assert user.email == user_email
    assertQuerySetEqual(
        EmailAddress.objects.values_list("user_id", "email", "verified_at"),
        [
            (
                user.pk,
                user_email,
                datetime.datetime(2023, 5, 5, 11, 11, 11, tzinfo=datetime.timezone.utc),
            )
        ],
    )
    assert user.linked_applications.count() == 0
    assertRecords(
        caplog,
        [
            (
                "inclusion_connect.auth",
                logging.INFO,
                {
                    "application": "my_application",
                    "email": "email@mailinator.com",
                    "user": user.pk,
                    "event": "confirm_email_address",
                },
            ),
            (
                "inclusion_connect.auth",
                logging.INFO,
                {
                    "application": "my_application",
                    "email": "email@mailinator.com",
                    "user": user.pk,
                    "event": "login",
                },
            ),
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
    assertQuerySetEqual(
        Stats.objects.values_list("date", "user", "application", "action").order_by("action"),
        [
            (datetime.date(2023, 5, 1), user.pk, application.pk, "login"),
            (datetime.date(2023, 5, 1), user.pk, application.pk, "register"),
        ],
    )

    oidc_flow_followup(client, auth_response_params, user, oidc_params, caplog)


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
    application = ApplicationFactory(client_id=oidc_params["client_id"])
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
    assertQuerySetEqual(
        Stats.objects.values_list("date", "user", "application", "action"),
        [(datetime.date(2023, 5, 1), user.pk, application.pk, "login")],
    )

    oidc_flow_followup(client, auth_response_params, user, oidc_params, caplog)


@freeze_time("2023-05-05 11:11:11")
def test_login_after_password_reset(caplog, client, oidc_params):
    application = ApplicationFactory(client_id=oidc_params["client_id"])
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
                "vous recevrez un e-mail contenant des instructions pour réinitialiser votre mot de passe."
                f'<br><a href="{settings.FAQ_URL}" class="matomo-event" data-matomo-category="aide" '
                'data-matomo-action="clic" data-matomo-name="J\'ai besoin d\'aide (mdp reset)">'
                "J’ai besoin d’aide</a>",
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
    assertQuerySetEqual(
        Stats.objects.values_list("date", "user", "application", "action"),
        [(datetime.date(2023, 5, 1), user.pk, application.pk, "login")],
    )

    oidc_flow_followup(client, auth_response_params, user, oidc_params, caplog)


@freeze_time("2023-05-05 11:11:11")
def test_login_after_password_reset_other_client(caplog, client, oidc_params):
    application = ApplicationFactory(client_id=oidc_params["client_id"])
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
                "vous recevrez un e-mail contenant des instructions pour réinitialiser votre mot de passe."
                f'<br><a href="{settings.FAQ_URL}" class="matomo-event" data-matomo-category="aide" '
                'data-matomo-action="clic" data-matomo-name="J\'ai besoin d\'aide (mdp reset)">'
                "J’ai besoin d’aide</a>",
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
    assertQuerySetEqual(
        Stats.objects.values_list("date", "user", "application", "action"),
        [(datetime.date(2023, 5, 1), user.pk, application.pk, "login")],
    )

    oidc_flow_followup(other_client, auth_response_params, user, oidc_params, caplog)


@freeze_time("2023-05-05 11:11:11")
def test_login_hint_is_preserved(caplog, client, oidc_params):
    ApplicationFactory(client_id=oidc_params["client_id"])

    user_email = "email@mailinator.com"
    auth_url = reverse("oauth2_provider:register")
    auth_params = oidc_params | {"login_hint": user_email}
    auth_complete_url = add_url_params(auth_url, auth_params)
    response = client.get(auth_complete_url, follow=True)
    assertContains(
        response,
        # Pre-filled with email address from login_hint.
        '<input type="email" name="email" value="email@mailinator.com" placeholder="nom@domaine.fr" '
        # Disabled, users cannot change data passed by the RP.
        'autocomplete="email" class="form-control" required disabled id="id_email">',
        count=1,
    )

    response = client.get(reverse("accounts:login"))
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


def test_edit_user_info_and_password(caplog, client, mailoutbox):  # noqa: PLR0915 Too many statements
    application = ApplicationFactory()
    user = UserFactory(first_name="Manuel", last_name="Calavera", email="manny.calavera@mailinator.com")
    verified_email = user.email
    referrer_uri = "https://go/back/there"
    params = {"referrer_uri": referrer_uri, "referrer": application.client_id}
    edit_user_info_url = add_url_params(reverse("accounts:edit_user_info"), params)
    change_password_url = add_url_params(reverse("accounts:change_password"), params)

    # User is redirected to login
    response = client.get(edit_user_info_url)
    assertRedirects(
        response,
        add_url_params(reverse("accounts:login"), {"next": edit_user_info_url}),
    )
    response = client.post(
        response.url,
        data={"email": user.email, "password": DEFAULT_PASSWORD},
        follow=True,
    )
    assertRedirects(response, edit_user_info_url)
    assertContains(response, "<h1>\n                Informations générales\n            </h1>")
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

    # Edit user info
    response = client.post(
        edit_user_info_url,
        data={"last_name": "Doe", "first_name": "John", "email": "my@email.com"},
    )
    assertRedirects(response, add_url_params(reverse("accounts:confirm-email"), params))
    confirm_email_url = response.url
    user.refresh_from_db()
    assert user.first_name == "John"
    assert user.last_name == "Doe"
    assert user.email == verified_email
    [old, new] = user.email_addresses.order_by(F("verified_at").asc(nulls_last=True))
    assert old.verified_at is not None
    assert old.email == verified_email
    assert new.verified_at is None
    assert new.email == "my@email.com"
    assert client.session[EMAIL_CONFIRM_KEY] == "my@email.com"
    assertRecords(
        caplog,
        [
            (
                "inclusion_connect.auth",
                logging.INFO,
                {
                    "event": "edit_user_info",
                    "user": user.pk,
                    "application": application.client_id,
                    "old_last_name": "Calavera",
                    "new_last_name": "Doe",
                    "old_first_name": "Manuel",
                    "new_first_name": "John",
                    "old_email": "manny.calavera@mailinator.com",
                    "new_email": "my@email.com",
                },
            )
        ],
    )

    [verification_email] = mailoutbox
    assert verification_email.to == ["my@email.com"]
    assert verification_email.subject == "Vérification de l’adresse e-mail"

    # send new link
    response = client.post(confirm_email_url, follow=True)
    assertRedirects(response, confirm_email_url)
    assertRecords(
        caplog,
        [
            (
                "inclusion_connect.auth",
                logging.INFO,
                {"event": "send_verification_email", "user": user.pk},
            )
        ],
    )

    # Verify email address
    verification_url = get_verification_link(verification_email.body)
    response = client.get(verification_url)
    assertRedirects(response, edit_user_info_url)
    user.refresh_from_db()
    assert user.next_redirect_uri is None
    assertRecords(
        caplog,
        [
            (
                "inclusion_connect.auth",
                logging.INFO,
                {
                    "email": "my@email.com",
                    "user": user.pk,
                    "event": "confirm_email_address",
                },
            ),
            (
                "inclusion_connect.auth",
                logging.INFO,
                {"email": "my@email.com", "user": user.pk, "event": "login"},
            ),
        ],
    )

    # Page still contains return to referrer link
    response = client.get(response.url)
    assertContains(response, "Retour")
    assertContains(response, referrer_uri)

    # Go change password
    response = client.get(change_password_url)
    assertContains(response, "<h1>\n                Changer mon mot de passe\n            </h1>")
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
        data={"email": "my@email.com", "password": "V€r¥--$3©®€7"},
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


def test_edit_user_info_and_password_with_login_hint(caplog, client, mailoutbox):  # noqa: PLR0915 Too many statements
    application = ApplicationFactory()
    user = UserFactory(first_name="Manuel", last_name="Calavera", email="manny.calavera@mailinator.com")
    referrer_uri = "https://go/back/there"
    params = {
        "referrer_uri": referrer_uri,
        "referrer": application.client_id,
        "login_hint": user.email,
    }
    edit_user_info_url = add_url_params(reverse("accounts:edit_user_info"), params)

    # User is redirected to login
    response = client.get(edit_user_info_url)
    assertRedirects(
        response,
        add_url_params(reverse("accounts:login"), {"next": edit_user_info_url}),
    )
    assertContains(
        client.get(response.url),
        # Pre-filled with email address from login_hint.
        f'<input type="email" name="email" value="{user.email}" placeholder="nom@domaine.fr" '
        # Disabled, users cannot change data passed by the RP.
        'autocomplete="email" maxlength="320" class="form-control" required disabled id="id_email">',
        count=1,
    )
    response = client.post(
        response.url,
        data={"email": user.email, "password": DEFAULT_PASSWORD},
        follow=True,
    )
    assertRedirects(response, edit_user_info_url)
    assertContains(response, "<h1>\n                Informations générales\n            </h1>")
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


def test_edit_user_info_other_client(caplog, client, oidc_params, mailoutbox):
    application = ApplicationFactory()
    user = UserFactory(first_name="Manuel", last_name="Calavera", email="manny.calavera@mailinator.com")
    verified_email = user.email
    referrer_uri = "https://go/back/there"
    params = {"referrer_uri": referrer_uri, "referrer": application.client_id}
    edit_user_info_url = add_url_params(reverse("accounts:edit_user_info"), params)

    # User is redirected to login
    response = client.get(edit_user_info_url)
    assertRedirects(
        response,
        add_url_params(reverse("accounts:login"), {"next": edit_user_info_url}),
    )
    response = client.post(
        response.url,
        data={"email": user.email, "password": DEFAULT_PASSWORD},
        follow=True,
    )
    assertRedirects(response, edit_user_info_url)
    assertContains(response, "<h1>\n                Informations générales\n            </h1>")
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

    # Edit user info
    response = client.post(
        edit_user_info_url,
        data={"last_name": "Doe", "first_name": "John", "email": "my@email.com"},
    )
    assertRedirects(response, add_url_params(reverse("accounts:confirm-email"), params))
    confirm_email_url = response.url
    user.refresh_from_db()
    assert user.first_name == "John"
    assert user.last_name == "Doe"
    assert user.email == verified_email
    [old, new] = user.email_addresses.order_by(F("verified_at").asc(nulls_last=True))
    assert old.verified_at is not None
    assert old.email == verified_email
    assert new.verified_at is None
    assert new.email == "my@email.com"
    assert client.session[EMAIL_CONFIRM_KEY] == "my@email.com"
    assertRecords(
        caplog,
        [
            (
                "inclusion_connect.auth",
                logging.INFO,
                {
                    "event": "edit_user_info",
                    "user": user.pk,
                    "application": application.client_id,
                    "old_last_name": "Calavera",
                    "new_last_name": "Doe",
                    "old_first_name": "Manuel",
                    "new_first_name": "John",
                    "old_email": "manny.calavera@mailinator.com",
                    "new_email": "my@email.com",
                },
            )
        ],
    )

    [verification_email] = mailoutbox
    assert verification_email.to == ["my@email.com"]
    assert verification_email.subject == "Vérification de l’adresse e-mail"
    verification_url = get_verification_link(verification_email.body)
    other_client = Client()
    response = other_client.get(verification_url)
    assertRedirects(response, edit_user_info_url)
    user.refresh_from_db()
    assert user.next_redirect_uri is None
    assertRecords(
        caplog,
        [
            (
                "inclusion_connect.auth",
                logging.INFO,
                {
                    "email": "my@email.com",
                    "user": user.pk,
                    "event": "confirm_email_address",
                },
            ),
            (
                "inclusion_connect.auth",
                logging.INFO,
                {"email": "my@email.com", "user": user.pk, "event": "login"},
            ),
        ],
    )

    # Page still contains return to referrer link
    response = other_client.get(response.url)
    assertContains(response, "Retour")
    assertContains(response, referrer_uri)

    # Still dsplay the return button if the user asks again for a verification e-mail
    response = client.post(confirm_email_url, follow=True)
    assertRedirects(response, edit_user_info_url)
    assertContains(response, "Retour")
    assertContains(response, referrer_uri)

    # Same thing if the user refreshes the page (why would he do that?)
    response = client.get(confirm_email_url, follow=True)
    assertRedirects(response, edit_user_info_url)
    assertContains(response, "Retour")
    assertContains(response, referrer_uri)


def test_admin_session_doesnt_give_access_to_non_admin_views(client, oidc_params):
    staff_user = UserFactory(is_staff=True)
    response = client.post(
        add_url_params(reverse("admin:login"), {"next": reverse("admin:index")}),
        data={"username": staff_user.email, "password": DEFAULT_PASSWORD},
    )
    assert get_user(client) == staff_user

    # We don't have access to accounts or oidc views with staff_user
    account_url = reverse("accounts:edit_user_info")
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
    assertQuerySetEqual(
        Stats.objects.values_list("date", "user", "application", "action"),
        [
            (datetime.date(2023, 5, 1), user.pk, application_1.pk, "login"),
            (datetime.date(2023, 5, 1), user.pk, application_2.pk, "login"),
        ],
        ordered=False,
    )


def test_use_peama(client, oidc_params, requests_mock, caplog):
    application = ApplicationFactory(client_id=oidc_params["client_id"])

    auth_url = reverse("oauth2_provider:authorize")
    auth_complete_url = add_url_params(auth_url, oidc_params)
    response = client.get(auth_complete_url)
    assertRedirects(response, reverse("accounts:login"))

    response = client.get(reverse("accounts:login"))
    assertContains(response, "Connexion agents Pôle emploi")

    response = client.get(reverse("oidc_federation:peama:init"))
    response, peama_data = mock_peama_oauth_dance(client, requests_mock, response.url)
    assertRedirects(response, reverse("accounts:accept_terms"))
    user = User.objects.get()
    assertRecords(
        caplog,
        [
            (
                "inclusion_connect.auth.oidc_federation",
                logging.INFO,
                {
                    "application": application.client_id,
                    "email": user.email,
                    "user": user.pk,
                    "event": "register",
                    "federation": Federation.PEAMA,
                },
            )
        ],
    )

    response = client.post(reverse("accounts:accept_terms"))
    assertRedirects(response, auth_complete_url, fetch_redirect_response=False)
    assertRecords(
        caplog,
        [
            (
                "inclusion_connect.auth",
                logging.INFO,
                {
                    "application": application.client_id,
                    "event": "accept_terms",
                    "user": user.pk,
                },
            )
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
                    "application": application.client_id,
                    "event": "redirect",
                    "user": user.pk,
                    "url": f"http://localhost/callback?code={code}&state=state",
                },
            )
        ],
    )

    user = User.objects.get()
    additional_claims = {
        "site_pe": PEAMA_ADDITIONAL_DATA["siteTravail"],
        "structure_pe": PEAMA_ADDITIONAL_DATA["structureTravail"],
    }
    id_token = oidc_flow_followup(client, auth_response_params, user, oidc_params, caplog, additional_claims)

    logout_endpoint = requests_mock.get(settings.PEAMA_LOGOUT_ENDPOINT, status_code=204)
    response = call_logout(
        client,
        "get",
        {"id_token_hint": id_token, "post_logout_redirect_uri": "http://callback/"},
    )
    assert logout_endpoint.call_count == 1
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
            ),
            (
                "inclusion_connect.auth.oidc_federation",
                logging.INFO,
                {
                    "user": user.pk,
                    "federation": Federation.PEAMA,
                    "application": "my_application",
                    "event": "logout_peama",
                    "id_token_hint": peama_data.access_token["id_token"],
                },
            ),
        ],
    )

    response = client.get(auth_complete_url)
    assertRedirects(response, reverse("accounts:login"))


@override_settings(FORCE_WEAK_PASSWORD_UPDATE=True)
@freeze_time("2023-05-05 11:11:11")
def test_login_weak_password(caplog, client, oidc_params):
    auth_url = reverse("oauth2_provider:authorize")
    application = ApplicationFactory(client_id=oidc_params["client_id"])
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
    assertQuerySetEqual(
        Stats.objects.values_list("date", "user", "application", "action"),
        [(datetime.date(2023, 5, 1), user.pk, application.pk, "login")],
    )

    oidc_flow_followup(client, auth_response_params, user, oidc_params, caplog)
