# Functional tests for all documented customer processes
import datetime
import logging
import re

import pytest
from django.contrib import messages
from django.contrib.auth import get_user
from django.core import mail
from django.db.models import F
from django.urls import reverse
from freezegun import freeze_time
from pytest_django.asserts import assertContains, assertQuerySetEqual, assertRedirects

from inclusion_connect.accounts.views import EMAIL_CONFIRM_KEY
from inclusion_connect.stats.models import Stats
from inclusion_connect.users.models import EmailAddress, User
from inclusion_connect.utils.urls import add_url_params, get_url_params
from tests.asserts import assertMessages
from tests.conftest import Client
from tests.helpers import call_logout, oidc_flow_followup, token_are_revoked
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
    assert caplog.record_tuples == []

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
    assert caplog.record_tuples == [
        (
            "inclusion_connect.auth",
            logging.INFO,
            "{'ip_address': '127.0.0.1', "
            "'application': 'my_application', "
            "'email': 'email@mailinator.com', "
            f"'user': UUID('{user.pk}'), "
            "'event': 'register'}",
        )
    ]
    caplog.clear()

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
        [(user.pk, user_email, datetime.datetime(2023, 5, 5, 11, 11, 11, tzinfo=datetime.timezone.utc))],
    )
    assert user.linked_applications.count() == 0
    assert caplog.record_tuples == [
        (
            "inclusion_connect.auth",
            logging.INFO,
            "{'ip_address': '127.0.0.1', "
            "'application': 'my_application', "
            "'email': 'email@mailinator.com', "
            f"'user': UUID('{user.pk}'), "
            "'event': 'confirm_email_address'}",
        ),
        (
            "inclusion_connect.auth",
            logging.INFO,
            "{'ip_address': '127.0.0.1', "
            "'application': 'my_application', "
            "'email': 'email@mailinator.com', "
            f"'user': UUID('{user.pk}'), "
            "'event': 'login'}",
        ),
    ]
    caplog.clear()

    response = client.get(auth_complete_url)
    assert response.status_code == 302
    assert response.url.startswith(oidc_params["redirect_uri"])
    auth_response_params = get_url_params(response.url)
    assert user.linked_applications.count() == 1
    code = auth_response_params["code"]
    assert caplog.record_tuples == [
        (
            "inclusion_connect.oidc",
            logging.INFO,
            "{'ip_address': '127.0.0.1', "
            "'application': 'my_application', "
            "'event': 'redirect', "
            f"'user': UUID('{user.pk}'), "
            f"'url': 'http://localhost/callback?code={code}&state=state'"
            "}",
        )
    ]
    caplog.clear()
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
    assert caplog.record_tuples == []

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
    assert caplog.record_tuples == [
        (
            "inclusion_connect.auth",
            logging.INFO,
            "{'ip_address': '127.0.0.1', "
            "'application': 'my_application', "
            f"'email': '{user_email}', "
            f"'user': UUID('{user.pk}'), "
            "'event': 'register'"
            "}",
        )
    ]
    caplog.clear()

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
        [(user.pk, user_email, datetime.datetime(2023, 5, 5, 11, 11, 11, tzinfo=datetime.timezone.utc))],
    )
    assert user.linked_applications.count() == 0
    assert caplog.record_tuples == [
        (
            "inclusion_connect.auth",
            logging.INFO,
            "{'ip_address': '127.0.0.1', "
            f"'email': '{user_email}', "
            f"'user': UUID('{user.pk}'), "
            "'event': 'confirm_email_address', "
            "'application': 'my_application'"
            "}",
        ),
        (
            "inclusion_connect.auth",
            logging.INFO,
            "{'ip_address': '127.0.0.1', "
            f"'email': '{user_email}', "
            f"'user': UUID('{user.pk}'), "
            "'event': 'login', "
            "'application': 'my_application'"
            "}",
        ),
    ]
    caplog.clear()

    response = other_client.get(auth_complete_url)
    assert response.status_code == 302
    assert response.url.startswith(oidc_params["redirect_uri"])
    auth_response_params = get_url_params(response.url)
    assert user.linked_applications.count() == 1
    code = auth_response_params["code"]
    assert caplog.record_tuples == [
        (
            "inclusion_connect.oidc",
            logging.INFO,
            "{'ip_address': '127.0.0.1', "
            "'application': 'my_application', "
            "'event': 'redirect', "
            f"'user': UUID('{user.pk}'), "
            f"'url': 'http://localhost/callback?code={code}&state=state'"
            "}",
        )
    ]
    caplog.clear()
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
    assert caplog.record_tuples == []

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
    assert caplog.record_tuples == [
        (
            "inclusion_connect.auth",
            logging.INFO,
            "{'ip_address': '127.0.0.1', "
            "'application': 'my_application', "
            "'email': 'email@mailinator.com', "
            f"'user': UUID('{user.pk}'), "
            "'event': 'register'}",
        )
    ]
    caplog.clear()

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
    assert caplog.record_tuples == [
        (
            "inclusion_connect.auth",
            logging.INFO,
            "{'ip_address': '127.0.0.1', "
            "'event': 'admin_change', "
            f"'acting_user': UUID('{admin_user.pk}'), "
            f"'user': UUID('{user.pk}'), "
            "'email_confirmed': 'email@mailinator.com'"
            "}",
        )
    ]
    caplog.clear()

    # The user is told to go to IC login page
    other_client = Client() if use_other_client else client
    response = other_client.get(reverse("accounts:login"))
    response = other_client.post(
        reverse("accounts:login"),
        data={"email": user.email, "password": DEFAULT_PASSWORD},
    )
    assertRedirects(response, auth_complete_url, fetch_redirect_response=False)
    # 'application' not available, OIDC params were stored in session,
    # and users lose their sessions when changing browsers.
    # It is simply nice to have, a best effort solution is OK.
    maybe_application = "" if use_other_client else "'application': 'my_application', "
    assert caplog.record_tuples == [
        (
            "inclusion_connect.auth",
            logging.INFO,
            "{'ip_address': '127.0.0.1', " + maybe_application + "'user': UUID('%s'), 'event': 'login'}" % user.pk,
        )
    ]
    caplog.clear()

    response = other_client.get(auth_complete_url)
    assert response.status_code == 302
    assert response.url.startswith(oidc_params["redirect_uri"])
    auth_response_params = get_url_params(response.url)
    assert user.linked_applications.count() == 1
    code = auth_response_params["code"]
    assert caplog.record_tuples == [
        (
            "inclusion_connect.oidc",
            logging.INFO,
            "{'ip_address': '127.0.0.1', "
            # auth_complete_url contains the client_id, 'application' can be logged.
            "'application': 'my_application', "
            "'event': 'redirect', "
            f"'user': UUID('{user.pk}'), "
            f"'url': 'http://localhost/callback?code={code}&state=state'"
            "}",
        )
    ]
    caplog.clear()
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
    assert caplog.record_tuples == [("django.request", logging.WARNING, "Bad Request: /accounts/activate/")]
    caplog.clear()

    user_email = "email@mailinator.com"
    auth_url = reverse("oauth2_provider:activate")
    auth_params = oidc_params | {"login_hint": user_email, "firstname": "firstname", "lastname": "lastname"}
    auth_complete_url = add_url_params(auth_url, auth_params)
    response = client.get(auth_complete_url)
    assertRedirects(response, reverse("accounts:activate"))

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
    assert caplog.record_tuples == [
        (
            "inclusion_connect.auth",
            logging.INFO,
            "{'ip_address': '127.0.0.1', "
            "'application': 'my_application', "
            "'email': 'email@mailinator.com', "
            f"'user': UUID('{user.pk}'), "
            "'event': 'activate'}",
        )
    ]
    caplog.clear()

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
        [(user.pk, user_email, datetime.datetime(2023, 5, 5, 11, 11, 11, tzinfo=datetime.timezone.utc))],
    )
    assert user.linked_applications.count() == 0
    assert caplog.record_tuples == [
        (
            "inclusion_connect.auth",
            logging.INFO,
            # 'application' not available, OIDC params were stored in session,
            # and users lose their sessions when changing browsers.
            # It is simply nice to have, a best effort solution is OK.
            "{'ip_address': '127.0.0.1', "
            "'application': 'my_application', "
            "'email': 'email@mailinator.com', "
            f"'user': UUID('{user.pk}'), "
            "'event': 'confirm_email_address'"
            "}",
        ),
        (
            "inclusion_connect.auth",
            logging.INFO,
            # 'application' not available, OIDC params were stored in session,
            # and users lose their sessions when changing browsers.
            # It is simply nice to have, a best effort solution is OK.
            "{'ip_address': '127.0.0.1', "
            "'application': 'my_application', "
            "'email': 'email@mailinator.com', "
            f"'user': UUID('{user.pk}'), "
            "'event': 'login'"
            "}",
        ),
    ]
    caplog.clear()

    response = client.get(auth_complete_url)
    assert response.status_code == 302
    assert response.url.startswith(oidc_params["redirect_uri"])
    auth_response_params = get_url_params(response.url)
    assert user.linked_applications.count() == 1
    code = auth_response_params["code"]
    assert caplog.record_tuples == [
        (
            "inclusion_connect.oidc",
            logging.INFO,
            "{'ip_address': '127.0.0.1', "
            # auth_complete_url contains the client_id, 'application' can be logged.
            "'application': 'my_application', "
            "'event': 'redirect', "
            f"'user': UUID('{user.pk}'), "
            f"'url': 'http://localhost/callback?code={code}&state=state'"
            "}",
        )
    ]
    caplog.clear()
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
    assert caplog.record_tuples == []

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
    assert caplog.record_tuples == [
        (
            "inclusion_connect.auth",
            logging.INFO,
            "{'ip_address': '127.0.0.1', "
            "'application': 'my_application', "
            f"'user': UUID('{user.pk}'), "
            "'event': 'login'}",
        )
    ]
    caplog.clear()

    response = client.get(auth_complete_url)
    assert response.status_code == 302
    assert response.url.startswith(oidc_params["redirect_uri"])
    auth_response_params = get_url_params(response.url)
    assert user.linked_applications.count() == 1
    code = auth_response_params["code"]
    assert caplog.record_tuples == [
        (
            "inclusion_connect.oidc",
            logging.INFO,
            "{'ip_address': '127.0.0.1', "
            "'application': 'my_application', "
            "'event': 'redirect', "
            f"'user': UUID('{user.pk}'), "
            f"'url': 'http://localhost/callback?code={code}&state=state'"
            "}",
        )
    ]
    caplog.clear()
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
    assert caplog.record_tuples == []

    response = client.post(reverse("accounts:password_reset"), data={"email": user.email})
    assertRedirects(response, reverse("accounts:login"))
    assert caplog.record_tuples == [
        (
            "inclusion_connect.auth",
            logging.INFO,
            "{'ip_address': '127.0.0.1', "
            "'application': 'my_application', "
            "'event': 'forgot_password', "
            "'user': UUID('%s')}" % user.pk,
        )
    ]
    caplog.clear()

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
    response = client.post(response.url, data={"new_password1": "V€r¥--$3©®€7", "new_password2": "V€r¥--$3©®€7"})
    assertRedirects(response, auth_complete_url, fetch_redirect_response=False)
    assert get_user(client).is_authenticated is True
    assert caplog.record_tuples == [
        (
            "inclusion_connect.auth",
            logging.INFO,
            "{'ip_address': '127.0.0.1', "
            "'application': 'my_application', "
            "'event': 'reset_password', "
            "'user': UUID('%s')}" % user.pk,
        ),
        (
            "inclusion_connect.auth",
            logging.INFO,
            "{'ip_address': '127.0.0.1', "
            "'application': 'my_application', "
            "'event': 'login', "
            "'user': UUID('%s')}" % user.pk,
        ),
    ]
    caplog.clear()

    response = client.get(auth_complete_url)
    assert response.status_code == 302
    assert response.url.startswith(oidc_params["redirect_uri"])
    auth_response_params = get_url_params(response.url)
    code = auth_response_params["code"]
    assert caplog.record_tuples == [
        (
            "inclusion_connect.oidc",
            logging.INFO,
            "{'ip_address': '127.0.0.1', "
            "'application': 'my_application', "
            "'event': 'redirect', "
            f"'user': UUID('{user.pk}'), "
            f"'url': 'http://localhost/callback?code={code}&state=state'"
            "}",
        )
    ]
    caplog.clear()
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
    assert caplog.record_tuples == []

    response = client.post(reverse("accounts:password_reset"), data={"email": user.email})
    assertRedirects(response, reverse("accounts:login"))
    assert caplog.record_tuples == [
        (
            "inclusion_connect.auth",
            logging.INFO,
            "{'ip_address': '127.0.0.1', "
            "'application': 'my_application', "
            "'event': 'forgot_password', "
            "'user': UUID('%s')}" % user.pk,
        )
    ]
    caplog.clear()

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
    response = other_client.post(response.url, data={"new_password1": "V€r¥--$3©®€7", "new_password2": "V€r¥--$3©®€7"})
    assertRedirects(response, auth_complete_url, fetch_redirect_response=False)
    assert get_user(other_client).is_authenticated is True
    assert caplog.record_tuples == [
        (
            "inclusion_connect.auth",
            logging.INFO,
            "{'ip_address': '127.0.0.1', "
            "'application': 'my_application', "
            "'event': 'reset_password', "
            "'user': UUID('%s')}" % user.pk,
        ),
        (
            "inclusion_connect.auth",
            logging.INFO,
            "{'ip_address': '127.0.0.1', "
            "'application': 'my_application', "
            "'event': 'login', "
            "'user': UUID('%s')}" % user.pk,
        ),
    ]
    caplog.clear()

    response = other_client.get(auth_complete_url)
    assert response.status_code == 302
    assert response.url.startswith(oidc_params["redirect_uri"])
    auth_response_params = get_url_params(response.url)
    code = auth_response_params["code"]
    assert caplog.record_tuples == [
        (
            "inclusion_connect.oidc",
            logging.INFO,
            "{'ip_address': '127.0.0.1', "
            "'application': 'my_application', "
            "'event': 'redirect', "
            f"'user': UUID('{user.pk}'), "
            f"'url': 'http://localhost/callback?code={code}&state=state'"
            "}",
        )
    ]
    caplog.clear()
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
        'autocomplete="email" class="form-control" title="" required disabled id="id_email">',
        count=1,
    )

    response = client.get(reverse("accounts:login"))
    assertContains(
        response,
        # Pre-filled with email address from login_hint.
        '<input type="email" name="email" value="email@mailinator.com" placeholder="nom@domaine.fr" '
        # Disabled, users cannot change data passed by the RP.
        'autocomplete="email" maxlength="320" class="form-control" title="" required disabled id="id_email">',
        count=1,
    )

    response = client.get(reverse("accounts:password_reset"))
    assertContains(
        response,
        # Pre-filled with email address from login_hint.
        # Disabled, users cannot change data passed by the RP.
        '<input type="email" name="email" value="email@mailinator.com" placeholder="nom@domaine.fr" '
        'autocomplete="email" class="form-control" title="" required disabled id="id_email">',
        count=1,
    )

    assert caplog.record_tuples == []


def test_logout_no_confirmation(caplog, client, oidc_params):
    user = UserFactory()
    ApplicationFactory(client_id=oidc_params["client_id"])

    auth_url = reverse("oauth2_provider:authorize")
    auth_complete_url = add_url_params(auth_url, oidc_params)
    response = client.get(auth_complete_url)
    assertRedirects(response, reverse("accounts:login"))
    assert caplog.record_tuples == []

    response = client.post(response.url, data={"email": user.email, "password": DEFAULT_PASSWORD})
    assert get_user(client).is_authenticated is True
    assert caplog.record_tuples == [
        (
            "inclusion_connect.auth",
            logging.INFO,
            "{'ip_address': '127.0.0.1', 'application': 'my_application', "
            "'user': UUID('%s'), 'event': 'login'}" % user.pk,
        )
    ]
    caplog.clear()

    response = client.get(response.url)
    auth_response_params = get_url_params(response.url)
    code = auth_response_params["code"]
    assert caplog.record_tuples == [
        (
            "inclusion_connect.oidc",
            logging.INFO,
            "{'ip_address': '127.0.0.1', "
            "'application': 'my_application', "
            "'event': 'redirect', "
            f"'user': UUID('{user.pk}'), "
            f"'url': 'http://localhost/callback?code={code}&state=state'"
            "}",
        )
    ]
    caplog.clear()
    id_token = oidc_flow_followup(client, auth_response_params, user, oidc_params, caplog)

    assert get_user(client).is_authenticated is True
    response = call_logout(client, "get", {"id_token_hint": id_token, "post_logout_redirect_uri": "http://callback/"})
    assertRedirects(response, "http://callback/", fetch_redirect_response=False)
    assert not get_user(client).is_authenticated
    assert token_are_revoked(user)
    assert caplog.record_tuples == [
        (
            "inclusion_connect.oidc",
            logging.INFO,
            "{'ip_address': '127.0.0.1', "
            "'application': 'my_application', "
            "'event': 'logout', "
            f"'id_token_hint': '{id_token}', "
            "'post_logout_redirect_uri': 'http://callback/', "
            f"'user': UUID('{user.pk}')"
            "}",
        )
    ]
    caplog.clear()

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
        assert caplog.record_tuples == []

        response = client.post(response.url, data={"email": user.email, "password": DEFAULT_PASSWORD})
        assert get_user(client).is_authenticated is True
        assert caplog.record_tuples == [
            (
                "inclusion_connect.auth",
                logging.INFO,
                "{'ip_address': '127.0.0.1', 'application': 'my_application', "
                "'user': UUID('%s'), 'event': 'login'}" % user.pk,
            )
        ]
        caplog.clear()

        response = client.get(response.url)
        auth_response_params = get_url_params(response.url)
        code = auth_response_params["code"]
        assert caplog.record_tuples == [
            (
                "inclusion_connect.oidc",
                logging.INFO,
                "{'ip_address': '127.0.0.1', "
                "'application': 'my_application', "
                "'event': 'redirect', "
                f"'user': UUID('{user.pk}'), "
                f"'url': 'http://localhost/callback?code={code}&state=state'"
                "}",
            )
        ]
        caplog.clear()
        id_token = oidc_flow_followup(client, auth_response_params, user, oidc_params, caplog)
        assert get_user(client).is_authenticated is True
        assert caplog.record_tuples == []

    with freeze_time("2023-05-25 20:05"):
        assert get_user(client).is_authenticated is False
        response = call_logout(
            client, "get", {"id_token_hint": id_token, "post_logout_redirect_uri": "http://callback/"}
        )
        assert caplog.record_tuples == [
            (
                "inclusion_connect.oidc",
                logging.INFO,
                "{'ip_address': '127.0.0.1', "
                "'application': 'my_application', "
                "'event': 'logout', "
                f"'id_token_hint': '{id_token}', "
                "'post_logout_redirect_uri': 'http://callback/', "
                f"'user': UUID('{user.pk}')"
                "}",
            )
        ]
        caplog.clear()

        assertRedirects(response, "http://callback/", fetch_redirect_response=False)
        assert not get_user(client).is_authenticated
        assert token_are_revoked(user)

        response = client.get(auth_complete_url)
        assertRedirects(response, reverse("accounts:login"))
        assert caplog.record_tuples == []


def test_logout_with_confirmation(caplog, client, oidc_params):
    user = UserFactory()
    ApplicationFactory(client_id=oidc_params["client_id"])

    auth_url = reverse("oauth2_provider:authorize")
    auth_complete_url = add_url_params(auth_url, oidc_params)
    response = client.get(auth_complete_url)
    assertRedirects(response, reverse("accounts:login"))
    assert caplog.record_tuples == []

    response = client.post(response.url, data={"email": user.email, "password": DEFAULT_PASSWORD})
    assert get_user(client).is_authenticated is True
    assert caplog.record_tuples == [
        (
            "inclusion_connect.auth",
            logging.INFO,
            "{'ip_address': '127.0.0.1', 'application': 'my_application', "
            "'user': UUID('%s'), 'event': 'login'}" % user.pk,
        )
    ]
    caplog.clear()

    response = client.get(response.url)
    auth_response_params = get_url_params(response.url)
    code = auth_response_params["code"]
    assert caplog.record_tuples == [
        (
            "inclusion_connect.oidc",
            logging.INFO,
            "{'ip_address': '127.0.0.1', "
            "'application': 'my_application', "
            "'event': 'redirect', "
            f"'user': UUID('{user.pk}'), "
            f"'url': 'http://localhost/callback?code={code}&state=state'"
            "}",
        )
    ]
    caplog.clear()
    oidc_flow_followup(client, auth_response_params, user, oidc_params, caplog)

    assert get_user(client).is_authenticated is True
    response = call_logout(
        client, "get", {"client_id": oidc_params["client_id"], "post_logout_redirect_uri": "http://callback/"}
    )
    assert response.status_code == 200
    assertContains(
        response,
        '<input type="submit" class="btn btn-block btn-primary" name="allow" value="Se déconnecter" />',
    )
    assert caplog.record_tuples == []

    response = call_logout(
        client,
        "post",
        {"client_id": oidc_params["client_id"], "post_logout_redirect_uri": "http://callback/", "allow": True},
    )
    assertRedirects(response, "http://callback/", fetch_redirect_response=False)
    assert not get_user(client).is_authenticated
    assert token_are_revoked(user)
    assert caplog.record_tuples == [
        (
            "inclusion_connect.oidc",
            logging.INFO,
            "{'ip_address': '127.0.0.1', "
            "'application': 'my_application', "
            "'event': 'logout', "
            "'client_id': 'my_application', "
            "'post_logout_redirect_uri': 'http://callback/', "
            f"'user': UUID('{user.pk}')"
            "}",
        )
    ]
    caplog.clear()

    response = client.get(auth_complete_url)
    assertRedirects(response, reverse("accounts:login"))
    assert caplog.record_tuples == []


def test_logout_with_confirmation_when_session_and_tokens_already_expired_with_client_id(caplog, client, oidc_params):
    user = UserFactory()
    ApplicationFactory(client_id=oidc_params["client_id"])

    with freeze_time("2023-05-25 9:34"):
        auth_url = reverse("oauth2_provider:authorize")
        auth_complete_url = add_url_params(auth_url, oidc_params)
        response = client.get(auth_complete_url)
        assertRedirects(response, reverse("accounts:login"))
        assert caplog.record_tuples == []

        response = client.post(response.url, data={"email": user.email, "password": DEFAULT_PASSWORD})
        assert get_user(client).is_authenticated is True
        assert caplog.record_tuples == [
            (
                "inclusion_connect.auth",
                logging.INFO,
                "{'ip_address': '127.0.0.1', 'application': 'my_application', "
                "'user': UUID('%s'), 'event': 'login'}" % user.pk,
            )
        ]
        caplog.clear()
        response = client.get(response.url)
        auth_response_params = get_url_params(response.url)
        code = auth_response_params["code"]
        assert caplog.record_tuples == [
            (
                "inclusion_connect.oidc",
                logging.INFO,
                "{'ip_address': '127.0.0.1', "
                "'application': 'my_application', "
                "'event': 'redirect', "
                f"'user': UUID('{user.pk}'), "
                f"'url': 'http://localhost/callback?code={code}&state=state'"
                "}",
            )
        ]
        caplog.clear()
        oidc_flow_followup(client, auth_response_params, user, oidc_params, caplog)
        assert get_user(client).is_authenticated is True
        assert caplog.record_tuples == []

    with freeze_time("2023-05-25 20:05"):
        assert get_user(client).is_authenticated is False
        response = call_logout(
            client, "get", {"client_id": oidc_params["client_id"], "post_logout_redirect_uri": "http://callback/"}
        )
        assert response.status_code == 200
        assertContains(
            response,
            '<input type="submit" class="btn btn-block btn-primary" name="allow" value="Se déconnecter" />',
        )
        assert caplog.record_tuples == []

        response = call_logout(
            client,
            "post",
            {"client_id": oidc_params["client_id"], "post_logout_redirect_uri": "http://callback/", "allow": True},
        )
        assert caplog.record_tuples == [
            (
                "inclusion_connect.oidc",
                logging.INFO,
                "{'ip_address': '127.0.0.1', "
                "'application': 'my_application', "
                "'event': 'logout', "
                "'client_id': 'my_application', "
                "'post_logout_redirect_uri': 'http://callback/', "
                "'user': None}",  # User is anonymous.
            )
        ]
        caplog.clear()

        assertRedirects(response, "http://callback/", fetch_redirect_response=False)
        # The user is anonymous, without the `id_token`, the system cannot identify the user.
        # Without the user, their tokens cannot be revoked.
        assert not token_are_revoked(user)

        response = client.get(auth_complete_url)
        assertRedirects(response, reverse("accounts:login"))
        assert caplog.record_tuples == []


def test_edit_user_info_and_password(caplog, client, mailoutbox):  # noqa: PLR0915 Too many statements
    user = UserFactory(first_name="Manuel", last_name="Calavera", email="manny.calavera@mailinator.com")
    verified_email = user.email
    referrer_uri = "https://go/back/there"
    edit_user_info_url = add_url_params(reverse("accounts:edit_user_info"), {"referrer_uri": referrer_uri})
    change_password_url = add_url_params(reverse("accounts:change_password"), {"referrer_uri": referrer_uri})

    # User is redirected to login
    response = client.get(edit_user_info_url)
    assertRedirects(response, add_url_params(reverse("accounts:login"), {"next": edit_user_info_url}))
    response = client.post(response.url, data={"email": user.email, "password": DEFAULT_PASSWORD}, follow=True)
    assertRedirects(response, edit_user_info_url)
    assertContains(response, "<h1>\n                Informations générales\n            </h1>")
    # The redirect cleans `next_url` from the session.
    assert "next_url" not in client.session
    assert caplog.record_tuples == [
        (
            "inclusion_connect.auth",
            logging.INFO,
            "{'ip_address': '127.0.0.1', 'user': UUID('%s'), 'event': 'login'}" % user.pk,
        )
    ]
    caplog.clear()

    # Page contains return to referrer link
    assertContains(response, "Retour")
    assertContains(response, referrer_uri)

    # Edit user info
    response = client.post(
        edit_user_info_url,
        data={"last_name": "Doe", "first_name": "John", "email": "my@email.com"},
    )
    assertRedirects(response, add_url_params(reverse("accounts:confirm-email"), {"referrer_uri": referrer_uri}))
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
    assert caplog.record_tuples == [
        (
            "inclusion_connect.auth",
            logging.INFO,
            "{'ip_address': '127.0.0.1', "
            "'event': 'edit_user_info', "
            f"'user': UUID('{user.pk}'), "
            "'params': {'referrer_uri': 'https://go/back/there'}, "
            "'old_last_name': 'Calavera', "
            "'new_last_name': 'Doe', "
            "'old_first_name': 'Manuel', "
            "'new_first_name': 'John', "
            "'old_email': 'manny.calavera@mailinator.com', "
            "'new_email': 'my@email.com'"
            "}",
        )
    ]
    caplog.clear()

    [verification_email] = mailoutbox
    assert verification_email.to == ["my@email.com"]
    assert verification_email.subject == "Vérification de l’adresse e-mail"

    # send new link
    response = client.post(confirm_email_url, follow=True)
    assertRedirects(response, confirm_email_url)
    assert caplog.record_tuples == [
        (
            "inclusion_connect.auth",
            logging.INFO,
            "{'ip_address': '127.0.0.1', 'event': 'send_verification_email', 'user': UUID('%s')}" % user.pk,
        )
    ]
    caplog.clear()

    # Verify email address
    verification_url = get_verification_link(verification_email.body)
    response = client.get(verification_url)
    assertRedirects(response, edit_user_info_url)
    user.refresh_from_db()
    assert user.next_redirect_uri is None
    assert caplog.record_tuples == [
        (
            "inclusion_connect.auth",
            logging.INFO,
            "{'ip_address': '127.0.0.1', "
            "'email': 'my@email.com', "
            f"'user': UUID('{user.pk}'), "
            "'event': 'confirm_email_address'}",
        ),
        (
            "inclusion_connect.auth",
            logging.INFO,
            "{'ip_address': '127.0.0.1', "
            "'email': 'my@email.com', "
            f"'user': UUID('{user.pk}'), "
            "'event': 'login'}",
        ),
    ]
    caplog.clear()

    # Page still contains return to referrer link
    response = client.get(response.url)
    assertContains(response, "Retour")
    assertContains(response, referrer_uri)

    # Go change password
    response = client.get(change_password_url)
    assertContains(response, "<h1>\n                Changer mon mot de passe\n            </h1>")
    response = client.post(
        change_password_url,
        data={"old_password": DEFAULT_PASSWORD, "new_password1": "V€r¥--$3©®€7", "new_password2": "V€r¥--$3©®€7"},
    )
    assert get_user(client).is_authenticated is True
    assert caplog.record_tuples == [
        (
            "inclusion_connect.auth",
            logging.INFO,
            "{'ip_address': '127.0.0.1', "
            "'event': 'change_password', "
            f"'user': UUID('{user.pk}'), "
            "'params': {'referrer_uri': 'https://go/back/there'}"
            "}",
        )
    ]
    caplog.clear()

    client.logout()
    assert get_user(client).is_authenticated is False

    # User may login with new password
    response = client.post(
        reverse("accounts:login"), data={"email": "my@email.com", "password": "V€r¥--$3©®€7"}, follow=True
    )
    assert get_user(client).is_authenticated is True
    assert caplog.record_tuples == [
        (
            "inclusion_connect.auth",
            logging.INFO,
            "{'ip_address': '127.0.0.1', 'user': UUID('%s'), 'event': 'login'}" % user.pk,
        )
    ]


def test_edit_user_info_other_client(caplog, client, oidc_params, mailoutbox):
    user = UserFactory(first_name="Manuel", last_name="Calavera", email="manny.calavera@mailinator.com")
    verified_email = user.email
    referrer_uri = "https://go/back/there"
    edit_user_info_url = add_url_params(reverse("accounts:edit_user_info"), {"referrer_uri": referrer_uri})

    # User is redirected to login
    response = client.get(edit_user_info_url)
    assertRedirects(response, add_url_params(reverse("accounts:login"), {"next": edit_user_info_url}))
    response = client.post(response.url, data={"email": user.email, "password": DEFAULT_PASSWORD}, follow=True)
    assertRedirects(response, edit_user_info_url)
    assertContains(response, "<h1>\n                Informations générales\n            </h1>")
    # The redirect cleans `next_url` from the session.
    assert "next_url" not in client.session
    assert caplog.record_tuples == [
        (
            "inclusion_connect.auth",
            logging.INFO,
            "{'ip_address': '127.0.0.1', 'user': UUID('%s'), 'event': 'login'}" % user.pk,
        )
    ]
    caplog.clear()

    # Page contains return to referrer link
    assertContains(response, "Retour")
    assertContains(response, referrer_uri)

    # Edit user info
    response = client.post(
        edit_user_info_url,
        data={"last_name": "Doe", "first_name": "John", "email": "my@email.com"},
    )
    assertRedirects(response, add_url_params(reverse("accounts:confirm-email"), {"referrer_uri": referrer_uri}))
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
    assert caplog.record_tuples == [
        (
            "inclusion_connect.auth",
            logging.INFO,
            "{'ip_address': '127.0.0.1', "
            "'event': 'edit_user_info', "
            f"'user': UUID('{user.pk}'), "
            "'params': {'referrer_uri': 'https://go/back/there'}, "
            "'old_last_name': 'Calavera', "
            "'new_last_name': 'Doe', "
            "'old_first_name': 'Manuel', "
            "'new_first_name': 'John', "
            "'old_email': 'manny.calavera@mailinator.com', "
            "'new_email': 'my@email.com'"
            "}",
        )
    ]
    caplog.clear()

    [verification_email] = mailoutbox
    assert verification_email.to == ["my@email.com"]
    assert verification_email.subject == "Vérification de l’adresse e-mail"
    verification_url = get_verification_link(verification_email.body)
    other_client = Client()
    response = other_client.get(verification_url)
    assertRedirects(response, edit_user_info_url)
    user.refresh_from_db()
    assert user.next_redirect_uri is None
    assert caplog.record_tuples == [
        (
            "inclusion_connect.auth",
            logging.INFO,
            "{'ip_address': '127.0.0.1', "
            "'email': 'my@email.com', "
            f"'user': UUID('{user.pk}'), "
            "'event': 'confirm_email_address'}",
        ),
        (
            "inclusion_connect.auth",
            logging.INFO,
            "{'ip_address': '127.0.0.1', "
            "'email': 'my@email.com', "
            f"'user': UUID('{user.pk}'), "
            "'event': 'login'}",
        ),
    ]
    caplog.clear()

    # Page still contains return to referrer link
    response = other_client.get(response.url)
    assertContains(response, "Retour")
    assertContains(response, referrer_uri)

    # Still dsplay the return button if the user asks again for a verification e-mail
    response = client.post(confirm_email_url, follow=True)
    assertRedirects(response, add_url_params(reverse("accounts:edit_user_info"), {"referrer_uri": referrer_uri}))
    assertContains(response, "Retour")
    assertContains(response, referrer_uri)

    # Same thing if the user refreshes the page (why would he do that?)
    response = client.get(confirm_email_url, follow=True)
    assertRedirects(response, add_url_params(reverse("accounts:edit_user_info"), {"referrer_uri": referrer_uri}))
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
    assertContains(response, "Les comptes administrateurs n'ont pas accès à cette page.", status_code=403)
    assertContains(response, add_url_params(reverse("admin:logout"), {"next": account_url}), status_code=403)

    ApplicationFactory(client_id=oidc_params["client_id"])
    auth_complete_url = add_url_params(reverse("oauth2_provider:authorize"), oidc_params)
    response = client.get(auth_complete_url)
    assertContains(response, "Les comptes administrateurs n'ont pas accès à cette page.", status_code=403)
    assertContains(response, add_url_params(reverse("admin:logout"), {"next": auth_complete_url}), status_code=403)
