# Functional tests for all documented customer processes
import datetime
import re

import pytest
from django.contrib import messages
from django.contrib.auth import get_user
from django.core import mail
from django.db.models import F
from django.urls import reverse
from freezegun import freeze_time
from pytest_django.asserts import assertContains, assertQuerysetEqual, assertRedirects

from inclusion_connect.accounts.views import EMAIL_CONFIRM_KEY
from inclusion_connect.users.models import EmailAddress, User
from inclusion_connect.utils.urls import add_url_params, get_url_params
from tests.asserts import assertMessages
from tests.helpers import OIDC_PARAMS, call_logout, oidc_flow_followup, token_are_revoked
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
        reverse("oidc_overrides:register"),
        # Verify the GET parameter `next` does not override OIDC redirect_uri.
        f"{reverse('oidc_overrides:register')}?next=http://evil.com",
    ],
)
def test_register_endpoint(auth_url, client, mailoutbox):
    ApplicationFactory(client_id=OIDC_PARAMS["client_id"])
    user = UserFactory.build(email="")

    auth_complete_url = add_url_params(auth_url, OIDC_PARAMS)
    response = client.get(auth_complete_url)
    assertRedirects(response, reverse("accounts:register"))

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

    [email] = mailoutbox
    assert email.subject == "Vérification de l’adresse e-mail"
    assert email.to == [user_email]
    verification_url = get_verification_link(email.body)
    response = client.get(verification_url)
    assertRedirects(response, auth_complete_url, fetch_redirect_response=False)
    assert get_user(client).is_authenticated is True
    user.refresh_from_db()
    assert user.email == user_email
    assertQuerysetEqual(
        EmailAddress.objects.values_list("user_id", "email", "verified_at"),
        [(user.pk, user_email, datetime.datetime(2023, 5, 5, 11, 11, 11, tzinfo=datetime.timezone.utc))],
    )
    assert user.linked_applications.count() == 0

    response = client.get(auth_complete_url)
    assert response.status_code == 302
    assert response.url.startswith(OIDC_PARAMS["redirect_uri"])
    auth_response_params = get_url_params(response.url)
    assert user.linked_applications.count() == 1

    oidc_flow_followup(client, auth_response_params, user)


@freeze_time("2023-05-05 11:11:11")
@pytest.mark.parametrize(
    "auth_url",
    [
        reverse("oidc_overrides:activate"),
        # Verify the GET parameter `next` does not override OIDC redirect_uri.
        f"{reverse('oidc_overrides:activate')}?next=http://evil.com",
    ],
)
def test_activate_endpoint(auth_url, client, mailoutbox):
    ApplicationFactory(client_id=OIDC_PARAMS["client_id"])
    user = UserFactory.build(email="")

    auth_complete_url = add_url_params(auth_url, OIDC_PARAMS)
    response = client.get(auth_complete_url, follow=True)
    assert response.status_code == 400

    user_email = "email@mailinator.com"
    auth_url = reverse("oidc_overrides:activate")
    auth_params = OIDC_PARAMS | {"login_hint": user_email, "firstname": "firstname", "lastname": "lastname"}
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

    [email] = mailoutbox
    assert email.subject == "Vérification de l’adresse e-mail"
    assert email.to == [user_email]
    verification_url = get_verification_link(email.body)
    response = client.get(verification_url)
    assertRedirects(response, auth_complete_url, fetch_redirect_response=False)
    assert get_user(client).is_authenticated is True
    user.refresh_from_db()
    assert user.email == user_email
    assertQuerysetEqual(
        EmailAddress.objects.values_list("user_id", "email", "verified_at"),
        [(user.pk, user_email, datetime.datetime(2023, 5, 5, 11, 11, 11, tzinfo=datetime.timezone.utc))],
    )
    assert user.linked_applications.count() == 0

    response = client.get(auth_complete_url)
    assert response.status_code == 302
    assert response.url.startswith(OIDC_PARAMS["redirect_uri"])
    auth_response_params = get_url_params(response.url)
    assert user.linked_applications.count() == 1

    oidc_flow_followup(client, auth_response_params, user)


@pytest.mark.parametrize(
    "auth_url",
    [
        reverse("oidc_overrides:authorize"),
        # Verify the GET parameter `next` does not override OIDC redirect_uri.
        f"{reverse('oidc_overrides:authorize')}?next=http://evil.com",
    ],
)
def test_login_endpoint(auth_url, client):
    ApplicationFactory(client_id=OIDC_PARAMS["client_id"])
    user = UserFactory()

    auth_complete_url = add_url_params(auth_url, OIDC_PARAMS)
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
    assert get_user(client).is_authenticated is True
    user = User.objects.get(email=user.email)
    assert user.linked_applications.count() == 0

    response = client.get(auth_complete_url)
    assert response.status_code == 302
    assert response.url.startswith(OIDC_PARAMS["redirect_uri"])
    auth_response_params = get_url_params(response.url)
    assert user.linked_applications.count() == 1

    oidc_flow_followup(client, auth_response_params, user)


def test_login_after_password_reset(client):
    ApplicationFactory(client_id=OIDC_PARAMS["client_id"])
    user = UserFactory()

    auth_url = reverse("oidc_overrides:authorize")
    auth_complete_url = add_url_params(auth_url, OIDC_PARAMS)
    response = client.get(auth_complete_url)
    assertRedirects(response, reverse("accounts:login"))

    response = client.get(response.url)
    assertContains(response, reverse("accounts:password_reset"))

    response = client.post(reverse("accounts:password_reset"), data={"email": user.email})
    assertRedirects(response, reverse("accounts:login"))

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
    response = client.post(response.url, data={"new_password1": "password", "new_password2": "password"})
    assertRedirects(response, auth_complete_url, fetch_redirect_response=False)
    assert get_user(client).is_authenticated is True

    response = client.get(auth_complete_url)
    assert response.status_code == 302
    assert response.url.startswith(OIDC_PARAMS["redirect_uri"])
    auth_response_params = get_url_params(response.url)

    oidc_flow_followup(client, auth_response_params, user)


@freeze_time("2023-05-05 11:11:11")
def test_login_hint_is_preserved(client):
    ApplicationFactory(client_id=OIDC_PARAMS["client_id"])

    user_email = "email@mailinator.com"
    auth_url = reverse("oidc_overrides:register")
    auth_params = OIDC_PARAMS | {"login_hint": user_email}
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
        'autocomplete="email" class="form-control" title="" required disabled id="id_email">',
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


def test_logout_no_confirmation(client):
    """Logout without confirmation requires the id_token"""

    user = UserFactory()
    ApplicationFactory(client_id=OIDC_PARAMS["client_id"])

    auth_url = reverse("oidc_overrides:authorize")
    auth_complete_url = add_url_params(auth_url, OIDC_PARAMS)
    response = client.get(auth_complete_url)
    assertRedirects(response, reverse("accounts:login"))

    response = client.post(response.url, data={"email": user.email, "password": DEFAULT_PASSWORD})
    assert get_user(client).is_authenticated is True
    response = client.get(response.url)
    auth_response_params = get_url_params(response.url)
    id_token = oidc_flow_followup(client, auth_response_params, user)

    assert get_user(client).is_authenticated is True
    response = call_logout(client, "get", {"id_token_hint": id_token, "post_logout_redirect_uri": "https://callback/"})
    assertRedirects(response, "https://callback/", fetch_redirect_response=False)
    assert not get_user(client).is_authenticated
    assert token_are_revoked(user)

    response = client.get(auth_complete_url)
    assertRedirects(response, reverse("accounts:login"))


def test_logout_with_confirmation(client):
    # FIXME: currently not working
    pass


def test_edit_user_info_and_password(client, mailoutbox):
    user = UserFactory()
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

    # Page contains return to referrer link
    assertContains(response, "Retour")
    assertContains(response, referrer_uri)

    # Edit user info
    response = client.post(
        edit_user_info_url,
        data={"last_name": "Doe", "first_name": "John", "email": "my@email.com"},
    )
    assertRedirects(response, reverse("accounts:confirm-email"))
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
    [verification_email] = mailoutbox
    assert verification_email.to == ["my@email.com"]
    assert verification_email.subject == "Vérification de l’adresse e-mail"
    verification_url = get_verification_link(verification_email.body)
    response = client.get(verification_url)
    assertRedirects(response, reverse("accounts:edit_user_info"))

    # Go change password
    response = client.get(change_password_url)
    assertContains(response, "<h1>\n                Changer mon mot de passe\n            </h1>")
    response = client.post(
        change_password_url,
        data={"old_password": DEFAULT_PASSWORD, "new_password1": "toto", "new_password2": "toto"},
    )
    assert get_user(client).is_authenticated is True

    client.logout()
    assert get_user(client).is_authenticated is False

    # User may login with new password
    response = client.post(reverse("accounts:login"), data={"email": "my@email.com", "password": "toto"}, follow=True)
    assert get_user(client).is_authenticated is True
