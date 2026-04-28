import logging

from django.contrib import messages
from django.contrib.auth import get_user
from django.contrib.auth.hashers import make_password
from django.core import mail
from django.urls import reverse
from django.utils.encoding import force_bytes
from django.utils.html import escape
from django.utils.http import urlsafe_base64_encode
from freezegun import freeze_time
from pytest_django.asserts import (
    assertContains,
    assertNotContains,
    assertRedirects,
    assertTemplateUsed,
)

from inclusion_connect.accounts.views import PasswordResetView
from inclusion_connect.utils.oidc import OIDC_SESSION_KEY
from inclusion_connect.utils.urls import add_url_params
from tests.asserts import assertMessages, assertRecords
from tests.oidc_overrides.factories import ApplicationFactory
from tests.users.factories import DEFAULT_PASSWORD, UserFactory


class TestLoginView:
    def test_login(self, caplog, client):
        redirect_url = reverse("oauth2_provider:rp-initiated-logout")
        url = add_url_params(reverse("accounts:login"), {"next": redirect_url})
        user = UserFactory()

        response = client.get(url)
        assertContains(response, "Connexion")
        assertContains(response, "Adresse e-mail")  # Ask for email, not username

        response = client.post(url, data={"email": user.email, "password": DEFAULT_PASSWORD})
        assertRedirects(response, redirect_url, fetch_redirect_response=False)
        assert get_user(client).is_authenticated is True
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

    def test_no_next_url(self, caplog, client):
        user = UserFactory()

        response = client.post(
            reverse("accounts:login"),
            data={"email": user.email, "password": DEFAULT_PASSWORD},
        )
        assertRedirects(response, reverse("accounts:change_password"))
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

    def test_failed_bad_email_or_password(self, caplog, client):
        url = add_url_params(reverse("accounts:login"), {"next": "anything"})
        user = UserFactory()

        response = client.post(url, data={"email": user.email, "password": "V€r¥--$3©®€7"})
        assertTemplateUsed(response, "login.html")
        assertContains(response, "Adresse e-mail ou mot de passe invalide.")
        assert not get_user(client).is_authenticated
        assertRecords(
            caplog,
            [
                (
                    "inclusion_connect.auth",
                    logging.INFO,
                    {
                        "email": user.email,
                        "event": "login_error",
                        "errors": {
                            "__all__": [
                                {
                                    "message": "Adresse e-mail ou mot de passe invalide.",
                                    "code": "invalid_login",
                                }
                            ]
                        },
                    },
                )
            ],
        )

        response = client.post(url, data={"email": "wrong@email.com", "password": DEFAULT_PASSWORD})
        assertTemplateUsed(response, "login.html")
        assertContains(response, "Adresse e-mail ou mot de passe invalide.")
        assert not get_user(client).is_authenticated
        assertRecords(
            caplog,
            [
                (
                    "inclusion_connect.auth",
                    logging.INFO,
                    {
                        "email": "wrong@email.com",
                        "event": "login_error",
                        "errors": {
                            "__all__": [
                                {
                                    "message": "Adresse e-mail ou mot de passe invalide.",
                                    "code": "invalid_login",
                                }
                            ]
                        },
                    },
                )
            ],
        )

        # If user is inactive
        user.is_active = False
        user.save()
        response = client.post(url, data={"email": user.email, "password": DEFAULT_PASSWORD})
        assertTemplateUsed(response, "login.html")
        assertContains(response, "Adresse e-mail ou mot de passe invalide.")
        assert not get_user(client).is_authenticated
        assert client.session["next_url"] == "anything"
        assertRecords(
            caplog,
            [
                (
                    "inclusion_connect.auth",
                    logging.INFO,
                    {
                        "email": user.email,
                        "event": "login_error",
                        "errors": {
                            "__all__": [
                                {
                                    "message": "Adresse e-mail ou mot de passe invalide.",
                                    "code": "invalid_login",
                                }
                            ]
                        },
                    },
                )
            ],
        )

    def test_login_hint(self, caplog, client):
        redirect_url = reverse("oauth2_provider:rp-initiated-logout")
        url = add_url_params(reverse("accounts:login"), {"next": redirect_url})
        user = UserFactory(email="me@mailinator.com")
        client_session = client.session
        client_session[OIDC_SESSION_KEY] = {
            "login_hint": user.email,
            "firstname": user.first_name,
            "lastname": user.last_name,
        }
        client_session.save()

        response = client.get(url)
        assertContains(response, "Connexion")
        assertContains(response, "Adresse e-mail")  # Ask for email, not username
        assertContains(
            response,
            # Pre-filled with email address from login_hint.
            '<input type="email" name="email" value="me@mailinator.com" placeholder="nom@domaine.fr" '
            # Disabled, users cannot change data passed by the RP.
            'autocomplete="email" maxlength="320" class="form-control" required disabled id="id_email">',
            count=1,
        )

        # Email is simply ignored.
        response = client.post(url, data={"email": "evil@mailinator.com", "password": DEFAULT_PASSWORD})
        assertRedirects(response, redirect_url, fetch_redirect_response=False)
        assert get_user(client).is_authenticated is True
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

    def test_empty_login_hint(self, client):
        url = add_url_params(reverse("accounts:login"), {"login_hint": ""})

        response = client.get(url)
        assertContains(response, "Connexion")
        assertContains(response, "Adresse e-mail")  # Ask for email, not username
        assertContains(
            response,
            # Not pre-filled with email address since login_hint is empty
            '<input type="email" name="email" placeholder="nom@domaine.fr" '
            # Not disabled.
            'autocomplete="email" maxlength="320" class="form-control" required id="id_email">',
            count=1,
        )


class TestPasswordResetView:
    @freeze_time("2023-06-08 09:10:03")
    def test_password_reset(self, caplog, client):
        user = UserFactory()

        with freeze_time("2023-06-08 09:10:03"):
            redirect_url = reverse("oauth2_provider:rp-initiated-logout")
            url = add_url_params(reverse("accounts:login"), {"next": redirect_url})
            response = client.get(url)
            password_reset_url = reverse("accounts:password_reset")
            assertContains(response, password_reset_url)

            response = client.get(password_reset_url)
            assertTemplateUsed(response, "password_reset.html")

            response = client.post(password_reset_url, data={"email": user.email})
            assertRedirects(response, reverse("accounts:login"))
            assert client.session["next_url"] == redirect_url
            assertMessages(
                response,
                [
                    (
                        messages.SUCCESS,
                        "Si un compte existe avec cette adresse e-mail, "
                        "vous recevrez un e-mail contenant des instructions pour réinitialiser votre mot de passe.",
                    ),
                ],
            )

            # Check sent email
            [email] = mail.outbox
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            token = PasswordResetView.token_generator.make_token(user)
            password_reset_url = reverse("accounts:password_reset_confirm", args=(uid, token))
            assert password_reset_url in email.body
            assertRecords(
                caplog,
                [
                    (
                        "inclusion_connect.auth",
                        logging.INFO,
                        {"event": "forgot_password", "user": user.pk},
                    )
                ],
            )

        # More than a day after link generation
        with freeze_time("2023-06-09 09:10:04"):
            response = client.get(password_reset_url)
            assertContains(
                response,
                "Veuillez renouveler votre demande de mise à jour de mot de passe.",
            )

        # Exaclty a day after link generation
        with freeze_time("2023-06-09 09:10:03"):
            # Change password
            password = "V€r¥--$3©®€7"
            response = client.get(password_reset_url)  # retrieve the modified url
            response = client.post(
                response.url,
                data={"new_password1": password, "new_password2": password},
            )

            # User is now logged in and redirected to next_url
            assertRedirects(response, redirect_url, fetch_redirect_response=False)
            assert get_user(client).is_authenticated is True
            # The redirect cleans `next_url` from the session.
            assert "next_url" not in client.session
            assertRecords(
                caplog,
                [
                    (
                        "inclusion_connect.auth",
                        logging.INFO,
                        {"event": "reset_password", "user": user.pk},
                    ),
                    (
                        "inclusion_connect.auth",
                        logging.INFO,
                        {"event": "login", "user": user.pk},
                    ),
                ],
            )

    def test_password_reset_unknown_email(self, caplog, client):
        redirect_url = reverse("oauth2_provider:rp-initiated-logout")
        url = add_url_params(reverse("accounts:login"), {"next": redirect_url})
        response = client.get(url)
        password_reset_url = reverse("accounts:password_reset")
        assertContains(response, password_reset_url)

        response = client.get(password_reset_url)
        assertTemplateUsed(response, "password_reset.html")

        response = client.post(password_reset_url, data={"email": "evil@mailinator.com"})
        assertRedirects(response, reverse("accounts:login"))
        assert client.session["next_url"] == redirect_url
        assertMessages(
            response,
            [
                (
                    messages.SUCCESS,
                    "Si un compte existe avec cette adresse e-mail, "
                    "vous recevrez un e-mail contenant des instructions pour réinitialiser votre mot de passe.",
                ),
            ],
        )
        # Check sent email
        assert len(mail.outbox) == 0
        assertRecords(
            caplog,
            [
                (
                    "inclusion_connect.auth",
                    logging.INFO,
                    {"event": "forgot_password", "email": "evil@mailinator.com"},
                )
            ],
        )

    @freeze_time("2023-06-08 09:10:03")
    def test_login_hint(self, caplog, client, mailoutbox):
        user = UserFactory(email="me@mailinator.com")

        redirect_url = reverse("oauth2_provider:rp-initiated-logout")
        url = add_url_params(reverse("accounts:login"), {"next": redirect_url})

        client_session = client.session
        client_session[OIDC_SESSION_KEY] = {"login_hint": user.email}
        client_session.save()

        response = client.get(url)
        password_reset_url = reverse("accounts:password_reset")
        assertContains(response, password_reset_url)
        assertContains(
            response,
            # Pre-filled with email address from login_hint.
            '<input type="email" name="email" value="me@mailinator.com" placeholder="nom@domaine.fr" '
            # Disabled, users cannot change data passed by the RP.
            'autocomplete="email" maxlength="320" class="form-control" required disabled id="id_email">',
            count=1,
        )

        response = client.get(password_reset_url)
        assertTemplateUsed(response, "password_reset.html")

        # Email is simply ignored.
        response = client.post(password_reset_url, data={"email": "evil@mailinator.com"})
        assertRedirects(response, reverse("accounts:login"))
        assertMessages(
            response,
            [
                (
                    messages.SUCCESS,
                    "Si un compte existe avec cette adresse e-mail, "
                    "vous recevrez un e-mail contenant des instructions pour réinitialiser votre mot de passe.",
                ),
            ],
        )
        assert client.session["next_url"] == redirect_url

        # Check sent email
        [email] = mailoutbox
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = PasswordResetView.token_generator.make_token(user)
        password_reset_url = reverse("accounts:password_reset_confirm", args=(uid, token))
        assert password_reset_url in email.body
        assertRecords(
            caplog,
            [
                (
                    "inclusion_connect.auth",
                    logging.INFO,
                    {"event": "forgot_password", "user": user.pk},
                )
            ],
        )

        # Change password
        password = "V€r¥--$3©®€7"
        response = client.get(password_reset_url)  # retrieve the modified url
        response = client.post(response.url, data={"new_password1": password, "new_password2": password})

        # User is now logged in and redirected to next_url
        assertRedirects(response, redirect_url, fetch_redirect_response=False)
        assert get_user(client).is_authenticated is True
        # The redirect cleans `next_url` from the session.
        assert "next_url" not in client.session
        assertRecords(
            caplog,
            [
                (
                    "inclusion_connect.auth",
                    logging.INFO,
                    {"event": "reset_password", "user": user.pk},
                ),
                (
                    "inclusion_connect.auth",
                    logging.INFO,
                    {"event": "login", "user": user.pk},
                ),
            ],
        )


class TestPasswordResetConfirmView:
    def test_confirm_password_reset_error(self, caplog, client):
        user = UserFactory()
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = PasswordResetView.token_generator.make_token(user)
        response = client.get(reverse("accounts:password_reset_confirm", args=(uid, token)))
        print(response.url)
        assertRedirects(response, response.url, fetch_redirect_response=False)
        response = client.post(
            response.url,
            data={"new_password1": "password", "new_password2": "password-typo"},
        )
        assert response.status_code == 200
        assertRecords(
            caplog,
            [
                (
                    "inclusion_connect.auth",
                    logging.INFO,
                    {
                        "event": "reset_password_error",
                        "user": None,
                        "errors": {
                            "new_password2": [
                                {
                                    "message": "Les deux mots de passe ne correspondent pas.",
                                    "code": "password_mismatch",
                                }
                            ]
                        },
                    },
                )
            ],
        )


class TestPasswordChangeView:
    def test_change_password(self, caplog, client):
        application = ApplicationFactory()
        user = UserFactory()
        client.force_login(user)
        referrer_uri = "https://go/back/there"
        params = {"referrer_uri": referrer_uri, "referrer": application.client_id}
        change_password_url = add_url_params(reverse("accounts:change_password"), params)

        # Dont display return button without referrer_uri
        response = client.get(reverse("accounts:change_password"))
        return_text = "Retour"
        assertNotContains(response, return_text)

        # with referrer_uri
        response = client.get(change_password_url)
        assertContains(
            response,
            "<h1>\n                Changer mon mot de passe\n            </h1>",
        )
        # Left menu contains both pages
        assertContains(response, escape(change_password_url))
        # Page contains return to referrer link
        assertContains(response, return_text)
        assertContains(response, referrer_uri)

        # Go change password
        response = client.post(
            change_password_url,
            data={
                "old_password": DEFAULT_PASSWORD,
                "new_password1": "V€r¥--$3©®€7",
                "new_password2": "V€r¥--$3©®€7",
            },
        )
        assertRedirects(response, change_password_url)
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

    def test_change_password_failure(self, caplog, client):
        user = UserFactory(first_name="Manuel", last_name="Calavera")
        client.force_login(user)
        response = client.post(
            reverse("accounts:change_password"),
            data={
                "old_password": DEFAULT_PASSWORD,
                "new_password1": "password",
                "new_password2": "password",
            },
        )
        assert response.status_code == 200
        assert get_user(client).is_authenticated is True
        assertRecords(
            caplog,
            [
                (
                    "inclusion_connect.auth",
                    logging.INFO,
                    {
                        "event": "change_password_error",
                        "user": user.pk,
                        "errors": {
                            "new_password2": [
                                {
                                    "message": "Ce mot de passe est trop court. "
                                    "Il doit contenir au minimum 12 caractères.",
                                    "code": "password_too_short",
                                },
                                {
                                    "message": "Ce mot de passe est trop courant.",
                                    "code": "password_too_common",
                                },
                                {
                                    "message": "Le mot de passe ne contient pas assez de caractères.",
                                    "code": "",
                                },
                            ]
                        },
                    },
                )
            ],
        )


class TestChangeTemporaryPasswordView:
    def test_view(self, caplog, client):
        redirect_url = reverse("oauth2_provider:rp-initiated-logout")
        url = add_url_params(reverse("accounts:login"), {"next": redirect_url})
        user = UserFactory(password_is_temporary=True)

        response = client.post(url, data={"email": user.email, "password": DEFAULT_PASSWORD})
        assertRedirects(response, reverse("accounts:change_temporary_password"))
        assert get_user(client).is_authenticated is True
        assert client.session["next_url"] == redirect_url
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

        response = client.post(
            reverse("accounts:change_temporary_password"),
            data={"new_password1": "V€r¥--$3©®€7", "new_password2": "V€r¥--$3©®€7"},
        )
        assertRedirects(response, redirect_url, fetch_redirect_response=False)
        # The redirect cleans `next_url` from the session.
        assert "next_url" not in client.session
        user.refresh_from_db()
        assert user.password_is_temporary is False
        assertRecords(
            caplog,
            [
                (
                    "inclusion_connect.auth",
                    logging.INFO,
                    {"event": "change_temporary_password", "user": user.pk},
                )
            ],
        )

    def test_allow_same_password(self, client):
        user = UserFactory(password_is_temporary=True)
        client.force_login(user)

        response = client.post(
            reverse("accounts:change_temporary_password"),
            data={"new_password1": DEFAULT_PASSWORD, "new_password2": DEFAULT_PASSWORD},
        )
        assertRedirects(response, reverse("accounts:change_password"), fetch_redirect_response=False)

        user.refresh_from_db()
        assert user.password_is_temporary is False

    def test_invalid_password(self, caplog, client):
        user = UserFactory(password_is_temporary=True, first_name="Manuel", last_name="Calavera")
        client.force_login(user)
        response = client.post(
            reverse("accounts:change_temporary_password"),
            data={"new_password1": "password", "new_password2": "password"},
        )
        assert response.status_code == 200
        user.refresh_from_db()
        assert user.password_is_temporary is True
        assertRecords(
            caplog,
            [
                (
                    "inclusion_connect.auth",
                    logging.INFO,
                    {
                        "event": "change_temporary_password_error",
                        "user": user.pk,
                        "errors": {
                            "new_password2": [
                                {
                                    "message": "Ce mot de passe est trop court. "
                                    "Il doit contenir au minimum 12 caractères.",
                                    "code": "password_too_short",
                                },
                                {
                                    "message": "Ce mot de passe est trop courant.",
                                    "code": "password_too_common",
                                },
                                {
                                    "message": "Le mot de passe ne contient pas assez de caractères.",
                                    "code": "",
                                },
                            ]
                        },
                    },
                )
            ],
        )


class TestChangeWeakPasswordView:
    def test_view(self, caplog, client):
        redirect_url = reverse("oauth2_provider:rp-initiated-logout")
        url = add_url_params(reverse("accounts:login"), {"next": redirect_url})
        user = UserFactory(password=make_password("weak_password"))

        response = client.post(url, data={"email": user.email, "password": "weak_password"})
        assertRedirects(response, reverse("accounts:change_weak_password"))
        assert get_user(client).is_authenticated is True
        assert client.session["next_url"] == redirect_url
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

        response = client.post(
            reverse("accounts:change_weak_password"),
            data={"new_password1": DEFAULT_PASSWORD, "new_password2": DEFAULT_PASSWORD},
        )
        assertRedirects(response, redirect_url, fetch_redirect_response=False)

        # The redirect cleans `next_url` from the session.
        assert "next_url" not in client.session
        user.refresh_from_db()
        assert user.password_is_temporary is False
        assertRecords(
            caplog,
            [
                (
                    "inclusion_connect.auth",
                    logging.INFO,
                    {"event": "change_weak_password", "user": user.pk},
                )
            ],
        )

    def test_invalid_password(self, caplog, client):
        user = UserFactory(first_name="Manuel", last_name="Calavera", password=make_password("weak_password"))

        client.force_login(user)
        response = client.post(
            reverse("accounts:change_weak_password"),
            data={"new_password1": "password", "new_password2": "password"},
        )
        assert response.status_code == 200
        user.refresh_from_db()
        assertRecords(
            caplog,
            [
                (
                    "inclusion_connect.auth",
                    logging.INFO,
                    {
                        "event": "change_weak_password_error",
                        "user": user.pk,
                        "errors": {
                            "new_password2": [
                                {
                                    "message": "Ce mot de passe est trop court. "
                                    "Il doit contenir au minimum 12 caractères.",
                                    "code": "password_too_short",
                                },
                                {
                                    "message": "Ce mot de passe est trop courant.",
                                    "code": "password_too_common",
                                },
                                {
                                    "message": "Le mot de passe ne contient pas assez de caractères.",
                                    "code": "",
                                },
                            ]
                        },
                    },
                )
            ],
        )


class TestMiddleware:
    def test_post_login_actions(self, client):
        user = UserFactory(
            password_is_temporary=True,
            password_is_too_weak=True,
        )
        client.force_login(user)

        response = client.get(reverse("accounts:change_password"))
        assertRedirects(response, reverse("accounts:change_temporary_password"))

        client.post(
            reverse("accounts:change_temporary_password"),
            data={"new_password1": "V€r¥--$3©®€7", "new_password2": "V€r¥--$3©®€7"},
        )
        response = client.get(reverse("accounts:change_weak_password"))

        client.post(
            reverse("accounts:change_weak_password"),
            data={"new_password1": "V€r¥--$3©®€7", "new_password2": "V€r¥--$3©®€7"},
        )
        response = client.get(reverse("accounts:change_password"))
        assert response.status_code == 200

    def test_staff_users_are_not_concerned(self, client):
        user = UserFactory(
            password_is_temporary=True,
            is_staff=True,
        )
        client.force_login(user)
        response = client.get(reverse("admin:index"))
        assert response.status_code == 200

    def test_logout_is_whitelisted(self, client):
        user = UserFactory(
            password_is_temporary=True,
        )
        client.force_login(user)
        response = client.get(
            add_url_params(
                reverse("oauth2_provider:rp-initiated-logout"),
                {"state": "random_string"},
            )
        )
        assert response.status_code == 200
