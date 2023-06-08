import datetime
from urllib.parse import quote

import pytest
from django.contrib import messages
from django.contrib.auth import get_user
from django.core import mail
from django.db.models import F
from django.urls import reverse
from django.utils import timezone
from django.utils.encoding import force_bytes
from django.utils.html import format_html
from django.utils.http import urlsafe_base64_encode
from freezegun import freeze_time
from pytest_django.asserts import (
    assertContains,
    assertNotContains,
    assertQuerysetEqual,
    assertRedirects,
    assertTemplateUsed,
)

from inclusion_connect.accounts.tokens import email_verification_token
from inclusion_connect.accounts.views import EMAIL_CONFIRM_KEY, PasswordResetView
from inclusion_connect.users.models import EmailAddress, User
from inclusion_connect.utils.oidc import OIDC_SESSION_KEY
from inclusion_connect.utils.urls import add_url_params
from tests.asserts import assertMessages
from tests.helpers import OIDC_PARAMS, parse_response_to_soup
from tests.users.factories import DEFAULT_PASSWORD, EmailAddressFactory, UserFactory


class TestLoginView:
    def test_login(self, client):
        redirect_url = reverse("oauth2_provider:logout")
        url = add_url_params(reverse("accounts:login"), {"next": redirect_url})
        user = UserFactory()

        response = client.get(url)
        assertContains(response, "Connexion")
        assertContains(response, "Adresse e-mail")  # Ask for email, not username
        assertContains(response, reverse("accounts:register"))  # Link to register page

        response = client.post(url, data={"email": user.email, "password": DEFAULT_PASSWORD})
        assertRedirects(response, redirect_url, fetch_redirect_response=False)
        assert get_user(client).is_authenticated is True
        # The redirect cleans `next_url` from the session.
        assert "next_url" not in client.session

    def test_no_next_url(self, client):
        user = UserFactory()

        response = client.post(reverse("accounts:login"), data={"email": user.email, "password": DEFAULT_PASSWORD})
        assertRedirects(response, reverse("accounts:edit_user_info"))
        assert get_user(client).is_authenticated is True

    def test_failed_bad_email_or_password(self, client):
        url = add_url_params(reverse("accounts:login"), {"next": "anything"})
        user = UserFactory()

        response = client.post(url, data={"email": user.email, "password": "V€r¥--$3©®€7"})
        assertTemplateUsed(response, "login.html")
        assertContains(response, "Adresse e-mail ou mot de passe invalide.")
        assert not get_user(client).is_authenticated

        response = client.post(url, data={"email": "wrong@email.com", "password": DEFAULT_PASSWORD})
        assertTemplateUsed(response, "login.html")
        assertContains(response, "Adresse e-mail ou mot de passe invalide.")
        assert not get_user(client).is_authenticated

        # If user is inactive
        user.is_active = False
        user.save()
        response = client.post(url, data={"email": user.email, "password": DEFAULT_PASSWORD})
        assertTemplateUsed(response, "login.html")
        assertContains(response, "Adresse e-mail ou mot de passe invalide.")
        assert not get_user(client).is_authenticated
        assert client.session["next_url"] == "anything"

    def test_email_not_verified(self, client, mailoutbox):
        redirect_url = reverse("oauth2_provider:logout")
        url = add_url_params(reverse("accounts:login"), {"next": redirect_url})
        user_email = "me@mailinator.com"
        user = UserFactory(email="")
        EmailAddress.objects.create(user=user, email=user_email)

        response = client.post(url, data={"email": user_email, "password": DEFAULT_PASSWORD})
        assert response.status_code == 200
        assert not get_user(client).is_authenticated
        assertContains(
            response,
            """
            <div class="alert alert-danger alert-dismissible" role="alert">
                <button class="close" type="button" data-dismiss="alert" aria-label="close">&#215;</button>
                Un compte inactif avec cette adresse e-mail existe déjà, l’email de vérification vient d’être
                envoyé à nouveau.
            </div>
            """,
            html=True,
            count=1,
        )
        [email] = mailoutbox
        assert email.to == [user_email]
        assert email.subject == "Vérification de l’adresse e-mail"
        assert client.session["next_url"] == redirect_url

    def test_login_hint(self, client):
        redirect_url = reverse("oauth2_provider:logout")
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
        assertContains(response, reverse("accounts:register"))  # Link to registration page
        assertContains(
            response,
            # Pre-filled with email address from login_hint.
            '<input type="email" name="email" value="me@mailinator.com" placeholder="nom@domaine.fr" '
            # Disabled, users cannot change data passed by the RP.
            'autocomplete="email" class="form-control" title="" required disabled id="id_email">',
            count=1,
        )

        # Email is simply ignored.
        response = client.post(url, data={"email": "evil@mailinator.com", "password": DEFAULT_PASSWORD})
        assertRedirects(response, redirect_url, fetch_redirect_response=False)
        assert get_user(client).is_authenticated is True
        # The redirect cleans `next_url` from the session.
        assert "next_url" not in client.session


class TestRegisterView:
    @freeze_time("2023-04-26 11:11:11")
    def test_register(self, client, mailoutbox):
        redirect_url = reverse("oauth2_provider:logout")
        url = add_url_params(reverse("accounts:register"), {"next": redirect_url})

        response = client.get(url)
        assertContains(response, "Créer un compte")
        assertContains(response, reverse("accounts:login"))  # Link to login page
        assertContains(response, "CGU_20230302.pdf")
        assertContains(response, quote("Politique de confidentialité_20230512.pdf"))

        user_email = "user@mailinator.com"
        response = client.post(
            url,
            data={
                "email": user_email,
                "first_name": "Jack",
                "last_name": "Jackson",
                "password1": DEFAULT_PASSWORD,
                "password2": DEFAULT_PASSWORD,
                "terms_accepted": "on",
            },
        )
        assertRedirects(response, reverse("accounts:confirm-email"))
        assert get_user(client).is_authenticated is False
        assert client.session["next_url"] == redirect_url
        user_from_db = User.objects.get()
        assert user_from_db.terms_accepted_at == user_from_db.date_joined
        assert user_from_db.first_name == "Jack"
        assert user_from_db.last_name == "Jackson"
        assert user_from_db.email == ""
        assertQuerysetEqual(
            EmailAddress.objects.values_list("user_id", "email", "verified_at"),
            [(user_from_db.pk, user_email, None)],
        )

        [email] = mailoutbox
        assert email.to == [user_email]
        assert email.subject == "Vérification de l’adresse e-mail"
        uidb64 = urlsafe_base64_encode(str(user_from_db.pk).encode())
        token = email_verification_token(user_email)
        verify_path = reverse("accounts:confirm-email-token", kwargs={"uidb64": uidb64, "token": token})
        verify_link = f"http://testserver{verify_path}"
        assert email.body == (
            "Bonjour,\n\n"
            "Une demande de création de compte a été effectuée avec votre adresse e-mail. Si\n"
            "vous êtes à l’origine de cette requête, veuillez cliquer sur le lien ci-dessous\n"
            "afin de vérifier votre adresse e-mail :\n\n"
            f"{verify_link}\n\n"
            "Ce lien expire dans 1 jour.\n\n"
            "Si vous n’êtes pas à l’origine de cette demande, veuillez ignorer ce message.\n\n"
            "---\n"
            "L’équipe d’inclusion connect\n"
        )

    def test_error_email_exists(self, client):
        redirect_url = reverse("oauth2_provider:logout")
        url = add_url_params(reverse("accounts:register"), {"next": redirect_url})
        user = UserFactory()

        response = client.post(
            url,
            data={
                "email": user.email,
                "first_name": user.first_name,
                "last_name": user.last_name,
                "password1": DEFAULT_PASSWORD,
                "password2": DEFAULT_PASSWORD,
                "terms_accepted": "on",
            },
        )
        assert client.session["next_url"] == redirect_url
        assertTemplateUsed(response, "register.html")
        assert "email" in response.context["form"].errors
        assertContains(
            response,
            format_html(
                'Un compte avec cette adresse e-mail existe déjà, <a href="{}">se connecter</a> ?',
                reverse("accounts:login"),
            ),
            html=True,
        )

    def test_error_email_not_verified(self, client, mailoutbox):
        redirect_url = reverse("oauth2_provider:logout")
        url = add_url_params(reverse("accounts:register"), {"next": redirect_url})
        user = UserFactory(email="")
        user_email = "me@mailinator.com"
        EmailAddress.objects.create(user=user, email=user_email)

        response = client.post(
            url,
            data={
                "email": user_email,
                "first_name": user.first_name,
                "last_name": user.last_name,
                "password1": DEFAULT_PASSWORD,
                "password2": DEFAULT_PASSWORD,
                "terms_accepted": "on",
            },
        )
        assert client.session["next_url"] == redirect_url
        assertTemplateUsed(response, "register.html")
        assert "email" in response.context["form"].errors
        msg = (
            "Un compte inactif avec cette adresse e-mail existe déjà, "
            "l’email de vérification vient d’être envoyé à nouveau."
        )
        assertContains(response, msg, html=True, count=1)
        [email] = mailoutbox
        assert email.subject == "Vérification de l’adresse e-mail"
        assert email.to == [user_email]

    def test_email_already_exists_and_not_verified(self, client):
        redirect_url = reverse("oauth2_provider:logout")
        url = add_url_params(reverse("accounts:register"), {"next": redirect_url})
        user_email = "me@mailinator.com"
        EmailAddressFactory.create(email=user_email, verified_at=timezone.now())

        response = client.post(
            url,
            data={
                "email": user_email,
                "first_name": "Manuel",
                "last_name": "Calavera",
                "password1": DEFAULT_PASSWORD,
                "password2": DEFAULT_PASSWORD,
                "terms_accepted": "on",
            },
        )
        assert client.session["next_url"] == redirect_url
        assertTemplateUsed(response, "register.html")
        assert "email" in response.context["form"].errors
        login_url = reverse("accounts:login")
        msg = f'Un compte avec cette adresse e-mail existe déjà, <a href="{login_url}">se connecter</a> ?'
        # Displayed in bootstrap_form_errors type="all" and next to the field.
        assertContains(response, msg, count=1)

    def test_terms_are_required(self, client, mailoutbox):
        redirect_url = reverse("oauth2_provider:logout")
        url = add_url_params(reverse("accounts:register"), {"next": redirect_url})
        user = UserFactory.build()

        response = client.post(
            url,
            data={
                "email": user.email,
                "first_name": user.first_name,
                "last_name": user.last_name,
                "password1": DEFAULT_PASSWORD,
                "password2": DEFAULT_PASSWORD,
            },
        )
        assert client.session["next_url"] == redirect_url
        assertTemplateUsed(response, "register.html")
        assert "terms_accepted" in response.context["form"].errors
        assert mailoutbox == []

    @freeze_time("2023-04-26 11:11:11")
    def test_login_hint(self, client, mailoutbox):
        redirect_url = reverse("oauth2_provider:logout")
        url = add_url_params(reverse("accounts:register"), {"next": redirect_url})

        client_session = client.session
        client_session[OIDC_SESSION_KEY] = {"login_hint": "me@mailinator.com"}
        client_session.save()

        response = client.get(url)
        assertContains(response, "Créer un compte")
        assertContains(response, reverse("accounts:login"))  # Link to login page
        assertContains(response, "CGU_20230302.pdf")
        assertContains(response, quote("Politique de confidentialité_20230512.pdf"))
        assertContains(
            response,
            # Pre-filled with email address from login_hint.
            '<input type="email" name="email" value="me@mailinator.com" placeholder="nom@domaine.fr" '
            # Disabled, users cannot change data passed by the RP.
            'autocomplete="email" class="form-control" title="" required disabled id="id_email">',
            count=1,
        )

        response = client.post(
            url,
            data={
                # Email is simply ignored.
                "email": "evil@mailinator.com",
                "first_name": "John",
                "last_name": "Backy",
                "password1": DEFAULT_PASSWORD,
                "password2": DEFAULT_PASSWORD,
                "terms_accepted": "on",
            },
        )
        assertRedirects(response, reverse("accounts:confirm-email"))
        assert get_user(client).is_authenticated is False
        assert client.session["next_url"] == redirect_url
        user_from_db = User.objects.get()
        assert user_from_db.terms_accepted_at == user_from_db.date_joined
        assert user_from_db.first_name == "John"
        assert user_from_db.last_name == "Backy"
        assert user_from_db.email == ""
        assertQuerysetEqual(
            EmailAddress.objects.values_list("user_id", "email", "verified_at"),
            [(user_from_db.pk, "me@mailinator.com", None)],
        )

        [email] = mailoutbox
        assert email.to == ["me@mailinator.com"]
        assert email.subject == "Vérification de l’adresse e-mail"
        uidb64 = urlsafe_base64_encode(str(user_from_db.pk).encode())
        token = email_verification_token("me@mailinator.com")
        verify_path = reverse("accounts:confirm-email-token", kwargs={"uidb64": uidb64, "token": token})
        verify_link = f"http://testserver{verify_path}"
        assert email.body == (
            "Bonjour,\n\n"
            "Une demande de création de compte a été effectuée avec votre adresse e-mail. Si\n"
            "vous êtes à l’origine de cette requête, veuillez cliquer sur le lien ci-dessous\n"
            "afin de vérifier votre adresse e-mail :\n\n"
            f"{verify_link}\n\n"
            "Ce lien expire dans 1 jour.\n\n"
            "Si vous n’êtes pas à l’origine de cette demande, veuillez ignorer ce message.\n\n"
            "---\n"
            "L’équipe d’inclusion connect\n"
        )


class TestActivateAccountView:
    def test_activate_account(self, client):
        redirect_url = reverse("oauth2_provider:logout")
        url = add_url_params(reverse("accounts:activate"), {"next": redirect_url})
        user = UserFactory.build()

        # If missing params in oidc session
        response = client.get(url)
        assert response.status_code == 400

        client_session = client.session
        client_session[OIDC_SESSION_KEY] = {
            "login_hint": user.email,
            "firstname": user.first_name,
            "lastname": user.last_name,
        }
        client_session.save()
        response = client.get(url)
        assertTemplateUsed(response, "activate_account.html")

        response = client.post(
            url,
            data={
                "email": user.email,
                "first_name": user.first_name,
                "last_name": user.last_name,
                "password1": DEFAULT_PASSWORD,
                "password2": DEFAULT_PASSWORD,
                "terms_accepted": "on",
            },
        )
        assertRedirects(response, reverse("accounts:confirm-email"))
        assert get_user(client).is_authenticated is False
        assert client.session["next_url"] == redirect_url
        user = User.objects.get()  # Previous instance was a built factory, so refresh_from_db won't work
        assert user.terms_accepted_at == user.date_joined
        email_address = EmailAddress.objects.get()
        assert email_address.email == email_address.email
        assert email_address.user_id == email_address.user.pk
        assert email_address.verified_at is None

    def test_email_already_exists(self, client):
        redirect_url = reverse("oauth2_provider:logout")
        url = add_url_params(reverse("accounts:activate"), {"next": redirect_url})
        user = UserFactory()

        # If missing params in oidc session
        response = client.get(url)
        assert response.status_code == 400

        client_session = client.session
        client_session[OIDC_SESSION_KEY] = {
            "login_hint": user.email,
            "firstname": user.first_name,
            "lastname": user.last_name,
        }
        client_session.save()
        response = client.get(url)
        assertTemplateUsed(response, "activate_account.html")

        response = client.post(
            url,
            data={
                "email": user.email,
                "first_name": user.first_name,
                "last_name": user.last_name,
                "password1": DEFAULT_PASSWORD,
                "password2": DEFAULT_PASSWORD,
                "terms_accepted": "on",
            },
        )
        assertContains(
            response,
            format_html(
                'Un compte avec cette adresse e-mail existe déjà, <a href="{}">se connecter</a> ?',
                reverse("accounts:login"),
            ),
        )
        assert get_user(client).is_authenticated is False
        assert client.session["next_url"] == redirect_url

    def test_email_already_exists_not_verified(self, client):
        redirect_url = reverse("oauth2_provider:logout")
        url = add_url_params(reverse("accounts:activate"), {"next": redirect_url})
        user = UserFactory(email="")
        user_email = "me@mailinator.com"
        EmailAddress.objects.create(user=user, email=user_email)

        client_session = client.session
        client_session[OIDC_SESSION_KEY] = {
            "login_hint": user_email,
            "firstname": user.first_name,
            "lastname": user.last_name,
        }
        client_session.save()
        response = client.post(
            url,
            data={
                "email": user_email,
                "first_name": user.first_name,
                "last_name": user.last_name,
                "password1": DEFAULT_PASSWORD,
                "password2": DEFAULT_PASSWORD,
                "terms_accepted": "on",
            },
            follow=True,
        )
        assertContains(
            response,
            "Un compte inactif avec cette adresse e-mail existe déjà, "
            "l’email de vérification vient d’être envoyé à nouveau.",
            count=1,
        )
        assert get_user(client).is_authenticated is False
        assert client.session["next_url"] == redirect_url

    def test_terms_are_required(self, client):
        redirect_url = reverse("oauth2_provider:logout")
        url = add_url_params(reverse("accounts:activate"), {"next": redirect_url})
        user = UserFactory.build()

        client_session = client.session
        client_session[OIDC_SESSION_KEY] = {
            "login_hint": user.email,
            "firstname": user.first_name,
            "lastname": user.last_name,
        }
        client_session.save()

        response = client.post(
            url,
            data={
                "email": user.email,
                "first_name": user.first_name,
                "last_name": user.last_name,
                "password1": DEFAULT_PASSWORD,
                "password2": DEFAULT_PASSWORD,
            },
        )
        assertTemplateUsed(response, "activate_account.html")
        assert "terms_accepted" in response.context["form"].errors
        assert client.session["next_url"] == redirect_url


class TestPasswordResetView:
    @freeze_time("2023-06-08 09:10:03")
    def test_password_reset(self, client):
        user = UserFactory()

        with freeze_time("2023-06-08 09:10:03"):
            redirect_url = reverse("oauth2_provider:logout")
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
            assert len(mail.outbox) == 1
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            token = PasswordResetView.token_generator.make_token(user)
            password_reset_url = reverse("accounts:password_reset_confirm", args=(uid, token))
            assert password_reset_url in mail.outbox[0].body

        # More than a day after link generation
        with freeze_time("2023-06-09 09:10:04"):
            response = client.get(password_reset_url)
            assertContains(response, "Veuillez renouveler votre demande de mise à jour de mot de passe.")

        # Exaclty a day after link generation
        with freeze_time("2023-06-09 09:10:03"):
            # Change password
            password = "V€r¥--$3©®€7"
            response = client.get(password_reset_url)  # retrieve the modified url
            response = client.post(response.url, data={"new_password1": password, "new_password2": password})

            # User is now logged in and redirected to next_url
            assertRedirects(response, redirect_url, fetch_redirect_response=False)
            assert get_user(client).is_authenticated is True
            # The redirect cleans `next_url` from the session.
            assert "next_url" not in client.session

    def test_password_reset_unknown_email(self, client):
        redirect_url = reverse("oauth2_provider:logout")
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

    @freeze_time("2023-06-08 09:10:03")
    def test_login_hint(self, client, mailoutbox):
        user = UserFactory(email="me@mailinator.com")

        redirect_url = reverse("oauth2_provider:logout")
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
            'autocomplete="email" class="form-control" title="" required disabled id="id_email">',
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

        # Change password
        password = "V€r¥--$3©®€7"
        response = client.get(password_reset_url)  # retrieve the modified url
        response = client.post(response.url, data={"new_password1": password, "new_password2": password})

        # User is now logged in and redirected to next_url
        assertRedirects(response, redirect_url, fetch_redirect_response=False)
        assert get_user(client).is_authenticated is True
        # The redirect cleans `next_url` from the session.
        assert "next_url" not in client.session


class TestEditUserInfoView:
    def test_edit_name(self, client):
        user = UserFactory()
        verified_email = user.email
        client.force_login(user)
        referrer_uri = "https://go/back/there"
        edit_user_info_url = add_url_params(reverse("accounts:edit_user_info"), {"referrer_uri": referrer_uri})
        change_password_url = add_url_params(reverse("accounts:change_password"), {"referrer_uri": referrer_uri})

        # Dont display return button without referrer_uri
        response = client.get(reverse("accounts:edit_user_info"))
        return_text = "Retour"
        assertNotContains(response, return_text)
        assertContains(
            response,
            f'<input type="email" name="email" value="{user.email}" placeholder="nom@domaine.fr" '
            'autocomplete="email" class="form-control" title="" required id="id_email">',
            count=1,
        )

        # with referrer_uri
        response = client.get(edit_user_info_url)
        assertContains(response, "<h1>\n                Informations générales\n            </h1>")
        # Left menu contains both pages
        assertContains(response, edit_user_info_url)
        assertContains(response, change_password_url)
        # Page contains return to referrer link
        assertContains(response, return_text)
        assertContains(response, referrer_uri)

        # Edit user info
        response = client.post(
            edit_user_info_url,
            data={"last_name": "Doe", "first_name": "John", "email": user.email},
        )
        assertRedirects(response, edit_user_info_url)
        user.refresh_from_db()
        assert user.first_name == "John"
        assert user.last_name == "Doe"
        assert user.email == verified_email

    def test_edit_email(self, client):
        user = UserFactory()
        verified_email = user.email
        client.force_login(user)
        edit_user_info_url = add_url_params(reverse("accounts:edit_user_info"), {"referrer_uri": "rp_url"})

        # Edit user info
        response = client.post(
            edit_user_info_url,
            data={"last_name": "Doe", "first_name": "John", "email": "jo-with-typo@email.com"},
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
        assert new.email == "jo-with-typo@email.com"
        assert client.session[EMAIL_CONFIRM_KEY] == "jo-with-typo@email.com"
        assert user.next_redirect_uri == edit_user_info_url

        # Now, fix the typo.
        response = client.post(
            edit_user_info_url,
            data={"last_name": "Doe", "first_name": "John", "email": "joe@email.com"},
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
        assert new.email == "joe@email.com"
        assert client.session[EMAIL_CONFIRM_KEY] == "joe@email.com"
        assert user.next_redirect_uri == edit_user_info_url


def test_change_password(client):
    user = UserFactory()
    client.force_login(user)
    referrer_uri = "https://go/back/there"
    edit_user_info_url = add_url_params(reverse("accounts:edit_user_info"), {"referrer_uri": referrer_uri})
    change_password_url = add_url_params(reverse("accounts:change_password"), {"referrer_uri": referrer_uri})

    # Dont display return button without referrer_uri
    response = client.get(reverse("accounts:change_password"))
    return_text = "Retour"
    assertNotContains(response, return_text)

    # with referrer_uri
    response = client.get(change_password_url)
    assertContains(response, "<h1>\n                Changer mon mot de passe\n            </h1>")
    # Left menu contains both pages
    assertContains(response, edit_user_info_url)
    assertContains(response, change_password_url)
    # Page contains return to referrer link
    assertContains(response, return_text)
    assertContains(response, referrer_uri)

    # Go change password
    response = client.post(
        change_password_url,
        data={"old_password": DEFAULT_PASSWORD, "new_password1": "V€r¥--$3©®€7", "new_password2": "V€r¥--$3©®€7"},
    )
    assertRedirects(response, change_password_url)
    assert get_user(client).is_authenticated is True

    client.logout()
    assert get_user(client).is_authenticated is False

    response = client.post(
        reverse("accounts:login"), data={"email": user.email, "password": "V€r¥--$3©®€7"}, follow=True
    )
    assert get_user(client).is_authenticated is True


@pytest.mark.parametrize("terms_accepted_at", (None, datetime.datetime(2022, 1, 1, tzinfo=datetime.UTC)))
@freeze_time("2023-05-09 14:01:56")
def test_new_terms(client, terms_accepted_at):
    redirect_url = reverse("oauth2_provider:logout")
    url = add_url_params(reverse("accounts:login"), {"next": redirect_url})
    user = UserFactory(terms_accepted_at=terms_accepted_at)

    response = client.post(url, data={"email": user.email, "password": DEFAULT_PASSWORD})
    assertRedirects(response, reverse("accounts:accept_terms"))
    assert get_user(client).is_authenticated is True
    assert client.session["next_url"] == redirect_url

    response = client.post(reverse("accounts:accept_terms"))
    assertRedirects(response, redirect_url, fetch_redirect_response=False)
    # The redirect cleans `next_url` from the session.
    assert "next_url" not in client.session

    user.refresh_from_db()
    assert user.terms_accepted_at == timezone.now()


class TestConfirmEmailView:
    def test_get_anonymous(self, client):
        response = client.get(reverse("accounts:confirm-email"))
        assert response.status_code == 404

    def test_get_with_confirmed_email(self, client):
        user = UserFactory()
        client.force_login(user)
        response = client.get(reverse("accounts:confirm-email"))
        assert response.status_code == 404

    def test_get(self, client, snapshot):
        user = UserFactory(email="")
        email = "me@mailinator.com"
        EmailAddress.objects.create(email=email, user=user)
        session = client.session
        session["email_to_confirm"] = email
        session.save()
        response = client.get(reverse("accounts:confirm-email"))
        assert response.status_code == 200
        assert str(parse_response_to_soup(response, selector="main")) == snapshot(
            name="me@mailinator.com is present in page output"
        )

    def test_post(self, client, mailoutbox):
        user = UserFactory(email="")
        user_email = "me@mailinator.com"
        EmailAddress.objects.create(email=user_email, user=user)
        session = client.session
        session["email_to_confirm"] = user_email
        session.save()
        email_confirmation_url = reverse("accounts:confirm-email")
        response = client.post(email_confirmation_url)
        assertRedirects(response, email_confirmation_url)
        [email] = mailoutbox
        assert email.to == [user_email]
        assert email.subject == "Vérification de l’adresse e-mail"


class TestConfirmEmailTokenView:
    @staticmethod
    def url(user, token):
        return reverse(
            "accounts:confirm-email-token",
            kwargs={
                "uidb64": urlsafe_base64_encode(str(user.pk).encode()),
                "token": token,
            },
        )

    @freeze_time("2023-04-26 11:11:11")
    def test_confirm_email(self, client):
        user = UserFactory(email="")
        email = "me@mailinator.com"
        email_address = EmailAddress.objects.create(email=email, user_id=user.pk)
        token = email_verification_token(email)
        session = client.session
        session[EMAIL_CONFIRM_KEY] = "me@mailinator.com"
        session.save()
        response = client.get(self.url(user, token))
        assertRedirects(response, reverse("accounts:edit_user_info"))
        email_address.refresh_from_db()
        assert email_address.verified_at == timezone.now()
        user.refresh_from_db()
        assert user.email == "me@mailinator.com"
        assert client.session["_auth_user_id"] == str(user.pk)
        assert client.session["_auth_user_backend"] == "inclusion_connect.auth.backends.EmailAuthenticationBackend"
        assert EMAIL_CONFIRM_KEY not in client.session

        client.logout()
        with freeze_time(timezone.now() + datetime.timedelta(days=1)):
            response = client.get(self.url(user, token))
        assertMessages(response, [(messages.INFO, "Cette adresse e-mail est déjà vérifiée.")])
        assertRedirects(response, reverse("accounts:login"))
        user.refresh_from_db()
        assert user.email == "me@mailinator.com"
        email_address.refresh_from_db()
        assert email_address.verified_at == datetime.datetime(2023, 4, 26, 11, 11, 11, tzinfo=datetime.timezone.utc)
        assert "_auth_user_id" not in client.session
        assert "_auth_user_backend" not in client.session

    @freeze_time("2023-04-26 11:11:11")
    def test_confirm_email_from_other_client(self, client):
        user = UserFactory(email="")
        email = "me@mailinator.com"
        email_address = EmailAddress.objects.create(email=email, user_id=user.pk)
        token = email_verification_token(email)
        next_url = add_url_params(reverse("oauth2_provider:register"), OIDC_PARAMS)
        user.save_next_redirect_uri(next_url)
        response = client.get(self.url(user, token))
        assertRedirects(response, next_url, fetch_redirect_response=False)
        email_address.refresh_from_db()
        assert email_address.verified_at == timezone.now()
        user.refresh_from_db()
        assert user.email == "me@mailinator.com"
        assert user.next_redirect_uri is None
        assert user.next_redirect_uri_stored_at is None
        assert client.session["_auth_user_id"] == str(user.pk)
        assert client.session["_auth_user_backend"] == "inclusion_connect.auth.backends.EmailAuthenticationBackend"

    @freeze_time("2023-04-26 11:11:11")
    def test_invalidates_previous_email(self, client):
        user = UserFactory(email="old@mailinator.com")
        email = "new@mailinator.com"
        email_address = EmailAddress.objects.create(email=email, user_id=user.pk)
        token = email_verification_token(email)
        response = client.get(self.url(user, token))
        assertRedirects(response, reverse("accounts:edit_user_info"))
        # Previous and unused emails were deleted.
        email_address = EmailAddress.objects.get()
        assert email_address.verified_at == timezone.now()
        assert email_address.email == "new@mailinator.com"
        user.refresh_from_db()
        assert user.email == "new@mailinator.com"
        assert client.session["_auth_user_id"] == str(user.pk)
        assert client.session["_auth_user_backend"] == "inclusion_connect.auth.backends.EmailAuthenticationBackend"

    def test_expired_token(self, client):
        user = UserFactory(email="")
        email = "me@mailinator.com"
        email_address = EmailAddress.objects.create(email=email, user_id=user.pk)
        with freeze_time(timezone.now() - datetime.timedelta(days=1)):
            token = email_verification_token(email)
        response = client.get(self.url(user, token))
        assertMessages(response, [(messages.ERROR, "Le lien de vérification d’adresse e-mail a expiré.")])
        assert client.session[EMAIL_CONFIRM_KEY] == "me@mailinator.com"
        assertRedirects(response, reverse("accounts:confirm-email"))
        email_address.refresh_from_db()
        assert email_address.verified_at is None
        user.refresh_from_db()
        assert user.email == ""
        assert "_auth_user_id" not in client.session
        assert "_auth_user_backend" not in client.session

    def test_forged_uidb64(self, client):
        user = UserFactory(email="")
        other_user = UserFactory()
        email = "me@mailinator.com"
        email_address = EmailAddress.objects.create(email=email, user_id=user.pk)
        token = email_verification_token(email)
        response = client.get(self.url(other_user, token))
        assert response.status_code == 404
        email_address.refresh_from_db()
        assert email_address.verified_at is None
        user.refresh_from_db()
        assert user.email == ""
        assert "_auth_user_id" not in client.session
        assert "_auth_user_backend" not in client.session

    def test_forged_token_bad_user_pk(self, client):
        user = UserFactory(email="")
        email = "me@mailinator.com"
        email_address = EmailAddress.objects.create(email=email, user_id=user.pk)
        token = email_verification_token(email)
        response = client.get(
            reverse(
                "accounts:confirm-email-token",
                kwargs={
                    "uidb64": urlsafe_base64_encode(b"1234abc"),
                    "token": token,
                },
            )
        )
        assert response.status_code == 404
        email_address.refresh_from_db()
        assert email_address.verified_at is None
        user.refresh_from_db()
        assert user.email == ""
        assert "_auth_user_id" not in client.session
        assert "_auth_user_backend" not in client.session

    def test_forged_token_bad_email(self, client):
        user = UserFactory(email="")
        email = "me@mailinator.com"
        bad_email = "evil@mailinator.com"
        email_address = EmailAddress.objects.create(email=email, user_id=user.pk)
        token = email_verification_token(email)
        encoded_evil_email = urlsafe_base64_encode(bad_email.encode())
        _encoded_email, timestamp, signature = token.split(":")
        token = f"{encoded_evil_email}:{timestamp}:{signature}"
        response = client.get(self.url(user, token))
        assert response.status_code == 404
        email_address.refresh_from_db()
        assert email_address.verified_at is None
        user.refresh_from_db()
        assert user.email == ""
        assert "_auth_user_id" not in client.session
        assert "_auth_user_backend" not in client.session

    @freeze_time("2023-04-26 11:11:11")
    def test_forged_token(self, client):
        user = UserFactory(email="")
        email = "me@mailinator.com"
        email_address = EmailAddress.objects.create(email=email, user_id=user.pk)
        session = client.session
        session[EMAIL_CONFIRM_KEY] = "me@mailinator.com"
        session.save()
        token = "forged"
        response = client.get(self.url(user, token))
        assert response.status_code == 404
        email_address.refresh_from_db()
        assert email_address.verified_at is None
        user.refresh_from_db()
        assert user.email == ""
        assert not get_user(client).is_authenticated

    @freeze_time("2023-04-26 11:11:11")
    def test_token_invalidated_by_email_change(self, client):
        user = UserFactory(email="me@mailinator.com")
        email = "new@mailinator.com"
        email_address = EmailAddress.objects.create(email=email, user_id=user.pk)
        token1 = email_verification_token(email)
        token2 = email_verification_token(email)
        response = client.get(self.url(user, token2))
        assertRedirects(response, reverse("accounts:edit_user_info"))
        # Confirming the email address deletes old verified emails and pending verifications.
        email_address = EmailAddress.objects.get()
        assert email_address.email == email
        assert email_address.verified_at == timezone.now()
        user.refresh_from_db()
        assert user.email == email
        assert client.session["_auth_user_id"] == str(user.pk)
        assert client.session["_auth_user_backend"] == "inclusion_connect.auth.backends.EmailAuthenticationBackend"

        # token1 is invalidated, even if user is currently logged in.
        response = client.get(self.url(user, token1))
        assertMessages(response, [("INFO", "Cette adresse e-mail est déjà vérifiée.")])
        assertRedirects(response, reverse("accounts:edit_user_info"))

        # token1 is invalidated.
        client.session.flush()
        response = client.get(self.url(user, token1))
        assertMessages(response, [("INFO", "Cette adresse e-mail est déjà vérifiée.")])
        assertRedirects(response, reverse("accounts:login"))


class TestChangeTemporaryPasswordView:
    def test_view(self, client):
        redirect_url = reverse("oauth2_provider:logout")
        url = add_url_params(reverse("accounts:login"), {"next": redirect_url})
        user = UserFactory(must_reset_password=True)

        response = client.post(url, data={"email": user.email, "password": DEFAULT_PASSWORD})
        assertRedirects(response, reverse("accounts:change_temporary_password"))
        assert get_user(client).is_authenticated is True
        assert client.session["next_url"] == redirect_url

        response = client.post(
            reverse("accounts:change_temporary_password"),
            data={"new_password1": "V€r¥--$3©®€7", "new_password2": "V€r¥--$3©®€7"},
        )
        assertRedirects(response, redirect_url, fetch_redirect_response=False)
        # The redirect cleans `next_url` from the session.
        assert "next_url" not in client.session

        user.refresh_from_db()
        assert user.must_reset_password is False

    def test_allow_same_password(self, client):
        user = UserFactory(must_reset_password=True)
        client.force_login(user)

        response = client.post(
            reverse("accounts:change_temporary_password"),
            data={"new_password1": DEFAULT_PASSWORD, "new_password2": DEFAULT_PASSWORD},
        )
        assertRedirects(response, reverse("accounts:edit_user_info"), fetch_redirect_response=False)

        user.refresh_from_db()
        assert user.must_reset_password is False


class TestMiddleware:
    def test_post_login_actions(self, client):
        user = UserFactory(
            terms_accepted_at=None,
            must_reset_password=True,
        )
        client.force_login(user)
        response = client.get(reverse("accounts:edit_user_info"))
        assertRedirects(response, reverse("accounts:accept_terms"))

        client.post(reverse("accounts:accept_terms"))
        response = client.get(reverse("accounts:edit_user_info"))
        assertRedirects(response, reverse("accounts:change_temporary_password"))

        client.post(
            reverse("accounts:change_temporary_password"),
            data={"new_password1": "V€r¥--$3©®€7", "new_password2": "V€r¥--$3©®€7"},
        )
        response = client.get(reverse("accounts:edit_user_info"))
        assert response.status_code == 200

    def test_staff_users_are_not_concerned(self, client):
        user = UserFactory(
            terms_accepted_at=None,
            must_reset_password=True,
            is_staff=True,
        )
        client.force_login(user)
        response = client.get(reverse("admin:index"))
        assert response.status_code == 200

    def test_logout_is_whitelisted(self, client):
        user = UserFactory(
            terms_accepted_at=None,
            must_reset_password=True,
        )
        client.force_login(user)
        response = client.get(add_url_params(reverse("oauth2_provider:logout"), {"state": "random_string"}))
        assert response.status_code == 200
