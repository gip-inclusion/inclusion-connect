import datetime
import logging
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
    assertQuerySetEqual,
    assertRedirects,
    assertTemplateUsed,
)

from inclusion_connect.accounts.tokens import email_verification_token
from inclusion_connect.accounts.views import EMAIL_CONFIRM_KEY, PasswordResetView
from inclusion_connect.users.models import EmailAddress, User
from inclusion_connect.utils.oidc import OIDC_SESSION_KEY
from inclusion_connect.utils.urls import add_url_params
from tests.asserts import assertMessages
from tests.helpers import parse_response_to_soup
from tests.oidc_overrides.factories import ApplicationFactory
from tests.users.factories import DEFAULT_PASSWORD, EmailAddressFactory, UserFactory


class TestLoginView:
    def test_login(self, caplog, client):
        redirect_url = reverse("oauth2_provider:rp-initiated-logout")
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
        assert caplog.record_tuples == [
            (
                "inclusion_connect.auth",
                logging.INFO,
                "{'ip_address': '127.0.0.1', 'user': UUID('%s'), 'event': 'login'}" % user.pk,
            )
        ]

    def test_no_next_url(self, caplog, client):
        user = UserFactory()

        response = client.post(reverse("accounts:login"), data={"email": user.email, "password": DEFAULT_PASSWORD})
        assertRedirects(response, reverse("accounts:edit_user_info"))
        assert get_user(client).is_authenticated is True
        assert caplog.record_tuples == [
            (
                "inclusion_connect.auth",
                logging.INFO,
                "{'ip_address': '127.0.0.1', 'user': UUID('%s'), 'event': 'login'}" % user.pk,
            )
        ]

    def test_failed_bad_email_or_password(self, caplog, client):
        url = add_url_params(reverse("accounts:login"), {"next": "anything"})
        user = UserFactory()

        response = client.post(url, data={"email": user.email, "password": "V€r¥--$3©®€7"})
        assertTemplateUsed(response, "login.html")
        assertContains(response, "Adresse e-mail ou mot de passe invalide.")
        assert not get_user(client).is_authenticated
        assert caplog.record_tuples == [
            (
                "inclusion_connect.auth",
                logging.INFO,
                "{'ip_address': '127.0.0.1', "
                f"'email': '{user.email}', "
                "'event': 'login_error', "
                "'errors': {'__all__': [{'message': "
                "'Adresse e-mail ou mot de passe invalide.\\n"
                "Si vous n’avez pas encore créé votre compte Inclusion Connect, rendez-vous en bas de page et "
                "cliquez sur créer mon compte.', "
                "'code': 'invalid_login'}]}}",
            )
        ]
        caplog.clear()

        response = client.post(url, data={"email": "wrong@email.com", "password": DEFAULT_PASSWORD})
        assertTemplateUsed(response, "login.html")
        assertContains(response, "Adresse e-mail ou mot de passe invalide.")
        assert not get_user(client).is_authenticated
        assert caplog.record_tuples == [
            (
                "inclusion_connect.auth",
                logging.INFO,
                "{'ip_address': '127.0.0.1', "
                "'email': 'wrong@email.com', "
                "'event': 'login_error', "
                "'errors': {'__all__': [{'message': "
                "'Adresse e-mail ou mot de passe invalide.\\n"
                "Si vous n’avez pas encore créé votre compte Inclusion Connect, rendez-vous en bas de page et "
                "cliquez sur créer mon compte.', "
                "'code': 'invalid_login'}]}}",
            )
        ]
        caplog.clear()

        # If user is inactive
        user.is_active = False
        user.save()
        response = client.post(url, data={"email": user.email, "password": DEFAULT_PASSWORD})
        assertTemplateUsed(response, "login.html")
        assertContains(response, "Adresse e-mail ou mot de passe invalide.")
        assert not get_user(client).is_authenticated
        assert client.session["next_url"] == "anything"
        assert caplog.record_tuples == [
            (
                "inclusion_connect.auth",
                logging.INFO,
                "{'ip_address': '127.0.0.1', "
                f"'email': '{user.email}', "
                "'event': 'login_error', "
                "'errors': {'__all__': [{'message': "
                "'Adresse e-mail ou mot de passe invalide.\\n"
                "Si vous n’avez pas encore créé votre compte Inclusion Connect, rendez-vous en bas de page et "
                "cliquez sur créer mon compte.', "
                "'code': 'invalid_login'}]}}",
            )
        ]

    def test_email_not_verified(self, caplog, client, mailoutbox):
        redirect_url = reverse("oauth2_provider:rp-initiated-logout")
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
        assert caplog.record_tuples == [
            (
                "inclusion_connect.auth",
                logging.INFO,
                "{'ip_address': '127.0.0.1', "
                "'email': 'me@mailinator.com', "
                "'event': 'login_error', "
                "'errors': {'__all__': [{'message': "
                "'Un compte inactif avec cette adresse e-mail existe déjà, l’email de vérification vient d’être "
                "envoyé à nouveau.', "
                "'code': 'unverified_email'}]}}",
            )
        ]

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
        assertContains(response, reverse("accounts:register"))  # Link to registration page
        assertContains(
            response,
            # Pre-filled with email address from login_hint.
            '<input type="email" name="email" value="me@mailinator.com" placeholder="nom@domaine.fr" '
            # Disabled, users cannot change data passed by the RP.
            'autocomplete="email" maxlength="320" class="form-control" title="" required disabled id="id_email">',
            count=1,
        )

        # Email is simply ignored.
        response = client.post(url, data={"email": "evil@mailinator.com", "password": DEFAULT_PASSWORD})
        assertRedirects(response, redirect_url, fetch_redirect_response=False)
        assert get_user(client).is_authenticated is True
        # The redirect cleans `next_url` from the session.
        assert "next_url" not in client.session
        assert caplog.record_tuples == [
            (
                "inclusion_connect.auth",
                logging.INFO,
                "{'ip_address': '127.0.0.1', 'user': UUID('%s'), 'event': 'login'}" % user.pk,
            )
        ]

    def test_empty_login_hint(self, client):
        url = add_url_params(reverse("accounts:login"), {"login_hint": ""})

        response = client.get(url)
        assertContains(response, "Connexion")
        assertContains(response, "Adresse e-mail")  # Ask for email, not username
        assertContains(response, reverse("accounts:register"))  # Link to registration page
        assertContains(
            response,
            # Not pre-filled with email address since login_hint is empty
            '<input type="email" name="email" placeholder="nom@domaine.fr" '
            # Not disabled.
            'autocomplete="email" maxlength="320" class="form-control" title="" required id="id_email">',
            count=1,
        )


class TestRegisterView:
    @freeze_time("2023-04-26 11:11:11")
    def test_register(self, caplog, client, mailoutbox):
        redirect_url = reverse("oauth2_provider:rp-initiated-logout")
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
        assertQuerySetEqual(
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
        assert caplog.record_tuples == [
            (
                "inclusion_connect.auth",
                logging.INFO,
                "{'ip_address': '127.0.0.1', "
                "'email': 'user@mailinator.com', "
                f"'user': UUID('{user_from_db.pk}'), "
                "'event': 'register'}",
            )
        ]

    def test_error_email_exists(self, caplog, client):
        redirect_url = reverse("oauth2_provider:rp-initiated-logout")
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
        assert caplog.record_tuples == [
            (
                "inclusion_connect.auth",
                logging.INFO,
                "{'ip_address': '127.0.0.1', "
                f"'user': UUID('{user.pk}'), "
                "'event': 'register_error', "
                "'errors': {'email': [{'message': "
                "'Un compte avec cette adresse e-mail existe déjà, "
                '<a href="/accounts/login/">se connecter</a> ?'
                "', "
                "'code': 'existing_email'"
                "}]}}",
            )
        ]

    def test_error_email_not_verified(self, caplog, client, mailoutbox):
        redirect_url = reverse("oauth2_provider:rp-initiated-logout")
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
        assert caplog.record_tuples == [
            (
                "inclusion_connect.auth",
                logging.INFO,
                "{'ip_address': '127.0.0.1', "
                f"'user': UUID('{user.pk}'), "
                "'event': 'register_error', "
                "'errors': {'email': [{'message': "
                "'Un compte inactif avec cette adresse e-mail existe déjà, l’email de vérification vient d’être "
                "envoyé à nouveau.', "
                "'code': 'unverified_email'"
                "}]}}",
            ),
        ]

    def test_email_already_exists_and_not_verified(self, caplog, client):
        redirect_url = reverse("oauth2_provider:rp-initiated-logout")
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
        user = User.objects.get()
        assert caplog.record_tuples == [
            (
                "inclusion_connect.auth",
                logging.INFO,
                "{'ip_address': '127.0.0.1', "
                f"'user': UUID('{user.pk}'), "
                "'event': 'register_error', "
                "'errors': {'email': [{'message': "
                "'Un compte avec cette adresse e-mail existe déjà, "
                '<a href="/accounts/login/">se connecter</a> ?'
                "', "
                "'code': 'existing_email'"
                "}]}}",
            )
        ]

    def test_terms_are_required(self, caplog, client, mailoutbox):
        redirect_url = reverse("oauth2_provider:rp-initiated-logout")
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
        assert caplog.record_tuples == [
            (
                "inclusion_connect.auth",
                logging.INFO,
                "{'ip_address': '127.0.0.1', "
                f"'email': '{user.email}', "
                "'event': 'register_error', "
                "'errors': {'terms_accepted': [{'message': 'Ce champ est obligatoire.', 'code': 'required'}]}"
                "}",
            )
        ]

    @freeze_time("2023-04-26 11:11:11")
    def test_login_hint(self, client, mailoutbox):
        redirect_url = reverse("oauth2_provider:rp-initiated-logout")
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
        assertQuerySetEqual(
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
    def test_activate_account(self, caplog, client):
        redirect_url = reverse("oauth2_provider:rp-initiated-logout")
        url = add_url_params(reverse("accounts:activate"), {"next": redirect_url})
        user = UserFactory.build(email="me@mailinator.com")

        # If missing params in oidc session
        response = client.get(url)
        assert response.status_code == 400
        assert caplog.record_tuples == [("django.request", logging.WARNING, "Bad Request: /accounts/activate/")]
        caplog.clear()

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
        assert caplog.record_tuples == [
            (
                "inclusion_connect.auth",
                logging.INFO,
                "{'ip_address': '127.0.0.1', "
                "'email': 'me@mailinator.com', "
                f"'user': UUID('{user.pk}'), "
                "'event': 'activate'}",
            )
        ]

    def test_email_already_exists(self, caplog, client):
        redirect_url = reverse("oauth2_provider:rp-initiated-logout")
        url = add_url_params(reverse("accounts:activate"), {"next": redirect_url})
        user = UserFactory()

        # If missing params in oidc session
        response = client.get(url)
        assert response.status_code == 400
        assert caplog.record_tuples == [("django.request", logging.WARNING, "Bad Request: /accounts/activate/")]
        caplog.clear()

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
        assert caplog.record_tuples == [
            (
                "inclusion_connect.auth",
                logging.INFO,
                "{'ip_address': '127.0.0.1', "
                f"'user': UUID('{user.pk}'), "
                "'event': 'activate_error', "
                "'errors': {"
                "'email': [{'message': 'Un compte avec cette adresse e-mail existe déjà, "
                '<a href="/accounts/login/">se connecter</a> ?'
                "', 'code': 'existing_email'}], "
                "'__all__': [{'message': 'Un compte avec cette adresse e-mail existe déjà, "
                '<a href="/accounts/login/">se connecter</a> ?'
                "', 'code': ''}]}}",
            )
        ]

    def test_email_already_exists_not_verified(self, caplog, client):
        redirect_url = reverse("oauth2_provider:rp-initiated-logout")
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
        assert caplog.record_tuples == [
            (
                "inclusion_connect.auth",
                logging.INFO,
                "{'ip_address': '127.0.0.1', "
                f"'user': UUID('{user.pk}'), "
                "'event': 'activate_error', "
                "'errors': {"
                "'email': [{'message': 'Un compte inactif avec cette adresse e-mail existe déjà, "
                "l’email de vérification vient d’être envoyé à nouveau.', 'code': 'unverified_email'}], "
                "'__all__': [{'message': 'Un compte inactif avec cette adresse e-mail existe déjà, "
                "l’email de vérification vient d’être envoyé à nouveau.', 'code': ''}]"
                "}}",
            )
        ]

    def test_terms_are_required(self, caplog, client):
        redirect_url = reverse("oauth2_provider:rp-initiated-logout")
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
        assert caplog.record_tuples == [
            (
                "inclusion_connect.auth",
                logging.INFO,
                "{'ip_address': '127.0.0.1', "
                f"'email': '{user.email}', "
                "'event': 'activate_error', "
                "'errors': {'terms_accepted': [{'message': 'Ce champ est obligatoire.', 'code': 'required'}]}"
                "}",
            )
        ]


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
            assert len(mail.outbox) == 1
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            token = PasswordResetView.token_generator.make_token(user)
            password_reset_url = reverse("accounts:password_reset_confirm", args=(uid, token))
            assert password_reset_url in mail.outbox[0].body
            assert caplog.record_tuples == [
                (
                    "inclusion_connect.auth",
                    logging.INFO,
                    "{'ip_address': '127.0.0.1', 'event': 'forgot_password', 'user': UUID('%s')}" % user.pk,
                )
            ]
            caplog.clear()

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
            assert caplog.record_tuples == [
                (
                    "inclusion_connect.auth",
                    logging.INFO,
                    "{'ip_address': '127.0.0.1', 'event': 'reset_password', 'user': UUID('%s')}" % user.pk,
                ),
                (
                    "inclusion_connect.auth",
                    logging.INFO,
                    "{'ip_address': '127.0.0.1', 'event': 'login', 'user': UUID('%s')}" % user.pk,
                ),
            ]

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
        assert caplog.record_tuples == [
            (
                "inclusion_connect.auth",
                logging.INFO,
                "{'ip_address': '127.0.0.1', 'event': 'forgot_password', 'email': 'evil@mailinator.com'}",
            )
        ]

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
            'autocomplete="email" maxlength="320" class="form-control" title="" required disabled id="id_email">',
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
        assert caplog.record_tuples == [
            (
                "inclusion_connect.auth",
                logging.INFO,
                "{'ip_address': '127.0.0.1', 'event': 'forgot_password', 'user': UUID('%s')}" % user.pk,
            )
        ]
        caplog.clear()

        # Change password
        password = "V€r¥--$3©®€7"
        response = client.get(password_reset_url)  # retrieve the modified url
        response = client.post(response.url, data={"new_password1": password, "new_password2": password})

        # User is now logged in and redirected to next_url
        assertRedirects(response, redirect_url, fetch_redirect_response=False)
        assert get_user(client).is_authenticated is True
        # The redirect cleans `next_url` from the session.
        assert "next_url" not in client.session
        assert caplog.record_tuples == [
            (
                "inclusion_connect.auth",
                logging.INFO,
                "{'ip_address': '127.0.0.1', 'event': 'reset_password', 'user': UUID('%s')}" % user.pk,
            ),
            (
                "inclusion_connect.auth",
                logging.INFO,
                "{'ip_address': '127.0.0.1', 'event': 'login', 'user': UUID('%s')}" % user.pk,
            ),
        ]


class TestPasswordResetConfirmView:
    def test_confirm_password_reset_error(self, caplog, client):
        user = UserFactory()
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = PasswordResetView.token_generator.make_token(user)
        response = client.get(reverse("accounts:password_reset_confirm", args=(uid, token)))
        print(response.url)
        assertRedirects(response, response.url, fetch_redirect_response=False)
        response = client.post(response.url, data={"new_password1": "password", "new_password2": "password-typo"})
        assert response.status_code == 200
        assert caplog.record_tuples == [
            (
                "inclusion_connect.auth",
                logging.INFO,
                "{'ip_address': '127.0.0.1', "
                "'event': 'reset_password_error', "
                "'user': None, "
                "'errors': {'new_password2': [{'message': 'Les deux mots de passe ne correspondent pas.', "
                "'code': 'password_mismatch'}]}"
                "}",
            )
        ]


class TestEditUserInfoView:
    def test_edit_name(self, caplog, client):
        user = UserFactory(first_name="Manuel", last_name="Calavera")
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
            follow=True,
        )
        assertRedirects(response, edit_user_info_url)
        assertContains(response, "Vos informations personnelles ont été mises à jour.")
        user.refresh_from_db()
        assert user.first_name == "John"
        assert user.last_name == "Doe"
        assert user.email == verified_email
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
                "'new_first_name': 'John'"
                "}",
            )
        ]

    def test_edit_email(self, caplog, client):
        verified_email = "oldjo@email.com"
        user = UserFactory(first_name="John", last_name="Doe", email=verified_email)
        client.force_login(user)
        edit_user_info_url = add_url_params(reverse("accounts:edit_user_info"), {"referrer_uri": "rp_url"})

        # Edit user info
        response = client.post(
            edit_user_info_url,
            data={"last_name": "Doe", "first_name": "John", "email": "jo-with-typo@email.com"},
        )
        assertRedirects(response, add_url_params(reverse("accounts:confirm-email"), {"referrer_uri": "rp_url"}))
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
        assert caplog.record_tuples == [
            (
                "inclusion_connect.auth",
                logging.INFO,
                "{'ip_address': '127.0.0.1', "
                "'event': 'edit_user_info', "
                f"'user': UUID('{user.pk}'), "
                "'params': {'referrer_uri': 'rp_url'}, "
                f"'old_email': '{verified_email}', "
                "'new_email': 'jo-with-typo@email.com'"
                "}",
            )
        ]
        caplog.clear()

        # Now, fix the typo.
        response = client.post(
            edit_user_info_url,
            data={"last_name": "Doe", "first_name": "John", "email": "joe@email.com"},
        )
        assertRedirects(response, add_url_params(reverse("accounts:confirm-email"), {"referrer_uri": "rp_url"}))
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
        assert caplog.record_tuples == [
            (
                "inclusion_connect.auth",
                logging.INFO,
                "{'ip_address': '127.0.0.1', "
                "'event': 'edit_user_info', "
                f"'user': UUID('{user.pk}'), "
                "'params': {'referrer_uri': 'rp_url'}, "
                f"'old_email': '{verified_email}', "
                "'new_email': 'joe@email.com'"
                "}",
            )
        ]

    def test_edit_invalid(self, caplog, client):
        verified_email = "verified@email.com"
        user = UserFactory(first_name="John", last_name="Doe", email=verified_email)
        client.force_login(user)
        response = client.post(add_url_params(reverse("accounts:edit_user_info"), {"referrer_uri": "rp_url"}))
        assert response.status_code == 200
        user.refresh_from_db()
        assert user.first_name == "John"
        assert user.last_name == "Doe"
        assert user.email == verified_email
        emailaddress = user.email_addresses.get()
        assert emailaddress.verified_at is not None
        assert emailaddress.email == verified_email
        assert caplog.record_tuples == [
            (
                "inclusion_connect.auth",
                logging.INFO,
                "{'ip_address': '127.0.0.1', "
                "'event': 'edit_user_info_error', "
                f"'user': UUID('{user.pk}'), "
                "'params': {'referrer_uri': 'rp_url'}, "
                "'errors': {'email': [{'message': 'Ce champ est obligatoire.', 'code': 'required'}]}"
                "}",
            )
        ]


class TestPasswordChangeView:
    def test_change_password(self, caplog, client):
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

        response = client.post(
            reverse("accounts:login"), data={"email": user.email, "password": "V€r¥--$3©®€7"}, follow=True
        )
        assert get_user(client).is_authenticated is True
        assert caplog.record_tuples == [
            (
                "inclusion_connect.auth",
                logging.INFO,
                "{'ip_address': '127.0.0.1', 'user': UUID('%s'), 'event': 'login'}" % user.pk,
            )
        ]

    def test_change_password_failure(self, caplog, client):
        user = UserFactory(first_name="Manuel", last_name="Calavera")
        client.force_login(user)
        response = client.post(
            reverse("accounts:change_password"),
            data={"old_password": DEFAULT_PASSWORD, "new_password1": "password", "new_password2": "password"},
        )
        assert response.status_code == 200
        assert get_user(client).is_authenticated is True
        assert caplog.record_tuples == [
            (
                "inclusion_connect.auth",
                logging.INFO,
                "{'ip_address': '127.0.0.1', "
                "'event': 'change_password_error', "
                f"'user': UUID('{user.pk}'), "
                "'params': {}, "
                "'errors': {'new_password2': ["
                "{'message': 'Ce mot de passe est trop court. Il doit contenir au minimum 12 caractères.', "
                "'code': 'password_too_short'}, "
                "{'message': 'Ce mot de passe est trop courant.', 'code': 'password_too_common'}, "
                "{'message': 'Le mot de passe ne contient pas assez de caractères.', 'code': ''}]}"
                "}",
            )
        ]


@pytest.mark.parametrize("terms_accepted_at", (None, datetime.datetime(2022, 1, 1, tzinfo=datetime.UTC)))
@freeze_time("2023-05-09 14:01:56")
def test_new_terms(caplog, client, terms_accepted_at):
    redirect_url = reverse("oauth2_provider:rp-initiated-logout")
    url = add_url_params(reverse("accounts:login"), {"next": redirect_url})
    user = UserFactory(terms_accepted_at=terms_accepted_at)

    response = client.post(url, data={"email": user.email, "password": DEFAULT_PASSWORD})
    assertRedirects(response, reverse("accounts:accept_terms"))
    assert get_user(client).is_authenticated is True
    assert client.session["next_url"] == redirect_url
    assert caplog.record_tuples == [
        (
            "inclusion_connect.auth",
            logging.INFO,
            "{'ip_address': '127.0.0.1', 'user': UUID('%s'), 'event': 'login'}" % user.pk,
        )
    ]
    caplog.clear()

    response = client.post(reverse("accounts:accept_terms"))
    assertRedirects(response, redirect_url, fetch_redirect_response=False)
    # The redirect cleans `next_url` from the session.
    assert "next_url" not in client.session

    user.refresh_from_db()
    assert user.terms_accepted_at == timezone.now()
    assert caplog.record_tuples == [
        (
            "inclusion_connect.auth",
            logging.INFO,
            "{'ip_address': '127.0.0.1', 'event': 'accept_terms', 'user': UUID('%s')}" % user.pk,
        )
    ]


class TestConfirmEmailView:
    def test_get_anonymous(self, client):
        response = client.get(reverse("accounts:confirm-email"), follow=True)
        assertRedirects(
            response, add_url_params(reverse("accounts:login"), {"next": reverse("accounts:edit_user_info")})
        )

    def test_get_with_confirmed_email(self, client):
        user = UserFactory()
        client.force_login(user)
        response = client.get(reverse("accounts:confirm-email"))
        assertRedirects(response, reverse("accounts:edit_user_info"))

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
    def test_confirm_email(self, caplog, client):
        email_updated_msg = "Votre adresse e-mail a été mise à jour."
        user = UserFactory(email="")
        email = "me@mailinator.com"
        email_address = EmailAddress.objects.create(email=email, user_id=user.pk)
        token = email_verification_token(email)
        session = client.session
        session[EMAIL_CONFIRM_KEY] = "me@mailinator.com"
        session.save()
        response = client.get(self.url(user, token), follow=True)
        assertRedirects(response, reverse("accounts:edit_user_info"))
        assertContains(response, email_updated_msg)
        email_address.refresh_from_db()
        assert email_address.verified_at == timezone.now()
        user.refresh_from_db()
        assert user.email == "me@mailinator.com"
        assert client.session["_auth_user_id"] == str(user.pk)
        assert client.session["_auth_user_backend"] == "inclusion_connect.auth.backends.EmailAuthenticationBackend"
        assert EMAIL_CONFIRM_KEY not in client.session
        assert caplog.record_tuples == [
            (
                "inclusion_connect.auth",
                logging.INFO,
                "{'ip_address': '127.0.0.1', "
                "'email': 'me@mailinator.com', "
                f"'user': UUID('{user.pk}'), "
                "'event': 'confirm_email_address'}",
            ),
            (
                "inclusion_connect.auth",
                logging.INFO,
                "{'ip_address': '127.0.0.1', "
                "'email': 'me@mailinator.com', "
                f"'user': UUID('{user.pk}'), "
                "'event': 'login'}",
            ),
        ]
        caplog.clear()

        client.logout()
        with freeze_time(timezone.now() + datetime.timedelta(days=1)):
            response = client.get(self.url(user, token), follow=True)
        assertMessages(response, [(messages.INFO, "Cette adresse e-mail est déjà vérifiée.")])
        assertRedirects(response, reverse("accounts:login"))
        assertNotContains(response, email_updated_msg)
        user.refresh_from_db()
        assert user.email == "me@mailinator.com"
        email_address.refresh_from_db()
        assert email_address.verified_at == datetime.datetime(2023, 4, 26, 11, 11, 11, tzinfo=datetime.timezone.utc)
        assert "_auth_user_id" not in client.session
        assert "_auth_user_backend" not in client.session
        assert caplog.record_tuples == [
            (
                "inclusion_connect.auth",
                logging.INFO,
                "{'ip_address': '127.0.0.1', "
                "'email': 'me@mailinator.com', "
                f"'user': UUID('{user.pk}'), "
                "'event': 'confirm_email_address_error', "
                "'error': 'already verified'}",
            )
        ]

    @freeze_time("2023-04-26 11:11:11")
    def test_confirm_email_from_other_client(self, caplog, client, oidc_params):
        user = UserFactory(email="")
        ApplicationFactory(client_id=oidc_params["client_id"])
        email = "me@mailinator.com"
        email_address = EmailAddress.objects.create(email=email, user_id=user.pk)
        token = email_verification_token(email)
        next_url = add_url_params(reverse("oauth2_provider:register"), oidc_params)
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
        assert caplog.record_tuples == [
            (
                "inclusion_connect.auth",
                logging.INFO,
                "{'ip_address': '127.0.0.1', "
                "'email': 'me@mailinator.com', "
                f"'user': UUID('{user.pk}'), "
                "'event': 'confirm_email_address', "
                "'application': 'my_application'}",
            ),
            (
                "inclusion_connect.auth",
                logging.INFO,
                "{'ip_address': '127.0.0.1', "
                "'email': 'me@mailinator.com', "
                f"'user': UUID('{user.pk}'), "
                "'event': 'login', "
                "'application': 'my_application'}",
            ),
        ]

    @freeze_time("2023-04-26 11:11:11")
    def test_invalidates_previous_email(self, client):
        user = UserFactory(email="old@mailinator.com")
        email = "new@mailinator.com"
        email_address = EmailAddress.objects.create(email=email, user_id=user.pk)
        token = email_verification_token(email)
        response = client.get(self.url(user, token), follow=True)
        assertRedirects(response, reverse("accounts:edit_user_info"))
        assertContains(response, "Votre adresse e-mail a été mise à jour.")
        # Previous and unused emails were deleted.
        email_address = EmailAddress.objects.get()
        assert email_address.verified_at == timezone.now()
        assert email_address.email == "new@mailinator.com"
        user.refresh_from_db()
        assert user.email == "new@mailinator.com"
        assert client.session["_auth_user_id"] == str(user.pk)
        assert client.session["_auth_user_backend"] == "inclusion_connect.auth.backends.EmailAuthenticationBackend"

    def test_expired_token(self, caplog, client):
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
        assert caplog.record_tuples == [
            (
                "inclusion_connect.auth",
                logging.INFO,
                "{'ip_address': '127.0.0.1', "
                "'event': 'confirm_email_address_error', "
                "'error': 'link expired', "
                "'email': 'me@mailinator.com', "
                f"'user': UUID('{user.pk}')"
                "}",
            )
        ]

    def test_forged_uidb64(self, caplog, client):
        user = UserFactory(email="")
        other_user = UserFactory()
        email = "me@mailinator.com"
        email_address = EmailAddress.objects.create(email=email, user_id=user.pk)
        token = email_verification_token(email)
        url = self.url(other_user, token)
        response = client.get(url)
        assert response.status_code == 404
        email_address.refresh_from_db()
        assert email_address.verified_at is None
        user.refresh_from_db()
        assert user.email == ""
        assert "_auth_user_id" not in client.session
        assert "_auth_user_backend" not in client.session
        assert caplog.record_tuples == [
            ("django.request", logging.WARNING, f"Not Found: {url}"),
            (
                "inclusion_connect.auth",
                logging.INFO,
                "{'ip_address': '127.0.0.1', "
                "'email': 'me@mailinator.com', "
                "'event': 'confirm_email_address_error', "
                "'error': 'email not found'"
                "}",
            ),
        ]

    def test_forged_token_bad_user_pk(self, caplog, client):
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
        assert all(logger == "django.request" for logger, _level, _msg in caplog.record_tuples)

    def test_forged_token_bad_email(self, caplog, client):
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
        assert all(logger == "django.request" for logger, _level, _msg in caplog.record_tuples)

    @freeze_time("2023-04-26 11:11:11")
    def test_forged_token(self, caplog, client):
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
        assert all(logger == "django.request" for logger, _level, _msg in caplog.record_tuples)

    @freeze_time("2023-04-26 11:11:11")
    def test_token_invalidated_by_email_change(self, caplog, client):
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
        assert caplog.record_tuples == [
            (
                "inclusion_connect.auth",
                logging.INFO,
                "{'ip_address': '127.0.0.1', "
                "'email': 'new@mailinator.com', "
                f"'user': UUID('{user.pk}'), "
                "'event': 'confirm_email_address'}",
            ),
            (
                "inclusion_connect.auth",
                logging.INFO,
                "{'ip_address': '127.0.0.1', "
                "'email': 'new@mailinator.com', "
                f"'user': UUID('{user.pk}'), "
                "'event': 'login'}",
            ),
        ]
        caplog.clear()

        # token1 is invalidated, even if user is currently logged in.
        response = client.get(self.url(user, token1))
        assertMessages(response, [("INFO", "Cette adresse e-mail est déjà vérifiée.")])
        assertRedirects(response, reverse("accounts:edit_user_info"))
        assert caplog.record_tuples == [
            (
                "inclusion_connect.auth",
                logging.INFO,
                "{'ip_address': '127.0.0.1', "
                "'email': 'new@mailinator.com', "
                f"'user': UUID('{user.pk}'), "
                "'event': 'confirm_email_address_error', "
                "'error': 'already verified'}",
            )
        ]
        caplog.clear()

        # token1 is invalidated.
        client.session.flush()
        response = client.get(self.url(user, token1))
        assertMessages(response, [("INFO", "Cette adresse e-mail est déjà vérifiée.")])
        assertRedirects(response, reverse("accounts:login"))
        assert caplog.record_tuples == [
            (
                "inclusion_connect.auth",
                logging.INFO,
                "{'ip_address': '127.0.0.1', "
                "'email': 'new@mailinator.com', "
                f"'user': UUID('{user.pk}'), "
                "'event': 'confirm_email_address_error', "
                "'error': 'already verified'}",
            )
        ]

    @freeze_time("2023-04-26 11:11:11")
    def test_unknown_email(self, caplog, client):
        user = UserFactory(email="")
        email = "me@mailinator.com"
        # No email_address record, maybe an admin removed it.
        token = email_verification_token(email)
        session = client.session
        session[EMAIL_CONFIRM_KEY] = "me@mailinator.com"
        session.save()
        url = self.url(user, token)
        response = client.get(url)
        assert response.status_code == 404
        assert caplog.record_tuples == [
            ("django.request", logging.WARNING, f"Not Found: {url}"),
            (
                "inclusion_connect.auth",
                logging.INFO,
                "{'ip_address': '127.0.0.1', "
                "'email': 'me@mailinator.com', "
                "'event': 'confirm_email_address_error', "
                "'error': 'email not found'"
                "}",
            ),
        ]


class TestChangeTemporaryPasswordView:
    def test_view(self, caplog, client):
        redirect_url = reverse("oauth2_provider:rp-initiated-logout")
        url = add_url_params(reverse("accounts:login"), {"next": redirect_url})
        user = UserFactory(must_reset_password=True)

        response = client.post(url, data={"email": user.email, "password": DEFAULT_PASSWORD})
        assertRedirects(response, reverse("accounts:change_temporary_password"))
        assert get_user(client).is_authenticated is True
        assert client.session["next_url"] == redirect_url
        assert caplog.record_tuples == [
            (
                "inclusion_connect.auth",
                logging.INFO,
                "{'ip_address': '127.0.0.1', 'user': UUID('%s'), 'event': 'login'}" % user.pk,
            )
        ]
        caplog.clear()

        response = client.post(
            reverse("accounts:change_temporary_password"),
            data={"new_password1": "V€r¥--$3©®€7", "new_password2": "V€r¥--$3©®€7"},
        )
        assertRedirects(response, redirect_url, fetch_redirect_response=False)
        # The redirect cleans `next_url` from the session.
        assert "next_url" not in client.session
        user.refresh_from_db()
        assert user.must_reset_password is False
        assert caplog.record_tuples == [
            (
                "inclusion_connect.auth",
                logging.INFO,
                "{'ip_address': '127.0.0.1', 'event': 'change_temporary_password', 'user': UUID('%s')}" % user.pk,
            )
        ]

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

    def test_invalid_password(self, caplog, client):
        user = UserFactory(must_reset_password=True, first_name="Manuel", last_name="Calavera")
        client.force_login(user)
        response = client.post(
            reverse("accounts:change_temporary_password"),
            data={"new_password1": "password", "new_password2": "password"},
        )
        assert response.status_code == 200
        user.refresh_from_db()
        assert user.must_reset_password is True
        assert caplog.record_tuples == [
            (
                "inclusion_connect.auth",
                logging.INFO,
                "{'ip_address': '127.0.0.1', "
                "'event': 'change_temporary_password_error', "
                f"'user': UUID('{user.pk}'), "
                "'errors': {'new_password2': ["
                "{'message': 'Ce mot de passe est trop court. Il doit contenir au minimum 12 caractères.', "
                "'code': 'password_too_short'}, "
                "{'message': 'Ce mot de passe est trop courant.', 'code': 'password_too_common'}, "
                "{'message': 'Le mot de passe ne contient pas assez de caractères.', 'code': ''}]}"
                "}",
            )
        ]


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
        response = client.get(
            add_url_params(reverse("oauth2_provider:rp-initiated-logout"), {"state": "random_string"})
        )
        assert response.status_code == 200
