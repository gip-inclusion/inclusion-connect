from urllib.parse import quote

from django.contrib import messages
from django.contrib.auth import get_user
from django.core import mail
from django.urls import reverse
from django.utils.encoding import force_bytes
from django.utils.html import format_html
from django.utils.http import urlsafe_base64_encode
from pytest_django.asserts import assertContains, assertRedirects, assertTemplateUsed

from inclusion_connect.accounts.views import PasswordResetView
from inclusion_connect.oidc_overrides.views import OIDCSessionMixin
from inclusion_connect.users.models import User
from inclusion_connect.utils.urls import add_url_params
from tests.users.factories import DEFAULT_PASSWORD, UserFactory


def test_login(client):
    redirect_url = reverse("oidc_overrides:logout")
    url = add_url_params(reverse("accounts:login"), {"next": redirect_url})
    user = UserFactory()
    assert not get_user(client).is_authenticated

    response = client.get(url)
    assertContains(response, "Connexion")
    assertContains(response, "Adresse e-mail")  # Ask for email, not username
    assertContains(response, reverse("accounts:registration"))  # Link to registration page

    response = client.post(url, data={"email": user.email, "password": DEFAULT_PASSWORD})
    assertRedirects(response, redirect_url, fetch_redirect_response=False)
    assert get_user(client).is_authenticated is True


def test_login_failed_bad_email_or_password(client):
    url = add_url_params(reverse("accounts:login"), {"next": "anything"})
    user = UserFactory()
    assert not get_user(client).is_authenticated

    response = client.post(url, data={"email": user.email, "password": "toto"})
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


def test_user_creation(client):
    redirect_url = reverse("oidc_overrides:logout")
    url = add_url_params(reverse("accounts:registration"), {"next": redirect_url})
    user = UserFactory.build()
    assert not get_user(client).is_authenticated

    response = client.get(url)
    assertContains(response, "Créer un compte")
    assertContains(response, reverse("accounts:login"))  # Link to login page
    assertContains(response, "CGU_20230302.pdf")
    assertContains(response, quote("Politique de confidentialité_20230302.pdf"))

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
    assertRedirects(response, redirect_url, fetch_redirect_response=False)
    assert get_user(client).is_authenticated is True
    user = User.objects.get(email=user.email)  # Previous instance was a built factory, so refresh_from_db won't work
    assert user.terms_accepted_at == user.date_joined


def test_user_creation_fails_email_exists(client):
    redirect_url = reverse("oidc_overrides:logout")
    url = add_url_params(reverse("accounts:registration"), {"next": redirect_url})
    user = UserFactory()
    assert not get_user(client).is_authenticated

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
    assertTemplateUsed(response, "registration.html")
    assert "email" in response.context["form"].errors
    assertContains(
        response,
        format_html(
            'Un compte avec cette adresse e-mail existe déjà, <a href="{}">se connecter</a> ?',
            reverse("accounts:login"),
        ),
        html=True,
    )


def test_user_creation_terms_are_required(client):
    redirect_url = reverse("oidc_overrides:logout")
    url = add_url_params(reverse("accounts:registration"), {"next": redirect_url})
    user = UserFactory.build()
    assert not get_user(client).is_authenticated

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
    assertTemplateUsed(response, "registration.html")
    assert "terms_accepted" in response.context["form"].errors


def test_account_activation(client):
    redirect_url = reverse("oidc_overrides:logout")
    url = add_url_params(reverse("accounts:activation"), {"next": redirect_url})
    user = UserFactory.build()
    assert not get_user(client).is_authenticated

    # If missing params in oidc session
    response = client.get(url)
    assert response.status_code == 400

    client_session = client.session
    client_session[OIDCSessionMixin.OIDC_SESSION_KEY] = {
        "email": user.email,
        "firstname": user.first_name,
        "lastname": user.last_name,
    }
    client_session.save()
    response = client.get(url)
    assertTemplateUsed(response, "account_activation.html")

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
    assertRedirects(response, redirect_url, fetch_redirect_response=False)
    assert get_user(client).is_authenticated is True
    user = User.objects.get(email=user.email)  # Previous instance was a built factory, so refresh_from_db won't work
    assert user.terms_accepted_at == user.date_joined


def test_account_activation_terms_are_required(client):
    redirect_url = reverse("oidc_overrides:logout")
    url = add_url_params(reverse("accounts:activation"), {"next": redirect_url})
    user = UserFactory.build()
    assert not get_user(client).is_authenticated
    client_session = client.session
    client_session[OIDCSessionMixin.OIDC_SESSION_KEY] = {
        "email": user.email,
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
    assertTemplateUsed(response, "account_activation.html")
    assert "terms_accepted" in response.context["form"].errors


def test_password_reset(client):
    user = UserFactory()

    redirect_url = reverse("oidc_overrides:logout")
    url = add_url_params(reverse("accounts:login"), {"next": redirect_url})
    response = client.get(url)
    password_reset_url = reverse("accounts:password_reset")
    assertContains(response, password_reset_url)

    response = client.get(password_reset_url)
    assertTemplateUsed(response, "password_reset.html")

    response = client.post(password_reset_url, data={"email": user.email})
    assertRedirects(response, reverse("accounts:login"))
    assert list(messages.get_messages(response.wsgi_request)) == [
        messages.storage.base.Message(
            messages.SUCCESS,
            "Si un compte existe avec cette adresse e-mail, "
            "vous recevrez un e-mail contenant des instructions pour réinitialiser votre mot de passe.",
        ),
    ]

    # Check sent email
    assert len(mail.outbox) == 1
    uid = urlsafe_base64_encode(force_bytes(user.pk))
    token = PasswordResetView.token_generator.make_token(user)
    password_reset_url = reverse("accounts:password_reset_confirm", args=(uid, token))
    assert password_reset_url in mail.outbox[0].body

    # Change password
    password = "toto"
    response = client.get(password_reset_url)  # retrieve the modified url
    response = client.post(response.url, data={"new_password1": password, "new_password2": password})

    # User is now logged in and redirected to next_url
    assertRedirects(response, redirect_url, fetch_redirect_response=False)
    assert get_user(client).is_authenticated is True
