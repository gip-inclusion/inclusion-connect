from urllib.parse import quote

from django.contrib import messages
from django.contrib.auth import get_user
from django.core import mail
from django.urls import reverse
from django.utils.encoding import force_bytes
from django.utils.html import format_html
from django.utils.http import urlsafe_base64_encode
from pytest_django.asserts import assertContains, assertNotContains, assertRedirects, assertTemplateUsed

from inclusion_connect.accounts.views import PasswordResetView
from inclusion_connect.oidc_overrides.views import OIDCSessionMixin
from inclusion_connect.users.models import User
from inclusion_connect.utils.urls import add_url_params
from tests.users.factories import DEFAULT_PASSWORD, UserFactory


def test_login(client):
    redirect_url = reverse("oidc_overrides:logout")
    url = add_url_params(reverse("accounts:login"), {"next": redirect_url})
    user = UserFactory()

    response = client.get(url)
    assertContains(response, "Connexion")
    assertContains(response, "Adresse e-mail")  # Ask for email, not username
    assertContains(response, reverse("accounts:register"))  # Link to registration page

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
    url = add_url_params(reverse("accounts:register"), {"next": redirect_url})
    user = UserFactory.build()

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


def test_user_creation_terms_are_required(client):
    redirect_url = reverse("oidc_overrides:logout")
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
    assertTemplateUsed(response, "register.html")
    assert "terms_accepted" in response.context["form"].errors


def test_activate_account(client):
    redirect_url = reverse("oidc_overrides:logout")
    url = add_url_params(reverse("accounts:activate"), {"next": redirect_url})
    user = UserFactory.build()

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
    assertRedirects(response, redirect_url, fetch_redirect_response=False)
    assert get_user(client).is_authenticated is True
    user = User.objects.get(email=user.email)  # Previous instance was a built factory, so refresh_from_db won't work
    assert user.terms_accepted_at == user.date_joined


def test_account_activation_email_already_exists(client):
    redirect_url = reverse("oidc_overrides:logout")
    url = add_url_params(reverse("accounts:activate"), {"next": redirect_url})
    user = UserFactory()

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


def test_activate_account_terms_are_required(client):
    redirect_url = reverse("oidc_overrides:logout")
    url = add_url_params(reverse("accounts:activate"), {"next": redirect_url})
    user = UserFactory.build()

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
    assertTemplateUsed(response, "activate_account.html")
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


def test_edit_user_info(client):
    user = UserFactory()
    client.force_login(user)
    referrer_uri = "https://go/back/there"
    edit_user_info_url = add_url_params(reverse("accounts:edit_user_info"), {"referrer_uri": referrer_uri})
    change_password_url = add_url_params(reverse("accounts:change_password"), {"referrer_uri": referrer_uri})

    # Dont display return button without referrer_uri
    response = client.get(reverse("accounts:edit_user_info"))
    return_text = "Retour"
    assertNotContains(response, return_text)

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
        data={"last_name": "Doe", "first_name": "John", "email": "my@email.com"},
    )
    assertRedirects(response, edit_user_info_url)
    user.refresh_from_db()
    assert user.first_name == "John"
    assert user.last_name == "Doe"
    assert user.email == "my@email.com"
    assertRedirects(response, edit_user_info_url)


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
        data={"old_password": DEFAULT_PASSWORD, "new_password1": "toto", "new_password2": "toto"},
    )
    assertRedirects(response, change_password_url)
    assert get_user(client).is_authenticated is True

    client.logout()
    assert get_user(client).is_authenticated is False

    response = client.post(reverse("accounts:login"), data={"email": user.email, "password": "toto"}, follow=True)
    assert get_user(client).is_authenticated is True
