from django.contrib.auth import get_user
from django.urls import reverse
from pytest_django.asserts import assertContains, assertRedirects, assertTemplateUsed

from inclusion_connect.users.factories import DEFAULT_PASSWORD, UserFactory
from inclusion_connect.users.models import User
from inclusion_connect.utils.urls import add_url_params


def test_login(client):
    redirect_url = reverse("oauth2_provider_logout")
    url = add_url_params(reverse("login"), {"next": redirect_url})
    user = UserFactory()
    assert not get_user(client).is_authenticated

    response = client.get(url)
    assertContains(response, "Connexion")
    assertContains(response, "Adresse e-mail")  # Ask for email, not username
    assertContains(response, reverse("registration"))  # Link to registration page

    response = client.post(url, data={"email": user.email, "password": DEFAULT_PASSWORD})
    assertRedirects(response, redirect_url, fetch_redirect_response=False)
    assert get_user(client).is_authenticated


def test_login_failed_bad_email_or_password(client):
    url = add_url_params(reverse("login"), {"next": "anything"})
    user = UserFactory()
    assert not get_user(client).is_authenticated

    response = client.post(url, data={"email": user.email, "password": "toto"})
    assertTemplateUsed("login.html")
    assertContains(response, "Adresse e-mail ou mot de passe invalide.")
    assert not get_user(client).is_authenticated

    response = client.post(url, data={"email": "wrong@email.com", "password": DEFAULT_PASSWORD})
    assertTemplateUsed("login.html")
    assertContains(response, "Adresse e-mail ou mot de passe invalide.")
    assert not get_user(client).is_authenticated

    # If user is inactive
    user.is_active = False
    user.save()
    response = client.post(url, data={"email": user.email, "password": DEFAULT_PASSWORD})
    assertTemplateUsed("login.html")
    assertContains(response, "Adresse e-mail ou mot de passe invalide.")
    assert not get_user(client).is_authenticated


def test_user_creation(client):
    redirect_url = reverse("oauth2_provider_logout")
    url = add_url_params(reverse("registration"), {"next": redirect_url})
    user = UserFactory.build()
    assert not get_user(client).is_authenticated

    response = client.get(url)
    assertContains(response, "Créer un compte")
    assertContains(response, reverse("login"))  # Link to login page

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
    assertRedirects(response, redirect_url, fetch_redirect_response=False)
    assert get_user(client).is_authenticated
    assert User.objects.get(email=user.email)


# TODO: Test next url propagation in all the registration process (creation + email validation)
