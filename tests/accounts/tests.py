import logging

from django.contrib import messages
from django.contrib.auth import get_user
from django.contrib.auth.hashers import make_password
from django.contrib.auth.tokens import default_token_generator
from django.urls import reverse
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from django_otp.oath import TOTP
from django_otp.plugins.otp_totp.models import TOTPDevice
from freezegun import freeze_time
from pytest_django.asserts import (
    assertContains,
    assertMessages,
    assertNotContains,
    assertQuerySetEqual,
    assertRedirects,
    assertTemplateUsed,
)

from inclusion_connect.utils.oidc import OIDC_SESSION_KEY
from inclusion_connect.utils.urls import add_url_params
from tests.asserts import assertRecords
from tests.helpers import confirm_otp_flow, parse_response_to_soup, pretty_indented
from tests.users.factories import DEFAULT_PASSWORD, UserFactory


class TestLoginView:
    def test_login(self, caplog, client, snapshot):
        redirect_url = reverse("accounts:change_password")
        url = add_url_params(reverse("accounts:login"), {"next": redirect_url})
        verify_otp_url = reverse("accounts:verify_otp")
        user = UserFactory()
        device = TOTPDevice.objects.create(user=user)

        response = client.get(url)
        assert pretty_indented(parse_response_to_soup(response, "#main")) == snapshot(name="login_form")

        response = client.post(url, data={"email": user.email, "password": DEFAULT_PASSWORD}, follow=True)
        assertRedirects(response, verify_otp_url)
        assert get_user(client).is_authenticated is True
        assert pretty_indented(parse_response_to_soup(response, "#main")) == snapshot(name="verify_otp")

        totp = TOTP(device.bin_key)
        response = client.post(verify_otp_url, {"otp_token": totp.token()})
        assertRedirects(response, redirect_url)

        # The redirect cleans `next_url` from the session.
        assert "next_url" not in client.session
        assertRecords(
            caplog,
            [
                (
                    "inclusion_connect.auth",
                    logging.INFO,
                    {"user": user.email, "event": "login"},
                ),
                (
                    "inclusion_connect.auth",
                    logging.INFO,
                    {"user": user.email, "event": "verify_otp_device", "device": device.pk},
                ),
            ],
        )

    def test_login_no_otp(self, caplog, client):
        redirect_url = reverse("accounts:change_password")
        login_url = add_url_params(reverse("accounts:login"), {"next": redirect_url})
        user = UserFactory()

        response = client.get(login_url)
        response = client.post(login_url, data={"email": user.email, "password": DEFAULT_PASSWORD}, follow=True)

        response, device = confirm_otp_flow(client, response)
        assertRedirects(response, redirect_url)

        assert get_user(client).is_authenticated is True

        assertRecords(
            caplog,
            [
                (
                    "inclusion_connect.auth",
                    logging.INFO,
                    {"user": user.email, "event": "login"},
                ),
                (
                    "inclusion_connect.auth",
                    logging.INFO,
                    {"user": user.email, "event": "create_otp_device", "device": device.pk},
                ),
                (
                    "inclusion_connect.auth",
                    logging.INFO,
                    {"user": user.email, "event": "confirm_otp_device", "device": device.pk},
                ),
            ],
        )

    def test_no_next_url(self, caplog, client):
        user = UserFactory()
        verify_otp_url = reverse("accounts:verify_otp")
        device = TOTPDevice.objects.create(user=user)

        response = client.post(
            reverse("accounts:login"),
            data={"email": user.email, "password": DEFAULT_PASSWORD},
            follow=True,
        )
        assertRedirects(response, verify_otp_url)

        totp = TOTP(device.bin_key)
        response = client.post(verify_otp_url, {"otp_token": totp.token()})
        assertRedirects(response, reverse("accounts:home"))
        assert get_user(client).is_authenticated is True
        assertRecords(
            caplog,
            [
                (
                    "inclusion_connect.auth",
                    logging.INFO,
                    {"user": user.email, "event": "login"},
                ),
                (
                    "inclusion_connect.auth",
                    logging.INFO,
                    {"user": user.email, "event": "verify_otp_device", "device": device.pk},
                ),
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

    def test_login_hint(self, caplog, client, snapshot):
        redirect_url = reverse("accounts:change_password")
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
        assert pretty_indented(parse_response_to_soup(response, "#main")) == snapshot

        # Email is simply ignored.
        response = client.post(url, data={"email": "evil@mailinator.com", "password": DEFAULT_PASSWORD})
        response, device = confirm_otp_flow(client, response)
        assertRedirects(response, redirect_url)
        assert get_user(client).is_authenticated is True
        assertRecords(
            caplog,
            [
                (
                    "inclusion_connect.auth",
                    logging.INFO,
                    {"user": user.email, "event": "login"},
                ),
                (
                    "inclusion_connect.auth",
                    logging.INFO,
                    {"user": user.email, "event": "create_otp_device", "device": device.pk},
                ),
                (
                    "inclusion_connect.auth",
                    logging.INFO,
                    {"user": user.email, "event": "confirm_otp_device", "device": device.pk},
                ),
            ],
        )

    def test_empty_login_hint(self, client, snapshot):
        url = add_url_params(reverse("accounts:login"), {"login_hint": ""})

        response = client.get(url)
        assert pretty_indented(parse_response_to_soup(response, "#main")) == snapshot


class TestPasswordResetConfirmView:
    def test_confirm_password_reset_error(self, caplog, client):
        user = UserFactory()
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)
        response = client.get(reverse("accounts:password_reset_confirm", args=(uid, token)))
        assertRedirects(response, response.url)
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
                        "user": user.email,
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
    def test_change_password(self, caplog, client, snapshot):
        user = UserFactory()
        client.force_login(user)
        change_password_url = reverse("accounts:change_password")

        response = client.get(change_password_url)
        assert pretty_indented(parse_response_to_soup(response, "#main")) == snapshot

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
                        "user": user.email,
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
                    {"user": user.email, "event": "login"},
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
                        "user": user.email,
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
        redirect_url = reverse("accounts:change_password")
        url = add_url_params(reverse("accounts:login"), {"next": redirect_url})
        change_temporary_password_url = reverse("accounts:change_temporary_password")
        verify_otp_url = reverse("accounts:verify_otp")

        user = UserFactory(password_is_temporary=True)
        device = TOTPDevice.objects.create(user=user)

        response = client.post(url, data={"email": user.email, "password": DEFAULT_PASSWORD}, follow=True)
        assertRedirects(response, verify_otp_url)

        totp = TOTP(device.bin_key)
        response = client.post(verify_otp_url, {"otp_token": totp.token()})
        assertRedirects(response, change_temporary_password_url)
        assert get_user(client).is_authenticated is True
        assert client.session["next_url"] == redirect_url
        assertRecords(
            caplog,
            [
                (
                    "inclusion_connect.auth",
                    logging.INFO,
                    {"user": user.email, "event": "login"},
                ),
                (
                    "inclusion_connect.auth",
                    logging.INFO,
                    {"user": user.email, "event": "verify_otp_device", "device": device.pk},
                ),
            ],
        )

        response = client.post(
            change_temporary_password_url,
            data={"new_password1": "V€r¥--$3©®€7", "new_password2": "V€r¥--$3©®€7"},
        )
        assertRedirects(response, redirect_url)
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
                    {"event": "change_temporary_password", "user": user.email},
                )
            ],
        )

    def test_view_no_otp(self, caplog, client):
        redirect_url = reverse("accounts:home")
        url = add_url_params(reverse("accounts:login"), {"next": redirect_url})
        change_temporary_password_url = reverse("accounts:change_temporary_password")

        user = UserFactory(password_is_temporary=True)

        response = client.post(url, data={"email": user.email, "password": DEFAULT_PASSWORD}, follow=True)
        response, device = confirm_otp_flow(client, response)

        assertRedirects(response, change_temporary_password_url)
        assert get_user(client).is_authenticated is True
        assert client.session["next_url"] == redirect_url
        assertRecords(
            caplog,
            [
                (
                    "inclusion_connect.auth",
                    logging.INFO,
                    {"user": user.email, "event": "login"},
                ),
                (
                    "inclusion_connect.auth",
                    logging.INFO,
                    {"user": user.email, "event": "create_otp_device", "device": device.pk},
                ),
                (
                    "inclusion_connect.auth",
                    logging.INFO,
                    {"user": user.email, "event": "confirm_otp_device", "device": device.pk},
                ),
            ],
        )

        response = client.post(
            change_temporary_password_url,
            data={"new_password1": "V€r¥--$3©®€7", "new_password2": "V€r¥--$3©®€7"},
        )
        assertRedirects(response, redirect_url)
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
                    {"event": "change_temporary_password", "user": user.email},
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
        assertRedirects(response, reverse("accounts:home"))

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
                        "user": user.email,
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
        redirect_url = reverse("accounts:change_password")
        url = add_url_params(reverse("accounts:login"), {"next": redirect_url})
        change_weak_password_url = reverse("accounts:change_weak_password")
        verify_otp_url = reverse("accounts:verify_otp")
        user = UserFactory(password=make_password("weak_password"))
        device = TOTPDevice.objects.create(user=user)

        response = client.post(url, data={"email": user.email, "password": "weak_password"}, follow=True)
        assertRedirects(response, verify_otp_url)

        totp = TOTP(device.bin_key)
        response = client.post(verify_otp_url, {"otp_token": totp.token()})
        assertRedirects(response, change_weak_password_url)

        assert get_user(client).is_authenticated is True
        assert client.session["next_url"] == redirect_url
        assertRecords(
            caplog,
            [
                (
                    "inclusion_connect.auth",
                    logging.INFO,
                    {"user": user.email, "event": "login"},
                ),
                (
                    "inclusion_connect.auth",
                    logging.INFO,
                    {"user": user.email, "event": "verify_otp_device", "device": device.pk},
                ),
            ],
        )

        response = client.post(
            change_weak_password_url,
            data={"new_password1": DEFAULT_PASSWORD, "new_password2": DEFAULT_PASSWORD},
        )
        assertRedirects(response, redirect_url)

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
                    {"event": "change_weak_password", "user": user.email},
                )
            ],
        )

    def test_view_no_otp(self, caplog, client):
        redirect_url = reverse("accounts:home")
        url = add_url_params(reverse("accounts:login"), {"next": redirect_url})
        change_weak_password_url = reverse("accounts:change_weak_password")
        user = UserFactory(password=make_password("weak_password"))

        response = client.post(url, data={"email": user.email, "password": "weak_password"}, follow=True)
        response, device = confirm_otp_flow(client, response)

        assertRedirects(response, change_weak_password_url)
        assert get_user(client).is_authenticated is True
        assert client.session["next_url"] == redirect_url
        assertRecords(
            caplog,
            [
                (
                    "inclusion_connect.auth",
                    logging.INFO,
                    {"user": user.email, "event": "login"},
                ),
                (
                    "inclusion_connect.auth",
                    logging.INFO,
                    {"user": user.email, "event": "create_otp_device", "device": device.pk},
                ),
                (
                    "inclusion_connect.auth",
                    logging.INFO,
                    {"user": user.email, "event": "confirm_otp_device", "device": device.pk},
                ),
            ],
        )

        response = client.post(
            change_weak_password_url,
            data={"new_password1": DEFAULT_PASSWORD, "new_password2": DEFAULT_PASSWORD},
        )
        assertRedirects(response, redirect_url)

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
                    {"event": "change_weak_password", "user": user.email},
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
                        "user": user.email,
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
        client.force_login(user, device=None)
        assert not TOTPDevice.objects.exists()

        # With no device
        response = client.get(reverse("accounts:change_password"))
        device = TOTPDevice.objects.get()
        confirm_otp_url = reverse("accounts:otp_confirm_device", args=(device.pk,))
        assertRedirects(response, confirm_otp_url)

        totp = TOTP(device.bin_key)
        post_data = {
            "name": "Mon appareil",
            "otp_token": totp.token(),
        }
        response = client.post(confirm_otp_url, data=post_data)
        assertRedirects(response, reverse("accounts:change_temporary_password"))

        # With a pre-existing confirmed device
        client.logout()
        TOTPDevice.objects.update(last_t=1)  # Reset last_t to allow using the same token again
        client.force_login(user, device=None)
        response = client.get(reverse("accounts:change_password"))
        verify_otp_url = reverse("accounts:verify_otp")
        assertRedirects(response, verify_otp_url)

        totp = TOTP(device.bin_key)
        response = client.post(verify_otp_url, {"otp_token": totp.token()})
        assertRedirects(response, reverse("accounts:change_temporary_password"))

        # Change temporary password
        client.post(
            reverse("accounts:change_temporary_password"),
            data={"new_password1": "V€r¥--$3©®€7", "new_password2": "V€r¥--$3©®€7"},
        )
        response = client.get(reverse("accounts:change_weak_password"))

        # Change weak password
        client.post(
            reverse("accounts:change_weak_password"),
            data={"new_password1": "V€r¥--$3©®€7", "new_password2": "V€r¥--$3©®€7"},
        )
        response = client.get(reverse("accounts:change_password"))
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


class TestOTP:
    @freeze_time("2025-03-11 05:18:56")
    def test_devices(self, client, snapshot, caplog):
        user = UserFactory()
        client.force_login(user)

        url = reverse("accounts:otp_devices")

        response = client.get(url)
        device = TOTPDevice.objects.get()
        assert (
            pretty_indented(
                parse_response_to_soup(
                    response,
                    ".s-main",
                    replace_in_attr=[
                        ("value", f"{device.pk}", "[PK of device]"),
                        ("id", f"delete_{device.pk}_modal", "delete_[PK of device]_modal"),
                        ("data-bs-target", f"#delete_{device.pk}_modal", "#delete_[PK of device]_modal"),
                    ],
                ),
            )
            == snapshot
        )

        response = client.post(url, data={"action": "new"})
        new_device = TOTPDevice.objects.filter(confirmed=False).get()
        assertRedirects(response, reverse("accounts:otp_confirm_device", args=(new_device.pk,)))

        assertRecords(
            caplog,
            [
                (
                    "inclusion_connect.auth",
                    logging.INFO,
                    {"user": user.email, "event": "create_otp_device", "device": new_device.pk},
                )
            ],
        )

        # Doing it twice still redirects to the same page (we don't create a second unconfirmed device)
        response = client.post(url, data={"action": "new"})
        assertRedirects(response, reverse("accounts:otp_confirm_device", args=(new_device.pk,)))
        assertRecords(caplog, [])

    def test_confirm(self, client, caplog):
        user = UserFactory()
        client.force_login(user)

        device = TOTPDevice.objects.create(user=user, confirmed=False, key="8fe0a9983c7dddb4acb0146c5507553371e9f211")
        url = reverse("accounts:otp_confirm_device", args=(device.pk,))
        response = client.get(url)
        assertContains(response, "R7QKTGB4PXO3JLFQCRWFKB2VGNY6T4QR")  # the otp secret matching the hex key

        totp = TOTP(device.bin_key, drift=100)
        post_data = {
            "name": "Mon appareil",
            "otp_token": totp.token(),  # a token from a long time ago
        }
        response = client.post(url, data=post_data)
        assert response.status_code == 200
        assert response.context["form"].errors == {"otp_token": ["Mauvais code OTP"]}
        device.refresh_from_db()
        assert device.confirmed is False

        # there's throttling
        totp = TOTP(device.bin_key)
        post_data["otp_token"] = totp.token()
        response = client.post(url, data=post_data)
        assert response.status_code == 200
        assert response.context["form"].errors == {"otp_token": ["Mauvais code OTP"]}
        device.refresh_from_db()
        assert device.confirmed is False

        # When resetting the failure count
        device.throttling_failure_timestamp = None
        device.throttling_failure_count = 0
        device.save()
        response = client.post(url, data=post_data)
        assertMessages(
            response, [messages.Message(messages.SUCCESS, "Votre nouvel appareil est confirmé", extra_tags="toast")]
        )
        assertRedirects(response, reverse("accounts:otp_devices"))
        device.refresh_from_db()
        assert device.confirmed is True

        assertRecords(
            caplog,
            [
                (
                    "inclusion_connect.auth",
                    logging.INFO,
                    {"user": user.email, "event": "confirm_otp_device", "device": device.pk},
                )
            ],
        )

    def test_delete_devices(self, client, snapshot):
        user = UserFactory()
        url = reverse("accounts:otp_devices")

        with freeze_time("2025-03-11 05:18:56") as frozen_time:
            device_1 = TOTPDevice.objects.create(user=user, confirmed=True, name="bitwarden")
            frozen_time.tick(60)

            device_2 = TOTPDevice.objects.create(user=user, confirmed=True, name="authenticator")
            frozen_time.tick(60)

            client.force_login(user, device_1)

            # List devices
            response = client.get(url)
            assertContains(response, device_1.name)
            assertContains(response, device_2.name)
            assert str(
                parse_response_to_soup(
                    response,
                    ".s-section",
                    replace_in_attr=[
                        ("value", f"{device_1.pk}", "[PK of device_1]"),
                        ("id", f"delete_{device_1.pk}_modal", "delete_[PK of device_1]_modal"),
                        ("data-bs-target", f"#delete_{device_1.pk}_modal", "#delete_[PK of device_1]_modal"),
                        ("value", f"{device_2.pk}", "[PK of device_2]"),
                        ("id", f"delete_{device_2.pk}_modal", "delete_[PK of device_2]_modal"),
                        ("data-bs-target", f"#delete_{device_2.pk}_modal", "#delete_[PK of device_2]_modal"),
                    ],
                )
            ) == snapshot(name="with_device")

            # We cannot remove the used device
            response = client.post(url, data={"delete-device": str(device_1.pk)}, follow=True)
            assertQuerySetEqual(TOTPDevice.objects.all(), [device_1, device_2], ordered=False)
            assertMessages(
                response,
                [
                    messages.Message(
                        messages.ERROR, "Impossible de supprimer l’appareil qui a été utilisé pour se connecter."
                    )
                ],
            )

            # The user removes his other other device
            response = client.post(url, data={"delete-device": str(device_2.pk)})
            assertQuerySetEqual(TOTPDevice.objects.all(), [device_1])
            assertContains(response, device_1.name)
            assertNotContains(response, device_2.name)
            assertMessages(response, [messages.Message(messages.SUCCESS, "L’appareil a été supprimé.")])


class TestLogout:
    def test_logout(self, client):
        user = UserFactory()
        client.force_login(user)
        url = reverse("accounts:logout")

        assert get_user(client).is_authenticated is True

        response = client.get(url)
        assert response.status_code == 405
        assert get_user(client).is_authenticated is True

        response = client.post(url)
        assertRedirects(response, reverse("accounts:login"))
        assert get_user(client).is_authenticated is False
