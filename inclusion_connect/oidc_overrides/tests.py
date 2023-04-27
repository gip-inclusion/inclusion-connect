from django.contrib.auth import get_user
from django.urls import reverse
from django.utils import timezone
from freezegun import freeze_time
from pytest_django.asserts import assertRedirects

from inclusion_connect.oidc_overrides.factories import ApplicationFactory
from inclusion_connect.oidc_overrides.views import OIDCSessionMixin
from inclusion_connect.users.factories import UserFactory
from inclusion_connect.users.models import UserApplicationLink
from inclusion_connect.utils.urls import add_url_params


OIDC_PARAMS = {
    "response_type": "code",
    "client_id": "my_application",
    "redirect_uri": "http://localhost/callback",
    "scope": "openid profile email",
    "state": "state",
    "nonce": "nonce",
}


def test_allow_wildcard_in_redirect_uris():
    application = ApplicationFactory(redirect_uris="http://localhost/*")
    assert application.redirect_uri_allowed("http://localhost/callback")

    application = ApplicationFactory(redirect_uris="*")
    assert application.redirect_uri_allowed("http://localhost/callback")

    # We do not handle wildcard in domains
    application = ApplicationFactory(redirect_uris="http://*.mydomain.com/callback")
    assert not application.redirect_uri_allowed("http://site1.mydomain.com/callback")


def test_logout(client):
    auth_url = reverse("oidc_overrides:authorize")
    user = UserFactory()
    client.force_login(user)
    response = client.get(auth_url)
    assert response.status_code == 400  # auth_url is missing all the arguments
    # TODO: Add a method to quickly to the oidc dance.

    assert get_user(client).is_authenticated
    logout_params = {"id_token_hint": 111}  # bad token
    # TODO: also try with existing token but expired
    response = client.get(add_url_params(reverse("oidc_overrides:logout"), logout_params))
    assertRedirects(response, "http://testserver/", fetch_redirect_response=False)
    assert not get_user(client).is_authenticated


def test_authorize_bad_oidc_params(client):
    # Application does not exist
    auth_url = reverse("oidc_overrides:authorize")
    auth_complete_url = add_url_params(auth_url, OIDC_PARAMS)
    response = client.get(auth_complete_url)
    # FIXME update the template
    assert response.status_code == 400


def test_authorize_not_authenticated(client):
    ApplicationFactory(client_id=OIDC_PARAMS["client_id"])
    auth_url = reverse("oidc_overrides:authorize")
    auth_complete_url = add_url_params(auth_url, OIDC_PARAMS)
    response = client.get(auth_complete_url)
    assertRedirects(response, reverse("accounts:login"))
    assert client.session["next_url"] == auth_complete_url
    assert client.session[OIDCSessionMixin.OIDC_SESSION_KEY] == OIDC_PARAMS


def test_registrations_bad_oidc_params(client):
    # Application does not exist
    auth_url = reverse("oidc_overrides:registrations")
    auth_complete_url = add_url_params(auth_url, OIDC_PARAMS)
    response = client.get(auth_complete_url)
    # FIXME update the template
    assert response.status_code == 400


def test_registrations_not_authenticated(client):
    ApplicationFactory(client_id=OIDC_PARAMS["client_id"])
    auth_url = reverse("oidc_overrides:registrations")
    auth_complete_url = add_url_params(auth_url, OIDC_PARAMS)
    response = client.get(auth_complete_url)
    assertRedirects(response, reverse("accounts:registration"))
    assert client.session["next_url"] == auth_complete_url
    assert client.session[OIDCSessionMixin.OIDC_SESSION_KEY] == OIDC_PARAMS


def test_activation_bad_oidc_params(client):
    auth_url = reverse("oidc_overrides:activation")
    auth_complete_url = add_url_params(auth_url, OIDC_PARAMS)
    response = client.get(auth_complete_url)
    # FIXME update the template
    assert response.status_code == 400


def test_activation_missing_user_info(client):
    ApplicationFactory(client_id=OIDC_PARAMS["client_id"])
    auth_url = reverse("oidc_overrides:activation")
    # Missing: email, firstname and lastname.
    auth_complete_url = add_url_params(auth_url, OIDC_PARAMS)
    response = client.get(auth_complete_url)
    # The user is redirected to the activation view as the oidc parameters are valid
    assertRedirects(response, reverse("accounts:activation"), fetch_redirect_response=False)
    assert client.session["next_url"] == auth_complete_url
    assert client.session[OIDCSessionMixin.OIDC_SESSION_KEY] == OIDC_PARAMS

    response = client.get(response.url)
    # FIXME update the template
    assert response.status_code == 400


def test_activation_not_authenticated(client):
    ApplicationFactory(client_id=OIDC_PARAMS["client_id"])
    auth_params = OIDC_PARAMS | {"email": "email", "firstname": "firstname", "lastname": "lastname"}
    auth_url = reverse("oidc_overrides:activation")
    auth_complete_url = add_url_params(auth_url, auth_params)
    response = client.get(auth_complete_url)
    assertRedirects(response, reverse("accounts:activation"))
    assert client.session["next_url"] == auth_complete_url
    assert client.session[OIDCSessionMixin.OIDC_SESSION_KEY] == auth_params


def test_user_application_link(client):
    application_1 = ApplicationFactory(client_id="ca713487-f4ac-4283-8429-cab7f0386a00")
    application_2 = ApplicationFactory(client_id="05fb7023-ef66-4b24-896e-35f54a6c637f")
    user = UserFactory()
    client.force_login(user)

    def get_user_application_link_values_list():
        return list(
            UserApplicationLink.objects.values_list("application_id", "user_id", "last_login").order_by(
                "application__client_id"
            )
        )

    auth_params_1 = OIDC_PARAMS.copy()
    auth_params_1["client_id"] = application_1.client_id
    auth_url_1 = add_url_params(reverse("oidc_overrides:authorize"), auth_params_1)
    auth_params_2 = OIDC_PARAMS.copy()
    auth_params_2["client_id"] = application_2.client_id
    auth_url_2 = add_url_params(reverse("oidc_overrides:authorize"), auth_params_2)

    assert user.linked_applications.count() == 0

    with freeze_time("2023-04-27 14:06"):
        dt_1 = timezone.now()
        client.get(auth_url_1)

    assert get_user_application_link_values_list() == [(application_1.pk, user.pk, dt_1)]

    with freeze_time("2023-04-27 14:07"):
        dt_2 = timezone.now()
        client.get(auth_url_2)

    assert get_user_application_link_values_list() == [
        (application_2.pk, user.pk, dt_2),
        (application_1.pk, user.pk, dt_1),
    ]

    with freeze_time("2023-04-27 14:08"):
        dt_3 = timezone.now()
        client.get(auth_url_1)

    assert get_user_application_link_values_list() == [
        (application_2.pk, user.pk, dt_2),
        (application_1.pk, user.pk, dt_3),  # last_login was updated
    ]
