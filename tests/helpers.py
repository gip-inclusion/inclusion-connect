import base64
import hashlib
import logging
import uuid

import jwt
from bs4 import BeautifulSoup
from django.contrib.auth import get_user
from django.contrib.sessions.models import Session
from django.utils import timezone
from django.utils.crypto import get_random_string
from oauth2_provider.models import get_access_token_model, get_id_token_model, get_refresh_token_model

from inclusion_connect.utils.urls import add_url_params, get_url_params
from tests.asserts import assertRecords
from tests.oidc_overrides.factories import DEFAULT_CLIENT_SECRET, ApplicationFactory, default_client_secret
from tests.users.factories import DEFAULT_PASSWORD


def oidc_flow_followup(
    client,
    auth_response_params,
    user,
    oidc_params,
    caplog,
    additional_claims=None,
    code_verifier=None,
    with_trailing_slash=False,
):
    # Call TOKEN endpoint
    token_data = {
        "client_id": oidc_params["client_id"],
        "client_secret": DEFAULT_CLIENT_SECRET,
        "code": auth_response_params["code"],
        "grant_type": "authorization_code",
        "redirect_uri": oidc_params["redirect_uri"],
    }
    if code_verifier:
        token_data["code_verifier"] = code_verifier
    url = "/auth/token" + ("/" if with_trailing_slash else "")
    response = client.post(url, data=token_data)
    assertRecords(
        caplog,
        [
            (
                "inclusion_connect.oidc",
                logging.INFO,
                {
                    "application": oidc_params["client_id"],
                    "event": "token",
                    "user": user.pk,
                },
            )
        ],
    )

    token_json = response.json()
    id_token = token_json["id_token"]
    decoded_id_token = jwt.decode(
        id_token,
        key=default_client_secret(),
        algorithms=["HS256"],
        audience=oidc_params["client_id"],
    )
    assert decoded_id_token["nonce"] == oidc_params["nonce"]
    assert decoded_id_token["sub"] == str(user.pk)
    assert uuid.UUID(decoded_id_token["sub"]), "Sub should be an uuid"
    assert decoded_id_token["given_name"] == user.first_name
    assert decoded_id_token["family_name"] == user.last_name
    assert decoded_id_token["email"] == user.email
    for k, v in (additional_claims or {}).items():
        assert decoded_id_token[k] == v

    # Call USER INFO endpoint
    response = client.get(
        "/auth/userinfo" + ("/" if with_trailing_slash else ""),
        headers={"Authorization": f"Bearer {token_json['access_token']}"},
    )
    assert response.json() == {
        "sub": str(user.pk),
        "given_name": user.first_name,
        "family_name": user.last_name,
        "email": user.email,
    } | (additional_claims or {})
    assertRecords(caplog, [])

    return token_json["id_token"]


def oidc_complete_flow(
    client,
    user,
    oidc_params,
    caplog,
    application=None,
    use_pkce=False,
    with_trailing_slash=False,
):
    application = application or ApplicationFactory(client_id=oidc_params["client_id"])
    auth_url = "/auth/authorize" + ("/" if with_trailing_slash else "")

    auth_params = oidc_params
    code_verifier = None
    if use_pkce:
        code_verifier = get_random_string(42)  # arbitrary value
        code_challenge = base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest()).decode().rstrip("=")
        auth_params = auth_params | {"code_challenge_method": "S256", "code_challenge": code_challenge}

    auth_complete_url = add_url_params(auth_url, auth_params)
    response = client.get(auth_complete_url)
    if not get_user(client).is_authenticated:
        assert client.session["next_url"] == auth_complete_url
        response = client.post(
            response.url,
            data={
                "email": user.email,
                "password": DEFAULT_PASSWORD,
            },
        )
        # The redirect cleans `next_url` from the session.
        assert "next_url" not in client.session
        assertRecords(
            caplog,
            [
                (
                    "inclusion_connect.auth",
                    logging.INFO,
                    {"application": application.client_id, "user": user.pk, "event": "login"},
                )
            ],
        )
        response = client.get(response.url)
    auth_response_params = get_url_params(response.url)
    code = auth_response_params["code"]
    assertRecords(
        caplog,
        [
            (
                "inclusion_connect.oidc",
                logging.INFO,
                {
                    "application": application.client_id,
                    "event": "redirect",
                    "user": user.pk,
                    "url": f"http://localhost/callback?code={code}&state=state",
                },
            )
        ],
    )

    return oidc_flow_followup(
        client,
        auth_response_params,
        user,
        oidc_params,
        caplog,
        code_verifier=code_verifier,
        with_trailing_slash=with_trailing_slash,
    )


def has_ongoing_sessions(user):
    ongoing_sessions = [
        s
        for s in Session.objects.filter(expire_date__gte=timezone.now())
        if s.get_decoded().get("_auth_user_id") == str(user.pk)
    ]
    return bool(ongoing_sessions)


def token_are_revoked(user):
    return (
        not get_id_token_model().objects.filter(user=user).exists()
        and not get_access_token_model().objects.filter(user=user).exists()
        and not get_refresh_token_model().objects.filter(revoked=None).exists()
    )


def parse_response_to_soup(response, selector=None, no_html_body=False, status_code=200):
    soup = BeautifulSoup(response.content, "html5lib", from_encoding=response.charset or "utf-8")
    if no_html_body:
        # If the provided HTML does not contain <html><body> tags
        # html5lib will always add them around the response:
        # ignore them
        soup = soup.body
    if selector is not None:
        [soup] = soup.select(selector)
    for csrf_token_input in soup.find_all("input", attrs={"name": "csrfmiddlewaretoken"}):
        csrf_token_input["value"] = "NORMALIZED_CSRF_TOKEN"
    if "nonce" in soup.attrs:
        soup["nonce"] = "NORMALIZED_CSP_NONCE"
    for csp_nonce_script in soup.find_all("script", {"nonce": True}):
        csp_nonce_script["nonce"] = "NORMALIZED_CSP_NONCE"
    return soup


def call_logout(client, method, params, with_trailing_slash=False):
    url = "/auth/logout" + ("/" if with_trailing_slash else "")
    if method == "get":
        return client.get(add_url_params(url, params))
    elif method == "post":
        return client.post(url, data=params)
    raise ValueError
