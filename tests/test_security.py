from dataclasses import dataclass
from typing import Dict, List, Optional

import pytest
from django.urls import reverse

from inclusion_connect.utils.oidc import OIDC_SESSION_KEY
from tests.users.factories import UserFactory


@dataclass
class OIDCSessionMixinTestInput:
    requires_login: bool
    viewname: str
    oidc_data: Optional[Dict[str, str]]


# All OIDCSessionMixin subclasses in the accounts app.
OIDCSessionMixin_accounts: List[OIDCSessionMixinTestInput] = [
    OIDCSessionMixinTestInput(False, "accounts:login", None),
    OIDCSessionMixinTestInput(False, "accounts:register", None),
    OIDCSessionMixinTestInput(
        False,
        "accounts:activate",
        {"firstname": "Mercedes", "lastname": "Colomar", "login_hint": "m.c@mailinator.com"},
    ),
]


@dataclass
class NextUrlExpected:
    next_url: str
    expected: bool


@pytest.mark.parametrize(
    "testinput",
    [
        NextUrlExpected("https://evil.com", False),
        NextUrlExpected("http://evil.com", False),
        NextUrlExpected("/foobar", True),
        NextUrlExpected("http://testserver/foobar", True),
    ],
)
class TestOpenRedirectWithNextParameter:
    @pytest.mark.parametrize("view", OIDCSessionMixin_accounts)
    def test_accounts(self, client, testinput, view):
        if view.requires_login:
            client.force_login(UserFactory())
        if view.oidc_data:
            client_session = client.session
            client_session[OIDC_SESSION_KEY] = view.oidc_data
            client_session.save()
        response = client.get(f"{reverse(view.viewname)}?next={testinput.next_url}")
        assert response.status_code in [200, 302]
        if testinput.expected:
            assert client.session["next_url"] == testinput.next_url
        else:
            assert "next_url" not in client.session
