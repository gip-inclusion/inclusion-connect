import datetime
import re
from dataclasses import dataclass

import pytest
from django.urls import reverse

from tests.oidc_overrides.factories import ApplicationFactory


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
    def test_accounts(self, client, testinput):
        ApplicationFactory(client_id="client_id")
        response = client.get(f"{reverse('accounts:login')}?next={testinput.next_url}")
        assert response.status_code in [200, 302]
        if testinput.expected:
            assert client.session["next_url"] == testinput.next_url
        else:
            assert "next_url" not in client.session


def test_security_txt_is_valid(client):
    response = client.get(reverse("security-txt"))
    assert response.status_code == 200
    assert response["Content-Type"] == "text/plain; charset=utf-8"

    expire_re = re.compile(r"^Expires: (?P<expires>.*)$")
    for line in response.content.decode().splitlines():
        if match := expire_re.match(line):
            expiry = match.group("expires")
            expiry = datetime.datetime.fromisoformat(expiry)
            break

    assert expiry - datetime.datetime.now(tz=datetime.timezone.utc) >= datetime.timedelta(days=14)
