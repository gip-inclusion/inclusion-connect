from django.urls import reverse

from tests.helpers import parse_response_to_soup


def test_login_form(client, snapshot):
    response = client.get(reverse("admin:login"))
    assert str(parse_response_to_soup(response, selector="#login-form")) == snapshot
