from django.urls import reverse

from tests.conftest import Client
from tests.helpers import parse_response_to_soup


def test_csrf_view(snapshot):
    client = Client(enforce_csrf_checks=True)
    response = client.post(
        reverse("accounts:login"),
        {"username": "doesnot", "password": "matter"},
    )
    script_content = parse_response_to_soup(response)
    assert str(script_content) == snapshot
