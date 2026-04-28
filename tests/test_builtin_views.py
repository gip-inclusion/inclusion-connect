from django.urls import reverse

from inclusion_connect.utils.urls import add_url_params
from tests.conftest import Client
from tests.helpers import parse_response_to_soup


def test_csrf_view(snapshot):
    client = Client(enforce_csrf_checks=True)
    response = client.post(
        add_url_params(
            reverse("accounts:login"),
            {
                "referrer_uri": "http://go.back/there",
                "other_parameter": "is_ignored",
            },
        ),
        {"username": "doesnot", "password": "matter"},
    )
    script_content = parse_response_to_soup(response)
    assert str(script_content) == snapshot
