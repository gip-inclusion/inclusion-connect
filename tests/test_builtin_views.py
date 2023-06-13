from django.urls import reverse

from inclusion_connect.utils.urls import add_url_params
from tests.conftest import Client


def test_csrf_view(snapshot):
    client = Client(enforce_csrf_checks=True)
    response = client.post(
        add_url_params(
            reverse("accounts:login"),
            {"referrer_uri": "http://go.back/there", "other_parameter": "is_ignored"},
        ),
        {"username": "doesnot", "password": "matter"},
    )
    assert str(response.content.decode()) == snapshot
