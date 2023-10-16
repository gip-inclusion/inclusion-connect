from django.test import override_settings
from django.urls import reverse

from inclusion_connect.utils.urls import add_url_params
from tests.conftest import Client, parse_response_to_soup


def test_csrf_view(snapshot):
    with override_settings(MATOMO_BASE_URL="https://matomo.example.com", MATOMO_SITE_ID=1):
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
