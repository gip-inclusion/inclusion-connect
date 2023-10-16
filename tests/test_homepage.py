from django.test import override_settings
from django.urls import reverse

from tests.conftest import parse_response_to_soup


def test_homepage(client, snapshot):
    with override_settings(MATOMO_BASE_URL="https://matomo.example.com", MATOMO_SITE_ID=1):
        response = client.get(reverse("homepage"))

        script_content = parse_response_to_soup(response)
        assert str(script_content) == snapshot
