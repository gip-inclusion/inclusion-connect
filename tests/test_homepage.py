from django.urls import reverse

from tests.helpers import parse_response_to_soup


def test_homepage(client, snapshot):
    response = client.get(reverse("homepage"))

    script_content = parse_response_to_soup(response)
    assert str(script_content) == snapshot
